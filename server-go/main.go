package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/hkdf"
)

// Redis client
var rdb *redis.Client
var ctx = context.Background()

// Constants
const (
	timestampWindowMs = 5 * 60 * 1000 // ±5 minutes
	nonceTTLSec       = 300           // 5 minutes
	noncePrefix       = "nonce:"
	sessionPrefix     = "sess:"
)

// Types
type SessionInitRequest struct {
	KeyAgreement    string `json:"keyAgreement"`
	ClientPublicKey string `json:"clientPublicKey"`
	TTLSec          *int   `json:"ttlSec,omitempty"`
}

type SessionInitResponse struct {
	SessionID       string `json:"sessionId"`
	ServerPublicKey string `json:"serverPublicKey"`
	EncAlg          string `json:"encAlg"`
	ExpiresInSec    int    `json:"expiresInSec"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Redis     string `json:"redis"`
}

type SessionData struct {
	Key       string `json:"key"`
	Type      string `json:"type"`
	ExpiresAt int64  `json:"expiresAt"`
}

type TransactionRequest struct {
	SchemeCode string  `json:"schemeCode"`
	Amount     float64 `json:"amount"`
}

type TransactionResponse struct {
	Status        string  `json:"status"`
	TransactionID string  `json:"transactionId"`
	SchemeCode    string  `json:"schemeCode"`
	Amount        float64 `json:"amount"`
	Timestamp     string  `json:"timestamp"`
	Message       string  `json:"message"`
}

// MetricsCollector for Server-Timing header
type MetricsCollector struct {
	startTime  time.Time
	operations []OperationTiming
}

type OperationTiming struct {
	Operation  string
	DurationMs float64
}

func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		startTime:  time.Now(),
		operations: make([]OperationTiming, 0),
	}
}

func (m *MetricsCollector) Measure(operation string, fn func()) {
	start := time.Now()
	fn()
	m.operations = append(m.operations, OperationTiming{
		Operation:  operation,
		DurationMs: float64(time.Since(start).Microseconds()) / 1000.0,
	})
}

func (m *MetricsCollector) MeasureResult(operation string, fn func() error) error {
	start := time.Now()
	err := fn()
	m.operations = append(m.operations, OperationTiming{
		Operation:  operation,
		DurationMs: float64(time.Since(start).Microseconds()) / 1000.0,
	})
	return err
}

func (m *MetricsCollector) ToServerTimingHeader() string {
	parts := make([]string, 0, len(m.operations)+1)
	for _, op := range m.operations {
		parts = append(parts, fmt.Sprintf("%s;dur=%.3f", strings.ReplaceAll(op.Operation, " ", "-"), op.DurationMs))
	}
	totalMs := float64(time.Since(m.startTime).Microseconds()) / 1000.0
	parts = append(parts, fmt.Sprintf("total;dur=%.3f", totalMs))
	return strings.Join(parts, ", ")
}

// Crypto helpers
func b64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func b64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func generateSessionID(prefix string) string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

func generateIV() []byte {
	iv := make([]byte, 12)
	rand.Read(iv)
	return iv
}

func generateRandomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// HKDF to derive 32-byte key
func hkdf32(sharedSecret, salt, info []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// AES-256-GCM encryption
func aesGcmEncrypt(key, iv, aad, plaintext []byte) (ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt and append tag
	sealed := aesgcm.Seal(nil, iv, plaintext, aad)

	// Split ciphertext and tag (tag is last 16 bytes)
	tagSize := aesgcm.Overhead()
	ciphertext = sealed[:len(sealed)-tagSize]
	tag = sealed[len(sealed)-tagSize:]

	return ciphertext, tag, nil
}

// AES-256-GCM decryption
func aesGcmDecrypt(key, iv, aad, ciphertext, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Combine ciphertext and tag for Open()
	sealed := append(ciphertext, tag...)
	plaintext, err := aesgcm.Open(nil, iv, sealed, aad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Build AAD from request components
func buildAAD(method, path, ts, nonce, kid string) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%s", method, path, ts, nonce, kid))
}

// Validate P-256 public key is on curve
func validateP256PublicKey(publicKeyBytes []byte) error {
	// P-256 uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes) = 65 bytes
	if len(publicKeyBytes) != 65 {
		return fmt.Errorf("INVALID_KEY_LENGTH")
	}

	if publicKeyBytes[0] != 0x04 {
		return fmt.Errorf("INVALID_KEY_FORMAT")
	}

	// Use ecdh to validate point is on curve
	curve := ecdh.P256()
	_, err := curve.NewPublicKey(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("POINT_NOT_ON_CURVE")
	}

	return nil
}

// Replay protection
func validateReplayProtection(nonce, timestamp string) error {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("TIMESTAMP_INVALID")
	}

	now := time.Now().UnixMilli()
	if math.Abs(float64(now-ts)) > timestampWindowMs {
		return fmt.Errorf("TIMESTAMP_INVALID")
	}

	// Nonce uniqueness check with Redis SET NX EX
	key := noncePrefix + nonce
	wasSet, err := rdb.SetNX(ctx, key, "1", time.Duration(nonceTTLSec)*time.Second).Result()
	if err != nil {
		return fmt.Errorf("REDIS_ERROR: %v", err)
	}

	if !wasSet {
		return fmt.Errorf("REPLAY_DETECTED")
	}

	return nil
}

// Session store operations
func storeSession(sessionID string, key []byte, sessionType string, ttlSec int) error {
	expiresAt := time.Now().UnixMilli() + int64(ttlSec)*1000
	data := SessionData{
		Key:       b64Encode(key),
		Type:      sessionType,
		ExpiresAt: expiresAt,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return rdb.Set(ctx, sessionPrefix+sessionID, jsonData, time.Duration(ttlSec)*time.Second).Err()
}

func getSession(sessionID string) (*SessionData, error) {
	value, err := rdb.Get(ctx, sessionPrefix+sessionID).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var data SessionData
	if err := json.Unmarshal([]byte(value), &data); err != nil {
		return nil, err
	}

	// Double-check expiry
	if time.Now().UnixMilli() > data.ExpiresAt {
		rdb.Del(ctx, sessionPrefix+sessionID)
		return nil, nil
	}

	return &data, nil
}

// HTTP Handlers
func sessionInitHandler(w http.ResponseWriter, r *http.Request) {
	metrics := NewMetricsCollector()
	defer func() {
		w.Header().Set("Server-Timing", metrics.ToServerTimingHeader())
	}()

	nonce := r.Header.Get("X-Nonce")
	timestamp := r.Header.Get("X-Timestamp")

	if nonce == "" || timestamp == "" {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Replay protection
	var replayErr error
	metrics.MeasureResult("replay-protection", func() error {
		replayErr = validateReplayProtection(nonce, timestamp)
		return replayErr
	})
	if replayErr != nil {
		log.Printf("Replay protection failed: %v", replayErr)
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Parse request body
	var req SessionInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	if req.KeyAgreement != "ECDH_P256" {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	if req.ClientPublicKey == "" {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Decode and validate client public key
	var clientPub []byte
	var validateErr error
	metrics.MeasureResult("validate-pubkey", func() error {
		var err error
		clientPub, err = b64Decode(req.ClientPublicKey)
		if err != nil {
			validateErr = err
			return err
		}
		validateErr = validateP256PublicKey(clientPub)
		return validateErr
	})
	if validateErr != nil {
		log.Printf("Client public key validation failed: %v", validateErr)
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Generate server ECDH keypair
	var serverPriv *ecdh.PrivateKey
	var serverPub []byte
	metrics.Measure("ecdh-keygen", func() {
		curve := ecdh.P256()
		serverPriv, _ = curve.GenerateKey(rand.Reader)
		serverPub = serverPriv.PublicKey().Bytes()
	})

	// Compute shared secret
	var sharedSecret []byte
	metrics.Measure("ecdh-compute", func() {
		curve := ecdh.P256()
		clientPubKey, _ := curve.NewPublicKey(clientPub)
		sharedSecret, _ = serverPriv.ECDH(clientPubKey)
	})

	// Generate session ID
	sessionID := generateSessionID("S")

	// Cap TTL between 5 minutes and 1 hour
	ttlSec := 1800
	if req.TTLSec != nil {
		ttlSec = *req.TTLSec
	}
	if ttlSec < 300 {
		ttlSec = 300
	}
	if ttlSec > 3600 {
		ttlSec = 3600
	}

	// Derive session key using HKDF
	salt := []byte(sessionID)
	info := []byte("SESSION|A256GCM|AUTH")
	var sessionKey []byte
	metrics.Measure("hkdf", func() {
		sessionKey, _ = hkdf32(sharedSecret, salt, info)
	})

	// Store session in Redis
	var storeErr error
	metrics.MeasureResult("redis-store", func() error {
		storeErr = storeSession(sessionID, sessionKey, "AUTH", ttlSec)
		return storeErr
	})
	if storeErr != nil {
		log.Printf("Failed to store session: %v", storeErr)
		sendError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}

	log.Printf("Session created: %s, ttl: %d", sessionID, ttlSec)

	sendJSON(w, http.StatusOK, SessionInitResponse{
		SessionID:       sessionID,
		ServerPublicKey: b64Encode(serverPub),
		EncAlg:          "A256GCM",
		ExpiresInSec:    ttlSec,
	})
}

func transactionPurchaseHandler(w http.ResponseWriter, r *http.Request) {
	metrics := NewMetricsCollector()
	defer func() {
		w.Header().Set("Server-Timing", metrics.ToServerTimingHeader())
	}()

	// Extract encryption headers
	kid := r.Header.Get("X-Kid")
	encAlg := r.Header.Get("X-Enc-Alg")
	ivB64 := r.Header.Get("X-IV")
	tagB64 := r.Header.Get("X-Tag")
	aadB64 := r.Header.Get("X-AAD")
	nonce := r.Header.Get("X-Nonce")
	timestamp := r.Header.Get("X-Timestamp")

	if kid == "" || encAlg == "" || ivB64 == "" || tagB64 == "" || aadB64 == "" || nonce == "" || timestamp == "" {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	if encAlg != "A256GCM" {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Replay protection
	var replayErr error
	metrics.MeasureResult("replay-protection", func() error {
		replayErr = validateReplayProtection(nonce, timestamp)
		return replayErr
	})
	if replayErr != nil {
		log.Printf("Replay protection failed: %v", replayErr)
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Extract session ID from kid
	var sessionID string
	if strings.HasPrefix(kid, "session:") {
		sessionID = kid[8:]
	} else {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Get session from Redis
	var session *SessionData
	var sessionErr error
	metrics.MeasureResult("redis-get", func() error {
		session, sessionErr = getSession(sessionID)
		return sessionErr
	})
	if sessionErr != nil || session == nil {
		sendError(w, http.StatusUnauthorized, "SESSION_EXPIRED")
		return
	}

	// Decode crypto components
	iv, err := b64Decode(ivB64)
	if err != nil || len(iv) != 12 {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	tag, err := b64Decode(tagB64)
	if err != nil || len(tag) != 16 {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	aad, err := b64Decode(aadB64)
	if err != nil {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Read body (base64-encoded ciphertext)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	ciphertext, err := b64Decode(string(body))
	if err != nil {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Rebuild expected AAD and verify
	var expectedAAD []byte
	metrics.Measure("aad-validation", func() {
		expectedAAD = buildAAD("POST", "/transaction/purchase", timestamp, nonce, kid)
	})
	if string(aad) != string(expectedAAD) {
		log.Printf("AAD mismatch")
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Decrypt session key
	sessionKey, err := b64Decode(session.Key)
	if err != nil {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Decrypt request body
	var plaintext []byte
	var decryptErr error
	metrics.MeasureResult("aes-gcm-decrypt", func() error {
		plaintext, decryptErr = aesGcmDecrypt(sessionKey, iv, aad, ciphertext, tag)
		return decryptErr
	})
	if decryptErr != nil {
		log.Printf("Decryption failed: %v", decryptErr)
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Parse decrypted JSON
	var requestData TransactionRequest
	if err := json.Unmarshal(plaintext, &requestData); err != nil {
		log.Printf("Failed to parse decrypted JSON: %v", err)
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	log.Printf("Decrypted request: %+v", requestData)

	// Business logic - process transaction
	responseData := TransactionResponse{
		Status:        "SUCCESS",
		TransactionID: fmt.Sprintf("TXN-%s", strings.ToUpper(generateRandomHex(8))),
		SchemeCode:    requestData.SchemeCode,
		Amount:        requestData.Amount,
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Message:       fmt.Sprintf("Purchase of %.2f in scheme %s completed successfully", requestData.Amount, requestData.SchemeCode),
	}

	// Encrypt response
	responsePlaintext, _ := json.Marshal(responseData)
	responseIV := generateIV()
	responseNonce := uuid.New().String()
	responseTimestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)

	// Build response AAD
	responseAAD := buildAAD("200", "/transaction/purchase", responseTimestamp, responseNonce, kid)

	var responseCiphertext, responseTag []byte
	metrics.Measure("aes-gcm-encrypt", func() {
		responseCiphertext, responseTag, _ = aesGcmEncrypt(sessionKey, responseIV, responseAAD, responsePlaintext)
	})

	// Set response headers
	w.Header().Set("X-Kid", kid)
	w.Header().Set("X-Enc-Alg", "A256GCM")
	w.Header().Set("X-IV", b64Encode(responseIV))
	w.Header().Set("X-Tag", b64Encode(responseTag))
	w.Header().Set("X-AAD", b64Encode(responseAAD))
	w.Header().Set("X-Nonce", responseNonce)
	w.Header().Set("X-Timestamp", responseTimestamp)
	w.Header().Set("Content-Type", "application/octet-stream")

	w.Write([]byte(b64Encode(responseCiphertext)))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	redisStatus := "ok"
	if err := rdb.Ping(ctx).Err(); err != nil {
		redisStatus = "disconnected"
	}

	status := "ok"
	if redisStatus != "ok" {
		status = "degraded"
	}

	sendJSON(w, http.StatusOK, HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Redis:     redisStatus,
	})
}

// Helper functions
func sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func sendError(w http.ResponseWriter, status int, message string) {
	sendJSON(w, status, ErrorResponse{Error: message})
}

func main() {
	// Initialize Redis
	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		redisHost = "localhost"
	}
	redisPort := os.Getenv("REDIS_PORT")
	if redisPort == "" {
		redisPort = "6379"
	}

	rdb = redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%s", redisHost, redisPort),
	})

	// Wait for Redis to be ready
	for i := 0; i < 10; i++ {
		if err := rdb.Ping(ctx).Err(); err == nil {
			log.Println("Connected to Redis")
			break
		}
		log.Println("Waiting for Redis...")
		time.Sleep(time.Second)
	}

	// Setup router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Routes
	r.Post("/session/init", sessionInitHandler)
	r.Post("/transaction/purchase", transactionPurchaseHandler)
	r.Get("/health", healthHandler)

	// Graceful shutdown
	srv := &http.Server{
		Addr:    ":3000",
		Handler: r,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		<-sigCh
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		rdb.Close()
	}()

	log.Println("Server listening on http://localhost:3000")
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
