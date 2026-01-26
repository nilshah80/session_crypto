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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/hkdf"
)

// Redis client and DB pool
var rdb *redis.Client
var dbPool *pgxpool.Pool

// Constants
const (
	timestampWindowMs = 5 * 60 * 1000 // ±5 minutes
	nonceTTLSec       = 300           // 5 minutes
	noncePrefix       = "nonce:"
	sessionPrefix     = "sess:"
)

// Types
type SessionInitRequest struct {
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
	Status   string `json:"status"`
	Timestamp string `json:"timestamp"`
	Redis    string `json:"redis"`
	Postgres string `json:"postgres"`
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
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("Failed to generate random session ID: %v", err))
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

func generateRandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("Failed to generate random hex: %v", err))
	}
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

// AES-256-GCM encryption - returns IV || ciphertext || tag
func aesGcmEncrypt(key, aad, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate random IV
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Encrypt (returns ciphertext || tag)
	sealed := aesgcm.Seal(nil, iv, plaintext, aad)

	// Return IV || ciphertext || tag
	return append(iv, sealed...), nil
}

// AES-256-GCM decryption - expects IV || ciphertext || tag
func aesGcmDecrypt(key, aad, data []byte) ([]byte, error) {
	if len(data) < 28 { // 12 (IV) + 16 (tag) minimum
		return nil, fmt.Errorf("INVALID_DATA_LENGTH")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract IV and ciphertext+tag
	iv := data[:12]
	ciphertextWithTag := data[12:]

	plaintext, err := aesgcm.Open(nil, iv, ciphertextWithTag, aad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Build AAD from request components
// Format: TIMESTAMP|NONCE|KID|CLIENTID
func buildAAD(ts, nonce, kid, clientId string) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s", ts, nonce, kid, clientId))
}

// SECURITY: Clear sensitive byte slices
// Go doesn't have SecureZeroMemory, so we manually zero each byte
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
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
func validateReplayProtection(reqCtx context.Context, nonce, timestamp string) error {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("TIMESTAMP_INVALID")
	}

	now := time.Now().UnixMilli()
	if math.Abs(float64(now-ts)) > timestampWindowMs {
		return fmt.Errorf("TIMESTAMP_INVALID")
	}

	// Nonce uniqueness check with Redis SET NX EX
	// Add 2-second timeout for Redis operation
	ctx, cancel := context.WithTimeout(reqCtx, 2*time.Second)
	defer cancel()

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
func storeSession(reqCtx context.Context, sessionID string, key []byte, sessionType string, ttlSec int) error {
	// SECURITY: Clear key parameter when done
	defer clearBytes(key)

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

	// 1. Write to PostgreSQL (Source of Truth)
	// Add 3-second timeout for DB operation
	dbCtx, dbCancel := context.WithTimeout(reqCtx, 3*time.Second)
	defer dbCancel()

	_, err = dbPool.Exec(dbCtx, `
		INSERT INTO sessions (session_id, data, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (session_id) DO UPDATE
		SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at
	`, sessionID, jsonData, expiresAt)
	if err != nil {
		return err
	}

	// 2. Write to Redis (Cache)
	// Add 2-second timeout for Redis operation
	redisCtx, redisCancel := context.WithTimeout(reqCtx, 2*time.Second)
	defer redisCancel()

	return rdb.Set(redisCtx, sessionPrefix+sessionID, jsonData, time.Duration(ttlSec)*time.Second).Err()
}

func getSession(reqCtx context.Context, sessionID string) (*SessionData, error) {
	// 1. Try Redis
	// Add 1-second timeout for Redis read
	redisCtx, redisCancel := context.WithTimeout(reqCtx, 1*time.Second)
	defer redisCancel()

	value, err := rdb.Get(redisCtx, sessionPrefix+sessionID).Result()
	if err == nil {
		var data SessionData
		if err := json.Unmarshal([]byte(value), &data); err != nil {
			return nil, err
		}
		// Check expiry
		if time.Now().UnixMilli() > data.ExpiresAt {
			go deleteSession(sessionID) // Async cleanup (uses background context)
			return nil, nil
		}
		return &data, nil
	}

	if err != redis.Nil {
		// Log Redis error but continue to DB
		log.Printf("Warning: Redis error in getSession: %v", err)
	}

	// 2. Fallback to PostgreSQL
	// Add 2-second timeout for DB read
	dbCtx, dbCancel := context.WithTimeout(reqCtx, 2*time.Second)
	defer dbCancel()

	var dataJSON []byte
	err = dbPool.QueryRow(dbCtx, "SELECT data FROM sessions WHERE session_id = $1", sessionID).Scan(&dataJSON)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var data SessionData
	if err := json.Unmarshal(dataJSON, &data); err != nil {
		return nil, err
	}

	// Check expiry
	if time.Now().UnixMilli() > data.ExpiresAt {
		go deleteSession(sessionID) // Async cleanup (uses background context)
		return nil, nil
	}

	// Populate Redis cache (fire and forget with short timeout)
	ttl := time.Duration(data.ExpiresAt-time.Now().UnixMilli()) * time.Millisecond
	if ttl > 0 {
		cacheCtx, cacheCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cacheCancel()
		rdb.Set(cacheCtx, sessionPrefix+sessionID, dataJSON, ttl)
	}

	return &data, nil
}

// deleteSession uses background context since it may be called asynchronously
func deleteSession(sessionID string) {
	bgCtx := context.Background()
	rdb.Del(bgCtx, sessionPrefix+sessionID)
	dbPool.Exec(bgCtx, "DELETE FROM sessions WHERE session_id = $1", sessionID)
}

// HTTP Handlers
func sessionInitHandler(w http.ResponseWriter, r *http.Request) {
	metrics := NewMetricsCollector()
	defer func() {
		w.Header().Set("Server-Timing", metrics.ToServerTimingHeader())
	}()

	idempotencyKey := r.Header.Get("X-Idempotency-Key")
	clientId := r.Header.Get("X-ClientId")

	if idempotencyKey == "" || clientId == "" {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Parse X-Idempotency-Key: timestamp.nonce
	parts := strings.Split(idempotencyKey, ".")
	if len(parts) != 2 {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}
	timestamp := parts[0]
	nonce := parts[1]

	// Replay protection
	reqCtx := r.Context()
	var replayErr error
	metrics.MeasureResult("replay-protection", func() error {
		replayErr = validateReplayProtection(reqCtx, nonce, timestamp)
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
	var keygenErr error
	metrics.Measure("ecdh-keygen", func() {
		curve := ecdh.P256()
		serverPriv, keygenErr = curve.GenerateKey(rand.Reader)
		if keygenErr == nil {
			serverPub = serverPriv.PublicKey().Bytes()
		}
	})
	if keygenErr != nil {
		log.Printf("ECDH keygen failed: %v", keygenErr)
		sendError(w, http.StatusInternalServerError, "CRYPTO_ERROR")
		return
	}

	// Compute shared secret
	var sharedSecret []byte
	var ecdhErr error
	metrics.Measure("ecdh-compute", func() {
		curve := ecdh.P256()
		clientPubKey, err := curve.NewPublicKey(clientPub)
		if err != nil {
			ecdhErr = err
			return
		}
		sharedSecret, ecdhErr = serverPriv.ECDH(clientPubKey)
	})
	if ecdhErr != nil {
		log.Printf("ECDH compute failed: %v", ecdhErr)
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}
	// SECURITY: Clear shared secret after HKDF
	defer clearBytes(sharedSecret)

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
	// Info includes clientId for domain separation
	salt := []byte(sessionID)
	info := []byte(fmt.Sprintf("SESSION|A256GCM|%s", clientId))
	var sessionKey []byte
	var hkdfErr error
	metrics.Measure("hkdf", func() {
		sessionKey, hkdfErr = hkdf32(sharedSecret, salt, info)
	})
	if hkdfErr != nil {
		log.Printf("HKDF key derivation failed: %v", hkdfErr)
		sendError(w, http.StatusInternalServerError, "CRYPTO_ERROR")
		return
	}

	// Store session in PostgreSQL and Redis
	var storeErr error
	metrics.MeasureResult("session-store", func() error {
		storeErr = storeSession(reqCtx, sessionID, sessionKey, "AUTH", ttlSec)
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

	// Extract headers
	kid := r.Header.Get("X-Kid")
	idempotencyKey := r.Header.Get("X-Idempotency-Key")
	clientId := r.Header.Get("X-ClientId")

	if kid == "" || idempotencyKey == "" || clientId == "" {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Parse X-Idempotency-Key: timestamp.nonce
	parts := strings.Split(idempotencyKey, ".")
	if len(parts) != 2 {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}
	timestamp := parts[0]
	nonce := parts[1]

	// Replay protection
	reqCtx := r.Context()
	var replayErr error
	metrics.MeasureResult("replay-protection", func() error {
		replayErr = validateReplayProtection(reqCtx, nonce, timestamp)
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

	// Get session from store
	var session *SessionData
	var sessionErr error
	metrics.MeasureResult("session-get", func() error {
		session, sessionErr = getSession(reqCtx, sessionID)
		return sessionErr
	})
	if sessionErr != nil || session == nil {
		sendError(w, http.StatusUnauthorized, "SESSION_EXPIRED")
		return
	}

	// Build AAD from headers (server reconstructs it)
	// AAD format: TIMESTAMP|NONCE|KID|CLIENTID
	var aad []byte
	metrics.Measure("aad-build", func() {
		aad = buildAAD(timestamp, nonce, kid, clientId)
	})

	// Read encrypted body (IV || ciphertext || tag)
	encryptedBody, err := io.ReadAll(r.Body)
	if err != nil {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Minimum length: IV (12) + tag (16) = 28 bytes
	if len(encryptedBody) < 28 {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}

	// Decrypt session key
	sessionKey, err := b64Decode(session.Key)
	if err != nil {
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}
	// SECURITY: Clear session key when done
	defer clearBytes(sessionKey)

	// Decrypt request body (body contains IV || ciphertext || tag)
	var plaintext []byte
	var decryptErr error
	metrics.MeasureResult("aes-gcm-decrypt", func() error {
		plaintext, decryptErr = aesGcmDecrypt(sessionKey, aad, encryptedBody)
		return decryptErr
	})
	if decryptErr != nil {
		log.Printf("Decryption failed: %v", decryptErr)
		sendError(w, http.StatusBadRequest, "CRYPTO_ERROR")
		return
	}
	// SECURITY: Clear decrypted plaintext after parsing
	defer clearBytes(plaintext)

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
	responsePlaintext, marshalErr := json.Marshal(responseData)
	if marshalErr != nil {
		log.Printf("Failed to marshal response: %v", marshalErr)
		sendError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	// SECURITY: Clear response plaintext after encryption
	defer clearBytes(responsePlaintext)

	responseNonce := uuid.New().String()
	responseTimestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	responseIdempotencyKey := fmt.Sprintf("%s.%s", responseTimestamp, responseNonce)

	// Build response AAD
	// AAD format: TIMESTAMP|NONCE|KID|CLIENTID
	responseAAD := buildAAD(responseTimestamp, responseNonce, kid, clientId)

	// Encrypt - returns IV || ciphertext || tag
	var encryptedResponse []byte
	var encryptErr error
	metrics.Measure("aes-gcm-encrypt", func() {
		encryptedResponse, encryptErr = aesGcmEncrypt(sessionKey, responseAAD, responsePlaintext)
	})
	if encryptErr != nil {
		log.Printf("Failed to encrypt response: %v", encryptErr)
		sendError(w, http.StatusInternalServerError, "CRYPTO_ERROR")
		return
	}

	// Set response headers
	w.Header().Set("X-Kid", kid)
	w.Header().Set("X-Idempotency-Key", responseIdempotencyKey)
	w.Header().Set("Content-Type", "application/octet-stream")

	w.Write(encryptedResponse)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	reqCtx := r.Context()
	redisStatus := "ok"
	if err := rdb.Ping(reqCtx).Err(); err != nil {
		redisStatus = "disconnected"
	}

	postgresStatus := "ok"
	if err := dbPool.Ping(reqCtx); err != nil {
		postgresStatus = "disconnected"
	}

	status := "ok"
	if redisStatus != "ok" || postgresStatus != "ok" {
		status = "degraded"
	}

	sendJSON(w, http.StatusOK, HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Redis:     redisStatus,
		Postgres:  postgresStatus,
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

// CORS middleware for browser clients
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Idempotency-Key, X-ClientId, X-Kid")
		w.Header().Set("Access-Control-Expose-Headers", "Server-Timing, X-Kid, X-Idempotency-Key")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	// Initialize Postgres
	pgHost := os.Getenv("POSTGRES_HOST")
	if pgHost == "" {
		pgHost = "127.0.0.1"
	}
	pgPort := os.Getenv("POSTGRES_PORT")
	if pgPort == "" {
		pgPort = "5432"
	}
	pgUser := os.Getenv("POSTGRES_USER")
	if pgUser == "" {
		pgUser = "postgres"
	}
	pgPass := os.Getenv("POSTGRES_PASSWORD")
	if pgPass == "" {
		pgPass = "postgres"
	}
	pgDB := os.Getenv("POSTGRES_DB")
	if pgDB == "" {
		pgDB = "session_crypto"
	}
	pgSSLMode := os.Getenv("POSTGRES_SSLMODE")
	if pgSSLMode == "" {
		pgSSLMode = "disable" // Use "require" in production
	}

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", pgUser, pgPass, pgHost, pgPort, pgDB, pgSSLMode)

	// Parse config and set pool options
	poolConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		log.Fatalf("Failed to parse database config: %v", err)
	}

	// Connection pool configuration
	poolConfig.MaxConns = 25
	poolConfig.MinConns = 5
	poolConfig.MaxConnLifetime = 5 * time.Minute
	poolConfig.MaxConnIdleTime = 1 * time.Minute

	// Wait for Postgres to be ready with timeout
	pgConnCtx, pgConnCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer pgConnCancel()

	pgConnected := false
	for i := 0; i < 10; i++ {
		dbPool, err = pgxpool.NewWithConfig(pgConnCtx, poolConfig)
		if err == nil {
			if err := dbPool.Ping(pgConnCtx); err == nil {
				log.Println("Connected to Postgres")
				pgConnected = true
				break
			}
			dbPool.Close()
		}
		log.Printf("Waiting for Postgres... (attempt %d/10)", i+1)
		select {
		case <-pgConnCtx.Done():
			log.Fatalf("Timeout waiting for Postgres connection")
		case <-time.After(time.Second):
		}
	}
	if !pgConnected {
		log.Fatalf("Failed to connect to Postgres after 10 attempts")
	}

	// Ensure table exists (Migration)
	initCtx := context.Background()
	_, err = dbPool.Exec(initCtx, `
		CREATE TABLE IF NOT EXISTS sessions (
		  session_id VARCHAR(255) PRIMARY KEY,
		  data JSONB NOT NULL,
		  expires_at BIGINT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
	`)
	if err != nil {
		log.Fatalf("Failed to ensure table exists: %v", err)
	}

	// Initialize Redis
	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		redisHost = "127.0.0.1"
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
		if err := rdb.Ping(initCtx).Err(); err == nil {
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
	r.Use(corsMiddleware)

	// Routes
	r.Post("/session/init", sessionInitHandler)
	r.Post("/transaction/purchase", transactionPurchaseHandler)
	r.Get("/health", healthHandler)

	// Graceful shutdown
	srv := &http.Server{
		Addr:         ":3000",
		Handler:      r,
		ReadTimeout:  10 * time.Second, // SECURITY: Prevent slowloris attacks
		WriteTimeout: 10 * time.Second, // SECURITY: Prevent slow responses from hanging
		IdleTimeout:  30 * time.Second, // SECURITY: Close idle connections
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
		dbPool.Close()
	}()

	log.Println("Server listening on http://localhost:3000")
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
