package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

const serverURL = "http://localhost:3000"

// HTTP client with timeout and connection pooling
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	},
}

// ===== Types =====

type CryptoTiming struct {
	Operation  string  `json:"operation"`
	DurationMs float64 `json:"durationMs"`
}

type EndpointMetrics struct {
	Endpoint         string         `json:"endpoint"`
	TotalRoundTripMs float64        `json:"totalRoundTripMs"`
	HttpRequestMs    float64        `json:"httpRequestMs"`
	CryptoOperations []CryptoTiming `json:"cryptoOperations"`
	ServerTiming     string         `json:"serverTiming,omitempty"`
}

type BenchmarkStats struct {
	Count   int
	TotalMs float64
	MinMs   float64
	MaxMs   float64
	MeanMs  float64
	P50Ms   float64
	P95Ms   float64
	P99Ms   float64
}

type SessionInitRequest struct {
	ClientPublicKey string `json:"clientPublicKey"`
	TTLSec          int    `json:"ttlSec"`
}

type SessionInitResponse struct {
	SessionID       string `json:"sessionId"`
	ServerPublicKey string `json:"serverPublicKey"`
	EncAlg          string `json:"encAlg"`
	ExpiresInSec    int    `json:"expiresInSec"`
}

type PurchaseRequest struct {
	SchemeCode string `json:"schemeCode"`
	Amount     int    `json:"amount"`
}

// ===== Security Helpers =====

// SECURITY: Clear sensitive byte slices
// Go doesn't have SecureZeroMemory, so we manually zero each byte
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

type SessionContext struct {
	SessionID  string
	SessionKey []byte
	Kid        string
	ClientID   string
}

// Close clears sensitive data from SessionContext
func (s *SessionContext) Close() {
	// SECURITY: Clear session key
	clearBytes(s.SessionKey)
}

// Client ID for this application
const clientID = "GO_CLIENT"

// ===== Metrics Helpers =====

func measureSync[T any](operation string, timings *[]CryptoTiming, fn func() T) T {
	start := time.Now()
	result := fn()
	*timings = append(*timings, CryptoTiming{
		Operation:  operation,
		DurationMs: float64(time.Since(start).Microseconds()) / 1000.0,
	})
	return result
}

func parseServerTiming(header string) []CryptoTiming {
	if header == "" {
		return nil
	}
	var timings []CryptoTiming
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		parts := strings.Split(part, ";")
		name := strings.TrimSpace(parts[0])
		var dur float64
		if len(parts) > 1 && strings.HasPrefix(parts[1], "dur=") {
			fmt.Sscanf(parts[1], "dur=%f", &dur)
		}
		timings = append(timings, CryptoTiming{Operation: name, DurationMs: dur})
	}
	return timings
}

func calculateStats(durations []float64) BenchmarkStats {
	sorted := make([]float64, len(durations))
	copy(sorted, durations)
	sort.Float64s(sorted)

	var sum float64
	for _, d := range sorted {
		sum += d
	}
	n := len(sorted)

	return BenchmarkStats{
		Count:   n,
		TotalMs: sum,
		MinMs:   sorted[0],
		MaxMs:   sorted[n-1],
		MeanMs:  sum / float64(n),
		P50Ms:   sorted[int(float64(n)*0.50)],
		P95Ms:   sorted[int(float64(n)*0.95)],
		P99Ms:   sorted[int(float64(n)*0.99)],
	}
}

func printBenchmarkStats(label string, stats BenchmarkStats) {
	fmt.Printf("%s:\n", label)
	fmt.Printf("  Throughput:    %.1f req/s\n", 1000/stats.MeanMs)
	fmt.Printf("  Latency:       Min: %.1fms | Max: %.1fms | Mean: %.1fms\n",
		stats.MinMs, stats.MaxMs, stats.MeanMs)
	fmt.Printf("                 P50: %.1fms | P95: %.1fms | P99: %.1fms\n",
		stats.P50Ms, stats.P95Ms, stats.P99Ms)
	fmt.Println()
}

func printMetricsSummary(initMetrics, purchaseMetrics *EndpointMetrics) {
	fmt.Println("\n================================================================================")
	fmt.Println("  Performance Metrics Summary")
	fmt.Println("================================================================================\n")

	for _, metrics := range []*EndpointMetrics{initMetrics, purchaseMetrics} {
		fmt.Printf("Endpoint: %s\n", metrics.Endpoint)
		fmt.Println("----------------------------------------")
		fmt.Printf("  Total Round-Trip:     %.3f ms\n", metrics.TotalRoundTripMs)
		fmt.Printf("  HTTP Request Time:    %.3f ms\n", metrics.HttpRequestMs)

		fmt.Println("\n  Client Crypto Operations:")
		for _, op := range metrics.CryptoOperations {
			fmt.Printf("    - %-18s %.3f ms\n", op.Operation, op.DurationMs)
		}

		if metrics.ServerTiming != "" {
			fmt.Println("\n  Server Timing:")
			for _, op := range parseServerTiming(metrics.ServerTiming) {
				fmt.Printf("    - %-18s %.3f ms\n", op.Operation, op.DurationMs)
			}
		}
		fmt.Println()
	}
}

// ===== Main =====

func main() {
	benchmark := flag.Int("benchmark", 0, "Run benchmark with N iterations")
	flag.Parse()

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Session Crypto PoC - Go Client")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Server: %s\n", serverURL)

	if *benchmark > 0 {
		fmt.Printf("  Mode: Benchmark (%d iterations)\n", *benchmark)
		if err := runBenchmark(*benchmark); err != nil {
			fmt.Printf("\n❌ Error: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("  Mode: Single run with metrics")

		session, initMetrics, err := initSession(true)
		if err != nil {
			fmt.Printf("\n❌ Error: %v\n", err)
			os.Exit(1)
		}
		// SECURITY: Clear session key when done
		defer session.Close()

		purchaseMetrics, err := makePurchase(session, PurchaseRequest{SchemeCode: "AEF", Amount: 5000}, true)
		if err != nil {
			fmt.Printf("\n❌ Error: %v\n", err)
			os.Exit(1)
		}

		printMetricsSummary(initMetrics, purchaseMetrics)
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  ✅ Completed successfully!")
	fmt.Println("═══════════════════════════════════════════════════════════════")
}

// ===== Benchmark =====

func runBenchmark(iterations int) error {
	const warmup = 5
	initDurations := make([]float64, 0, iterations)
	purchaseDurations := make([]float64, 0, iterations)
	combinedDurations := make([]float64, 0, iterations)

	fmt.Printf("\n================================================================================\n")
	fmt.Printf("  Throughput Benchmark (%d iterations, %d warmup)\n", iterations, warmup)
	fmt.Printf("================================================================================\n\n")

	for i := 0; i < iterations+warmup; i++ {
		flowStart := time.Now()

		session, initMetrics, err := initSession(false)
		if err != nil {
			return err
		}

		purchaseMetrics, err := makePurchase(session, PurchaseRequest{SchemeCode: "AEF", Amount: 5000}, false)
		if err != nil {
			session.Close() // Clear session key before returning on error
			return err
		}

		flowDuration := float64(time.Since(flowStart).Microseconds()) / 1000.0

		if i >= warmup {
			initDurations = append(initDurations, initMetrics.TotalRoundTripMs)
			purchaseDurations = append(purchaseDurations, purchaseMetrics.TotalRoundTripMs)
			combinedDurations = append(combinedDurations, flowDuration)
		}

		// SECURITY: Clear session key at end of each iteration (not defer in loop!)
		// Using defer inside loop accumulates all defers until function returns
		session.Close()

		if (i+1)%10 == 0 || i == iterations+warmup-1 {
			progress := i + 1 - warmup
			if progress < 0 {
				progress = 0
			}
			if progress > iterations {
				progress = iterations
			}
			fmt.Printf("\r  Progress: %d/%d iterations completed", progress, iterations)
		}
	}

	fmt.Println("\n")

	printBenchmarkStats("/session/init", calculateStats(initDurations))
	printBenchmarkStats("/transaction/purchase", calculateStats(purchaseDurations))
	printBenchmarkStats("Combined (init + purchase)", calculateStats(combinedDurations))

	return nil
}

// ===== Session Initialization =====

func initSession(verbose bool) (*SessionContext, *EndpointMetrics, error) {
	totalStart := time.Now()
	var cryptoOps []CryptoTiming

	if verbose {
		fmt.Println("\n📡 Step 1: Initializing session with server...\n")
	}

	// Generate client ECDH keypair (P-256)
	var clientPrivKey *ecdh.PrivateKey
	var clientPubBytes []byte
	measureSync("ecdh-keygen", &cryptoOps, func() any {
		var err error
		clientPrivKey, err = ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		clientPubBytes = clientPrivKey.PublicKey().Bytes()
		return nil
	})

	if verbose {
		fmt.Println("  ✅ Generated client ECDH keypair")
		fmt.Printf("     Public key (first 32 chars): %s...\n", base64.StdEncoding.EncodeToString(clientPubBytes)[:32])
	}

	nonce := uuid.New().String()
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	requestID := fmt.Sprintf("%s.%s", timestamp, nonce)

	if verbose {
		fmt.Println("\n  📤 Sending POST /session/init")
		fmt.Printf("     X-Idempotency-Key: %s\n", requestID)
		fmt.Printf("     X-ClientId: %s\n", clientID)
	}

	reqBody := SessionInitRequest{
		ClientPublicKey: base64.StdEncoding.EncodeToString(clientPubBytes),
		TTLSec:          1800,
	}

	reqJSON, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", serverURL+"/session/init", bytes.NewReader(reqJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Idempotency-Key", requestID)
	req.Header.Set("X-ClientId", clientID)

	httpStart := time.Now()
	resp, err := httpClient.Do(req)
	httpMs := float64(time.Since(httpStart).Microseconds()) / 1000.0

	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	serverTiming := resp.Header.Get("Server-Timing")

	if resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, nil, fmt.Errorf("session init failed: %d (failed to read error body: %v)", resp.StatusCode, readErr)
		}
		return nil, nil, fmt.Errorf("session init failed: %d - %s", resp.StatusCode, string(body))
	}

	var data SessionInitResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if verbose {
		fmt.Println("\n  📥 Received response:")
		fmt.Printf("     Session ID: %s\n", data.SessionID)
		fmt.Printf("     Encryption: %s\n", data.EncAlg)
		fmt.Printf("     Expires in: %d seconds\n", data.ExpiresInSec)
		fmt.Printf("     Server public key (first 32 chars): %s...\n", data.ServerPublicKey[:32])
	}

	// Decode and import server public key
	serverPubBytes, err := base64.StdEncoding.DecodeString(data.ServerPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode server public key: %w", err)
	}

	serverPubKey, err := ecdh.P256().NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to import server public key: %w", err)
	}

	// Compute shared secret
	var sharedSecret []byte
	measureSync("ecdh-compute", &cryptoOps, func() any {
		var err error
		sharedSecret, err = clientPrivKey.ECDH(serverPubKey)
		if err != nil {
			panic(err)
		}
		return nil
	})
	// SECURITY: Clear shared secret after HKDF
	defer clearBytes(sharedSecret)

	if verbose {
		fmt.Println("\n  🔐 Computed ECDH shared secret")
	}

	// Derive session key using HKDF
	// Info includes clientId for domain separation
	var sessionKey []byte
	measureSync("hkdf", &cryptoOps, func() any {
		salt := []byte(data.SessionID)
		info := []byte(fmt.Sprintf("SESSION|A256GCM|%s", clientID))
		hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, info)
		sessionKey = make([]byte, 32)
		io.ReadFull(hkdfReader, sessionKey)
		return nil
	})

	if verbose {
		fmt.Println("  🔑 Derived session key using HKDF-SHA256")
		fmt.Printf("     Session key (first 16 chars): %s...\n", base64.StdEncoding.EncodeToString(sessionKey)[:16])
	}

	metrics := &EndpointMetrics{
		Endpoint:         "/session/init",
		TotalRoundTripMs: float64(time.Since(totalStart).Microseconds()) / 1000.0,
		HttpRequestMs:    httpMs,
		CryptoOperations: cryptoOps,
		ServerTiming:     serverTiming,
	}

	return &SessionContext{
		SessionID:  data.SessionID,
		SessionKey: sessionKey,
		Kid:        "session:" + data.SessionID,
		ClientID:   clientID,
	}, metrics, nil
}

// ===== Make Purchase =====

func makePurchase(session *SessionContext, purchaseData PurchaseRequest, verbose bool) (*EndpointMetrics, error) {
	totalStart := time.Now()
	var cryptoOps []CryptoTiming

	if verbose {
		fmt.Println("\n📡 Step 2: Making encrypted purchase request...\n")
	}

	plaintext, _ := json.Marshal(purchaseData)
	// SECURITY: Clear request plaintext after encryption
	defer clearBytes(plaintext)

	if verbose {
		fmt.Println("  📝 Request payload:")
		fmt.Printf("     %s\n", string(plaintext))
	}

	// Generate nonce and timestamp for replay protection
	nonce := uuid.New().String()
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	requestID := fmt.Sprintf("%s.%s", timestamp, nonce)

	// Build AAD (server will reconstruct from headers)
	// Format: TIMESTAMP|NONCE|KID|CLIENTID
	aad := []byte(fmt.Sprintf("%s|%s|%s|%s", timestamp, nonce, session.Kid, session.ClientID))

	if verbose {
		fmt.Println("\n  🔒 Encrypting request...")
		fmt.Printf("     AAD: %s|%s...|session:%s...|%s\n",
			timestamp, nonce[:8], session.SessionID[:8], session.ClientID)
	}

	// Encrypt with AES-256-GCM - returns IV || ciphertext || tag
	block, _ := aes.NewCipher(session.SessionKey)
	aesGCM, _ := cipher.NewGCM(block)

	var encryptedBody []byte
	measureSync("aes-gcm-encrypt", &cryptoOps, func() any {
		iv := make([]byte, 12)
		if _, err := rand.Read(iv); err != nil {
			panic(fmt.Sprintf("Failed to generate IV: %v", err))
		}
		ciphertextWithTag := aesGCM.Seal(nil, iv, plaintext, aad)
		encryptedBody = append(iv, ciphertextWithTag...) // IV || ciphertext || tag
		return nil
	})

	if verbose {
		fmt.Printf("     Encrypted body length: %d bytes (IV + ciphertext + tag)\n", len(encryptedBody))
		fmt.Println("\n  📤 Sending encrypted POST /transaction/purchase")
	}

	req, _ := http.NewRequest("POST", serverURL+"/transaction/purchase",
		bytes.NewReader(encryptedBody))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Kid", session.Kid)
	req.Header.Set("X-Idempotency-Key", requestID)
	req.Header.Set("X-ClientId", session.ClientID)

	httpStart := time.Now()
	resp, err := httpClient.Do(req)
	httpMs := float64(time.Since(httpStart).Microseconds()) / 1000.0

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	serverTiming := resp.Header.Get("Server-Timing")

	if resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("purchase failed: %d (failed to read error body: %v)", resp.StatusCode, readErr)
		}
		return nil, fmt.Errorf("purchase failed: %d - %s", resp.StatusCode, string(body))
	}

	if verbose {
		fmt.Printf("\n  📥 Received encrypted response (status: %d)\n", resp.StatusCode)
	}

	// Extract response headers
	respKid := resp.Header.Get("X-Kid")
	respRequestID := resp.Header.Get("X-Idempotency-Key")

	if verbose {
		fmt.Println("     Response headers:")
		fmt.Printf("       X-Kid: %s\n", respKid)
		fmt.Printf("       X-Idempotency-Key: %s...\n", respRequestID[:30])
		fmt.Println("\n  🔓 Decrypting response...")
	}

	// Parse response request ID to get timestamp and nonce for AAD reconstruction
	respParts := strings.Split(respRequestID, ".")
	if len(respParts) != 2 {
		return nil, fmt.Errorf("invalid X-Idempotency-Key format in response")
	}
	respTimestamp := respParts[0]
	respNonce := respParts[1]

	// Reconstruct AAD from response headers
	respAad := []byte(fmt.Sprintf("%s|%s|%s|%s", respTimestamp, respNonce, respKid, session.ClientID))

	// Get encrypted body (IV || ciphertext || tag)
	respEncryptedBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if verbose {
		fmt.Printf("     Encrypted body length: %d bytes\n", len(respEncryptedBody))
	}

	// Extract IV, ciphertext+tag from body
	respIv := respEncryptedBody[:12]
	respCiphertextWithTag := respEncryptedBody[12:]

	var respPlaintext []byte
	measureSync("aes-gcm-decrypt", &cryptoOps, func() any {
		var err error
		respPlaintext, err = aesGCM.Open(nil, respIv, respCiphertextWithTag, respAad)
		if err != nil {
			panic(err)
		}
		return nil
	})
	// SECURITY: Clear decrypted response data
	defer clearBytes(respPlaintext)

	if verbose {
		var responseData map[string]interface{}
		json.Unmarshal(respPlaintext, &responseData)

		fmt.Println("  ✅ Decryption successful!\n")
		fmt.Println("  📋 Decrypted response:")
		fmt.Println("  ─────────────────────────────────────────")
		prettyJSON, _ := json.MarshalIndent(responseData, "", "    ")
		fmt.Println(string(prettyJSON))
		fmt.Println("  ─────────────────────────────────────────")
	}

	return &EndpointMetrics{
		Endpoint:         "/transaction/purchase",
		TotalRoundTripMs: float64(time.Since(totalStart).Microseconds()) / 1000.0,
		HttpRequestMs:    httpMs,
		CryptoOperations: cryptoOps,
		ServerTiming:     serverTiming,
	}, nil
}
