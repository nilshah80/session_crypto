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
	KeyAgreement    string `json:"keyAgreement"`
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

type SessionContext struct {
	SessionID  string
	SessionKey []byte
	Kid        string
}

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
			return err
		}

		flowDuration := float64(time.Since(flowStart).Microseconds()) / 1000.0

		if i >= warmup {
			initDurations = append(initDurations, initMetrics.TotalRoundTripMs)
			purchaseDurations = append(purchaseDurations, purchaseMetrics.TotalRoundTripMs)
			combinedDurations = append(combinedDurations, flowDuration)
		}

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

	if verbose {
		fmt.Println("\n  📤 Sending POST /session/init")
		fmt.Printf("     X-Nonce: %s\n", nonce)
		fmt.Printf("     X-Timestamp: %s\n", timestamp)
	}

	reqBody := SessionInitRequest{
		KeyAgreement:    "ECDH_P256",
		ClientPublicKey: base64.StdEncoding.EncodeToString(clientPubBytes),
		TTLSec:          1800,
	}

	reqJSON, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", serverURL+"/session/init", bytes.NewReader(reqJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Timestamp", timestamp)

	httpStart := time.Now()
	resp, err := http.DefaultClient.Do(req)
	httpMs := float64(time.Since(httpStart).Microseconds()) / 1000.0

	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	serverTiming := resp.Header.Get("Server-Timing")

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
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

	if verbose {
		fmt.Println("\n  🔐 Computed ECDH shared secret")
	}

	// Derive session key using HKDF
	var sessionKey []byte
	measureSync("hkdf", &cryptoOps, func() any {
		salt := []byte(data.SessionID)
		info := []byte("SESSION|A256GCM|AUTH")
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

	if verbose {
		fmt.Println("  📝 Request payload:")
		fmt.Printf("     %s\n", string(plaintext))
	}

	// Generate IV and nonce
	iv := make([]byte, 12)
	rand.Read(iv)
	nonce := uuid.New().String()
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())

	// Build AAD
	aad := []byte(fmt.Sprintf("POST|/transaction/purchase|%s|%s|%s", timestamp, nonce, session.Kid))

	if verbose {
		fmt.Println("\n  🔒 Encrypting request...")
		fmt.Printf("     IV (base64): %s\n", base64.StdEncoding.EncodeToString(iv))
		fmt.Printf("     AAD: POST|/transaction/purchase|%s|%s...|session:%s...\n",
			timestamp, nonce[:8], session.SessionID[:8])
	}

	// Encrypt with AES-256-GCM
	block, _ := aes.NewCipher(session.SessionKey)
	aesGCM, _ := cipher.NewGCM(block)

	var ciphertext, tag []byte
	measureSync("aes-gcm-encrypt", &cryptoOps, func() any {
		ciphertextWithTag := aesGCM.Seal(nil, iv, plaintext, aad)
		ciphertext = ciphertextWithTag[:len(ciphertextWithTag)-16]
		tag = ciphertextWithTag[len(ciphertextWithTag)-16:]
		return nil
	})

	if verbose {
		fmt.Printf("     Ciphertext length: %d bytes\n", len(ciphertext))
		fmt.Printf("     Auth tag (base64): %s\n", base64.StdEncoding.EncodeToString(tag))
		fmt.Println("\n  📤 Sending encrypted POST /transaction/purchase")
	}

	req, _ := http.NewRequest("POST", serverURL+"/transaction/purchase",
		bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(ciphertext))))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Kid", session.Kid)
	req.Header.Set("X-Enc-Alg", "A256GCM")
	req.Header.Set("X-IV", base64.StdEncoding.EncodeToString(iv))
	req.Header.Set("X-Tag", base64.StdEncoding.EncodeToString(tag))
	req.Header.Set("X-AAD", base64.StdEncoding.EncodeToString(aad))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Timestamp", timestamp)

	httpStart := time.Now()
	resp, err := http.DefaultClient.Do(req)
	httpMs := float64(time.Since(httpStart).Microseconds()) / 1000.0

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	serverTiming := resp.Header.Get("Server-Timing")

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("purchase failed: %d - %s", resp.StatusCode, string(body))
	}

	if verbose {
		fmt.Printf("\n  📥 Received encrypted response (status: %d)\n", resp.StatusCode)
	}

	// Extract response headers
	respIvB64 := resp.Header.Get("X-IV")
	respTagB64 := resp.Header.Get("X-Tag")
	respAadB64 := resp.Header.Get("X-AAD")

	if verbose {
		fmt.Println("     Response headers:")
		fmt.Printf("       X-Kid: %s\n", resp.Header.Get("X-Kid"))
		fmt.Printf("       X-Enc-Alg: %s\n", resp.Header.Get("X-Enc-Alg"))
		fmt.Printf("       X-IV: %s...\n", respIvB64[:16])
		fmt.Printf("       X-Tag: %s...\n", respTagB64[:20])
		fmt.Println("\n  🔓 Decrypting response...")
	}

	// Decode and decrypt response
	respIv, _ := base64.StdEncoding.DecodeString(respIvB64)
	respTag, _ := base64.StdEncoding.DecodeString(respTagB64)
	respAad, _ := base64.StdEncoding.DecodeString(respAadB64)

	bodyBytes, _ := io.ReadAll(resp.Body)
	respCiphertext, _ := base64.StdEncoding.DecodeString(string(bodyBytes))

	// Combine ciphertext and tag for decryption
	respCiphertextWithTag := append(respCiphertext, respTag...)

	var respPlaintext []byte
	measureSync("aes-gcm-decrypt", &cryptoOps, func() any {
		var err error
		respPlaintext, err = aesGCM.Open(nil, respIv, respCiphertextWithTag, respAad)
		if err != nil {
			panic(err)
		}
		return nil
	})

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
