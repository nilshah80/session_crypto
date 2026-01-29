use aws_lc_rs::{
    aead::{self, Aad, BoundKey, Nonce, NonceSequence, NONCE_LEN},
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey},
    hkdf::{Salt, HKDF_SHA256},
    rand::{SecureRandom, SystemRandom},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::env;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use zeroize::Zeroize;

// ===== Environment Config =====

fn env_or_default(key: &str, fallback: &str) -> String {
    env::var(key).unwrap_or_else(|_| fallback.to_string())
}

fn env_int_or_default(key: &str, fallback: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

lazy_static::lazy_static! {
    static ref SESSION_URL: String = env_or_default("SESSION_URL", "http://localhost:3001");
    static ref SERVER_URL: String = env_or_default("SERVER_URL", "http://localhost:3000");
}

fn benchmark_concurrency() -> usize {
    env_int_or_default("BENCHMARK_CONCURRENCY", 1)
}

// ===== Metrics Types =====

#[derive(Debug, Clone, Serialize)]
struct CryptoTiming {
    operation: String,
    duration_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
struct EndpointMetrics {
    endpoint: String,
    total_round_trip_ms: f64,
    http_request_ms: f64,
    crypto_operations: Vec<CryptoTiming>,
    server_timing: Option<String>,
}

#[derive(Debug)]
struct BenchmarkStats {
    #[allow(dead_code)]
    count: usize,
    min_ms: f64,
    max_ms: f64,
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
}

// ===== API Types =====

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionInitRequest {
    client_public_key: String,
    ttl_sec: i32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionInitResponse {
    session_id: String,
    server_public_key: String,
    enc_alg: String,
    expires_in_sec: i32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PurchaseRequest {
    scheme_code: String,
    amount: i32,
}

struct SessionContext {
    session_id: String,
    session_key: Vec<u8>,
    kid: String,
    client_id: String,
}

impl Drop for SessionContext {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

// Client ID for this application
const CLIENT_ID: &str = "RUST_CLIENT";

// ===== Nonce Sequence for AES-GCM =====

struct SingleNonce {
    nonce: Option<[u8; NONCE_LEN]>,
}

impl SingleNonce {
    fn new(nonce_bytes: [u8; NONCE_LEN]) -> Self {
        Self {
            nonce: Some(nonce_bytes),
        }
    }
}

impl NonceSequence for SingleNonce {
    fn advance(&mut self) -> Result<Nonce, aws_lc_rs::error::Unspecified> {
        self.nonce
            .take()
            .map(Nonce::assume_unique_for_key)
            .ok_or(aws_lc_rs::error::Unspecified)
    }
}

// ===== Metrics Helpers =====

fn measure_sync<T, F: FnOnce() -> T>(
    operation: &str,
    timings: &mut Vec<CryptoTiming>,
    f: F,
) -> T {
    let start = Instant::now();
    let result = f();
    timings.push(CryptoTiming {
        operation: operation.to_string(),
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    });
    result
}

fn parse_server_timing(header: &str) -> Vec<CryptoTiming> {
    header
        .split(',')
        .map(|part| {
            let parts: Vec<&str> = part.trim().split(';').collect();
            let name = parts[0].trim();
            let dur = parts
                .get(1)
                .and_then(|p| p.strip_prefix("dur="))
                .and_then(|d| d.parse::<f64>().ok())
                .unwrap_or(0.0);
            CryptoTiming {
                operation: name.to_string(),
                duration_ms: dur,
            }
        })
        .collect()
}

fn calculate_stats(durations: &[f64]) -> BenchmarkStats {
    let mut sorted = durations.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = sorted.len();
    let sum: f64 = sorted.iter().sum();

    BenchmarkStats {
        count: n,
        min_ms: sorted[0],
        max_ms: sorted[n - 1],
        mean_ms: sum / n as f64,
        p50_ms: sorted[(n as f64 * 0.50) as usize],
        p95_ms: sorted[(n as f64 * 0.95) as usize],
        p99_ms: sorted[(n as f64 * 0.99) as usize],
    }
}

fn print_benchmark_stats(
    label: &str,
    stats: &BenchmarkStats,
    iterations: usize,
    concurrency: usize,
    total_time: f64,
) {
    println!("{}:", label);

    // Calculate actual throughput based on concurrency and total time
    let actual_throughput = iterations as f64 / total_time;
    let theoretical_max_throughput = (1000.0 / stats.mean_ms) * concurrency as f64;
    let efficiency = (actual_throughput / theoretical_max_throughput) * 100.0;

    println!(
        "  Throughput:    {:.1} req/s (actual) | {:.1} req/s (theoretical max)",
        actual_throughput, theoretical_max_throughput
    );
    println!(
        "    Calculation: {} iterations / {:.2}s = {:.1} req/s (actual)",
        iterations, total_time, actual_throughput
    );
    println!(
        "                 (1000ms / {:.1}ms) × {} workers = {:.1} req/s (theoretical)",
        stats.mean_ms, concurrency, theoretical_max_throughput
    );
    println!("    Efficiency:  {:.1}% (actual/theoretical)", efficiency);
    println!(
        "  Latency:       Min: {:.1}ms | Max: {:.1}ms | Mean: {:.1}ms",
        stats.min_ms, stats.max_ms, stats.mean_ms
    );
    println!(
        "                 P50: {:.1}ms | P95: {:.1}ms | P99: {:.1}ms",
        stats.p50_ms, stats.p95_ms, stats.p99_ms
    );
    println!();
}

fn print_metrics_summary(init_metrics: &EndpointMetrics, purchase_metrics: &EndpointMetrics) {
    println!("\n================================================================================");
    println!("  Performance Metrics Summary");
    println!("================================================================================\n");

    for metrics in [init_metrics, purchase_metrics] {
        println!("Endpoint: {}", metrics.endpoint);
        println!("----------------------------------------");
        println!(
            "  Total Round-Trip:     {:.3} ms",
            metrics.total_round_trip_ms
        );
        println!("  HTTP Request Time:    {:.3} ms", metrics.http_request_ms);

        println!("\n  Client Crypto Operations:");
        for op in &metrics.crypto_operations {
            println!("    - {:18} {:.3} ms", op.operation, op.duration_ms);
        }

        if let Some(ref server_timing) = metrics.server_timing {
            println!("\n  Server Timing:");
            for op in parse_server_timing(server_timing) {
                println!("    - {:18} {:.3} ms", op.operation, op.duration_ms);
            }
        }
        println!();
    }
}

// ===== Main =====

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let benchmark_idx = args.iter().position(|a| a == "--benchmark");
    let is_benchmark = benchmark_idx.is_some();
    let benchmark_iterations: usize = benchmark_idx
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let concurrency = benchmark_concurrency();

    println!("═══════════════════════════════════════════════════════════════");
    println!("  Session Crypto PoC - Rust Client");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Session Server:  {}", *SESSION_URL);
    println!("  API Server:      {}", *SERVER_URL);

    if is_benchmark {
        println!(
            "  Mode:            Benchmark ({} iterations)",
            benchmark_iterations
        );
        println!("  Concurrency:     {} parallel workers", concurrency);
        println!("  HTTP Keep-Alive: Enabled (connection pooling)");
    } else {
        println!("  Mode:            Single run with metrics");
    }

    let result = if is_benchmark {
        run_benchmark(benchmark_iterations).await
    } else {
        run_single().await
    };

    match result {
        Ok(_) => {
            println!("═══════════════════════════════════════════════════════════════");
            println!("  ✅ Completed successfully!");
            println!("═══════════════════════════════════════════════════════════════\n");
        }
        Err(e) => {
            println!("\n❌ Error: {}", e);
            std::process::exit(1);
        }
    }
}

async fn run_single() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(90))
        .build()?;
    let (session, init_metrics) = init_session(&client, true).await?;
    let purchase_metrics = make_purchase(
        &client,
        &session,
        PurchaseRequest {
            scheme_code: "AEF".to_string(),
            amount: 5000,
        },
        true,
    )
    .await?;

    print_metrics_summary(&init_metrics, &purchase_metrics);
    Ok(())
}

async fn run_benchmark(iterations: usize) -> Result<(), Box<dyn std::error::Error>> {
    const WARMUP: usize = 5;
    let concurrency = benchmark_concurrency();

    // Reuse a single client for all iterations (reqwest Client uses connection pooling)
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(100)
        .build()?;

    println!("\n================================================================================");
    println!(
        "  Throughput Benchmark ({} iterations, {} warmup, concurrency: {})",
        iterations, WARMUP, concurrency
    );
    println!("================================================================================\n");

    // Thread-safe collection of results
    struct IterationResult {
        init_ms: f64,
        purchase_ms: f64,
        combined_ms: f64,
    }

    let total_iterations = iterations + WARMUP;
    let requests_per_worker = (total_iterations + concurrency - 1) / concurrency; // ceil div

    let completed_count = Arc::new(AtomicU64::new(0));
    let results = Arc::new(Mutex::new(Vec::<IterationResult>::new()));
    let first_err: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let start_time = Instant::now();

    // Create concurrent workers
    let mut handles = Vec::new();
    for w in 0..concurrency {
        let worker_start = w * requests_per_worker;
        let worker_end = (worker_start + requests_per_worker).min(total_iterations);
        if worker_start >= total_iterations {
            break;
        }

        let client = client.clone();
        let completed_count = Arc::clone(&completed_count);
        let results = Arc::clone(&results);
        let first_err = Arc::clone(&first_err);

        handles.push(tokio::spawn(async move {
            for i in worker_start..worker_end {
                // Check if another task errored
                {
                    let err = first_err.lock().await;
                    if err.is_some() {
                        return;
                    }
                }

                let flow_start = Instant::now();

                let init_result = init_session(&client, false)
                    .await
                    .map_err(|e| e.to_string());
                let (session, init_metrics) = match init_result {
                    Ok(v) => v,
                    Err(msg) => {
                        let mut err = first_err.lock().await;
                        if err.is_none() {
                            *err = Some(msg);
                        }
                        return;
                    }
                };

                let purchase_result = make_purchase(
                    &client,
                    &session,
                    PurchaseRequest {
                        scheme_code: "AEF".to_string(),
                        amount: 5000,
                    },
                    false,
                )
                .await
                .map_err(|e| e.to_string());
                let purchase_metrics = match purchase_result {
                    Ok(v) => v,
                    Err(msg) => {
                        let mut err = first_err.lock().await;
                        if err.is_none() {
                            *err = Some(msg);
                        }
                        return;
                    }
                };

                let flow_duration = flow_start.elapsed().as_secs_f64() * 1000.0;

                // Skip warmup iterations
                if i >= WARMUP {
                    let mut res = results.lock().await;
                    res.push(IterationResult {
                        init_ms: init_metrics.total_round_trip_ms,
                        purchase_ms: purchase_metrics.total_round_trip_ms,
                        combined_ms: flow_duration,
                    });
                }

                // Progress update
                let completed = completed_count.fetch_add(1, Ordering::Relaxed) + 1;
                if completed % 100 == 0 || completed == total_iterations as u64 {
                    let progress = if completed > WARMUP as u64 {
                        completed - WARMUP as u64
                    } else {
                        0
                    };
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let current_rps = if elapsed > 0.0 {
                        completed as f64 / elapsed
                    } else {
                        0.0
                    };
                    print!(
                        "\r  Progress: {}/{} | Current RPS: {:.0} | Concurrency: {}          ",
                        progress, iterations, current_rps, concurrency
                    );
                    let _ = std::io::stdout().flush();
                }
            }
        }));
    }

    // Wait for all workers to complete
    for handle in handles {
        handle.await?;
    }

    let total_time = start_time.elapsed().as_secs_f64();
    // ⬆️ Timer stops here - all printing below does NOT affect measurements

    // Check for errors
    let err = first_err.lock().await;
    if let Some(ref e) = *err {
        return Err(e.clone().into());
    }
    drop(err);

    println!("\n");

    // Display test summary
    println!("================================================================================");
    println!(
        "  Test Duration: {:.2}s ({:.2} minutes)",
        total_time,
        total_time / 60.0
    );
    println!("================================================================================\n");

    // Extract durations from results
    let results = results.lock().await;
    let init_durations: Vec<f64> = results.iter().map(|r| r.init_ms).collect();
    let purchase_durations: Vec<f64> = results.iter().map(|r| r.purchase_ms).collect();
    let combined_durations: Vec<f64> = results.iter().map(|r| r.combined_ms).collect();

    print_benchmark_stats(
        "/session/init",
        &calculate_stats(&init_durations),
        iterations,
        concurrency,
        total_time,
    );
    print_benchmark_stats(
        "/transaction/purchase",
        &calculate_stats(&purchase_durations),
        iterations,
        concurrency,
        total_time,
    );
    print_benchmark_stats(
        "Combined (init + purchase)",
        &calculate_stats(&combined_durations),
        iterations,
        concurrency,
        total_time,
    );

    Ok(())
}

// ===== Session Initialization =====

async fn init_session(
    client: &reqwest::Client,
    verbose: bool,
) -> Result<(SessionContext, EndpointMetrics), Box<dyn std::error::Error>> {
    let total_start = Instant::now();
    let mut crypto_ops: Vec<CryptoTiming> = Vec::new();
    let rng = SystemRandom::new();

    if verbose {
        println!("\n📡 Step 1: Initializing session with server...\n");
    }

    // Generate client ECDH keypair (P-256)
    let (client_private_key, client_pub_bytes) =
        measure_sync("ecdh-keygen", &mut crypto_ops, || {
            match EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng) {
                Ok(private_key) => match private_key.compute_public_key() {
                    Ok(public_key) => {
                        // ring returns uncompressed point format (65 bytes for P-256)
                        let pub_bytes = public_key.as_ref().to_vec();
                        Ok((private_key, pub_bytes))
                    }
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            }
        })
        .map_err(|_| "ECDH keypair generation failed")?;

    if verbose {
        println!("  ✅ Generated client ECDH keypair");
        println!(
            "     Public key (first 32 chars): {}...",
            &BASE64.encode(&client_pub_bytes)[..32]
        );
    }

    let nonce = uuid::Uuid::new_v4().to_string();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .to_string();
    let request_id = format!("{}.{}", timestamp, nonce);

    if verbose {
        println!("\n  📤 Sending POST /session/init");
        println!("     X-Idempotency-Key: {}", request_id);
        println!("     X-ClientId: {}", CLIENT_ID);
    }

    let req_body = SessionInitRequest {
        client_public_key: BASE64.encode(&client_pub_bytes),
        ttl_sec: 1800,
    };

    let http_start = Instant::now();
    let response = client
        .post(format!("{}/v1/session/init", *SESSION_URL))
        .header("Content-Type", "application/json")
        .header("X-Idempotency-Key", &request_id)
        .header("X-ClientId", CLIENT_ID)
        .json(&req_body)
        .send()
        .await?;
    let http_ms = http_start.elapsed().as_secs_f64() * 1000.0;

    let server_timing = response
        .headers()
        .get("Server-Timing")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if !response.status().is_success() {
        let error = response.text().await?;
        return Err(format!("Session init failed: {}", error).into());
    }

    let data: SessionInitResponse = response.json().await?;

    if verbose {
        println!("\n  📥 Received response:");
        println!("     Session ID: {}", data.session_id);
        println!("     Encryption: {}", data.enc_alg);
        println!("     Expires in: {} seconds", data.expires_in_sec);
        println!(
            "     Server public key (first 32 chars): {}...",
            &data.server_public_key[..32]
        );
    }

    // Decode server public key
    let server_pub_bytes = BASE64.decode(&data.server_public_key)?;
    let server_public_key =
        UnparsedPublicKey::new(&agreement::ECDH_P256, server_pub_bytes);

    // Compute shared secret using ECDH
    let mut shared_secret: Vec<u8> = measure_sync("ecdh-compute", &mut crypto_ops, || {
        agreement::agree_ephemeral(
            client_private_key,
            &server_public_key,
            aws_lc_rs::error::Unspecified,
            |secret: &[u8]| Ok::<_, aws_lc_rs::error::Unspecified>(secret.to_vec()),
        )
    })
    .map_err(|_| "ECDH agreement failed")?;

    if verbose {
        println!("\n  🔐 Computed ECDH shared secret");
    }

    // Derive session key using HKDF
    // Info includes client_id for domain separation
    let session_key = measure_sync("hkdf", &mut crypto_ops, || {
        let salt = Salt::new(HKDF_SHA256, data.session_id.as_bytes());
        let prk = salt.extract(shared_secret.as_slice());
        let info_str = format!("SESSION|A256GCM|{}", CLIENT_ID);
        let info = &[info_str.as_bytes()];
        let okm = prk.expand(info, HKDF_SHA256)?;
        let mut key = vec![0u8; 32];
        okm.fill(&mut key)?;
        Ok::<_, aws_lc_rs::error::Unspecified>(key)
    })
    .map_err(|_| "HKDF key derivation failed")?;

    // Zeroize shared secret
    shared_secret.zeroize();

    if verbose {
        println!("  🔑 Derived session key using HKDF-SHA256");
        println!(
            "     Session key (first 16 chars): {}...",
            &BASE64.encode(&session_key)[..16]
        );
    }

    let metrics = EndpointMetrics {
        endpoint: "/session/init".to_string(),
        total_round_trip_ms: total_start.elapsed().as_secs_f64() * 1000.0,
        http_request_ms: http_ms,
        crypto_operations: crypto_ops,
        server_timing,
    };

    Ok((
        SessionContext {
            session_id: data.session_id.clone(),
            session_key,
            kid: format!("session:{}", data.session_id),
            client_id: CLIENT_ID.to_string(),
        },
        metrics,
    ))
}

// ===== Make Purchase =====

async fn make_purchase(
    client: &reqwest::Client,
    session: &SessionContext,
    purchase_data: PurchaseRequest,
    verbose: bool,
) -> Result<EndpointMetrics, Box<dyn std::error::Error>> {
    let total_start = Instant::now();
    let mut crypto_ops: Vec<CryptoTiming> = Vec::new();
    let rng = SystemRandom::new();

    if verbose {
        println!("\n📡 Step 2: Making encrypted purchase request...\n");
    }

    let mut plaintext = serde_json::to_vec(&purchase_data)?;

    if verbose {
        println!("  📝 Request payload:");
        println!("     {}", serde_json::to_string(&purchase_data)?);
    }

    // Generate nonce and timestamp for replay protection
    let nonce_str = uuid::Uuid::new_v4().to_string();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .to_string();
    let request_id = format!("{}.{}", timestamp, nonce_str);

    // Build AAD (server will reconstruct from headers)
    // Format: TIMESTAMP|NONCE|KID|CLIENTID
    let aad = format!(
        "{}|{}|{}|{}",
        timestamp, nonce_str, session.kid, session.client_id
    );
    let aad_bytes = aad.as_bytes();

    if verbose {
        println!("\n  🔒 Encrypting request...");
        println!(
            "     AAD: {}|{}...|session:{}...|{}",
            timestamp,
            &nonce_str[..8],
            &session.session_id[..8],
            session.client_id
        );
    }

    // Encrypt with AES-256-GCM - returns IV || ciphertext || tag
    let encrypted_body = measure_sync("aes-gcm-encrypt", &mut crypto_ops, || {
        let mut iv = [0u8; 12];
        rng.fill(&mut iv)
            .map_err(|_| "Failed to generate IV")?;

        let unbound_key =
            aead::UnboundKey::new(&aead::AES_256_GCM, &session.session_key)
                .map_err(|_| "Failed to create unbound key")?;
        let nonce_seq = SingleNonce::new(iv);
        let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_seq);

        let mut in_out = plaintext.clone();
        let aad = Aad::from(aad_bytes);
        let tag = sealing_key.seal_in_place_separate_tag(aad, &mut in_out)
            .map_err(|_| "Encryption failed")?;

        // Concatenate IV || ciphertext || tag
        let mut result = Vec::with_capacity(12 + in_out.len() + 16);
        result.extend_from_slice(&iv);
        result.extend_from_slice(&in_out);
        result.extend_from_slice(tag.as_ref());

        // Zeroize in_out buffer after using it
        in_out.zeroize();

        Ok::<_, Box<dyn std::error::Error>>(result)
    })?;

    // Zeroize plaintext after encryption
    plaintext.zeroize();

    if verbose {
        println!("     Encrypted body length: {} bytes (IV + ciphertext + tag)", encrypted_body.len());
        println!("\n  📤 Sending encrypted POST /transaction/purchase");
    }

    let http_start = Instant::now();
    let response = client
        .post(format!("{}/transaction/purchase", *SERVER_URL))
        .header("Content-Type", "application/octet-stream")
        .header("X-Kid", &session.kid)
        .header("X-Idempotency-Key", &request_id)
        .header("X-ClientId", &session.client_id)
        .body(encrypted_body)
        .send()
        .await?;
    let http_ms = http_start.elapsed().as_secs_f64() * 1000.0;

    let server_timing = response
        .headers()
        .get("Server-Timing")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if !response.status().is_success() {
        let error = response.text().await?;
        return Err(format!("Purchase failed: {}", error).into());
    }

    if verbose {
        println!(
            "\n  📥 Received encrypted response (status: {})",
            response.status().as_u16()
        );
    }

    // Extract response headers
    let resp_kid = response
        .headers()
        .get("X-Kid")
        .ok_or("Missing X-Kid header")?
        .to_str()?
        .to_string();
    let resp_request_id = response
        .headers()
        .get("X-Idempotency-Key")
        .ok_or("Missing X-Idempotency-Key header")?
        .to_str()?
        .to_string();

    if verbose {
        println!("     Response headers:");
        println!("       X-Kid: {}", resp_kid);
        println!("       X-Idempotency-Key: {}...", &resp_request_id[..30.min(resp_request_id.len())]);
    }

    // Get encrypted body (IV || ciphertext || tag)
    let resp_encrypted_body = response.bytes().await?;

    if verbose {
        println!("     Encrypted body length: {} bytes", resp_encrypted_body.len());
        println!("\n  🔓 Decrypting response...");
    }

    // Parse response request ID to get timestamp and nonce for AAD reconstruction
    let parts: Vec<&str> = resp_request_id.split('.').collect();
    if parts.len() != 2 {
        return Err("Invalid X-Idempotency-Key format in response".into());
    }
    let resp_timestamp = parts[0];
    let resp_nonce = parts[1];

    // Reconstruct AAD from response headers
    let resp_aad = format!("{}|{}|{}|{}", resp_timestamp, resp_nonce, resp_kid, session.client_id);

    // Decrypt response - body contains IV || ciphertext || tag
    let mut resp_plaintext = measure_sync("aes-gcm-decrypt", &mut crypto_ops, || {
        // Extract IV (first 12 bytes)
        let resp_iv = &resp_encrypted_body[..12];
        // Rest is ciphertext || tag
        let ciphertext_with_tag = &resp_encrypted_body[12..];

        let unbound_key =
            aead::UnboundKey::new(&aead::AES_256_GCM, &session.session_key)
                .map_err(|_| "Failed to create unbound key for decryption")?;
        let mut resp_iv_arr = [0u8; 12];
        resp_iv_arr.copy_from_slice(resp_iv);
        let nonce_seq = SingleNonce::new(resp_iv_arr);
        let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_seq);

        let mut in_out = ciphertext_with_tag.to_vec();
        let aad = Aad::from(resp_aad.as_bytes());
        let plaintext = opening_key.open_in_place(aad, &mut in_out)
            .map_err(|_| "Decryption failed")?;
        Ok::<_, Box<dyn std::error::Error>>(plaintext.to_vec())
    })?;

    if verbose {
        let response_data: serde_json::Value = serde_json::from_slice(&resp_plaintext)?;
        println!("  ✅ Decryption successful!\n");
        println!("  📋 Decrypted response:");
        println!("  ─────────────────────────────────────────");
        println!("{}", serde_json::to_string_pretty(&response_data)?);
        println!("  ─────────────────────────────────────────");
    }

    // Zeroize resp_plaintext before function ends
    resp_plaintext.zeroize();

    Ok(EndpointMetrics {
        endpoint: "/transaction/purchase".to_string(),
        total_round_trip_ms: total_start.elapsed().as_secs_f64() * 1000.0,
        http_request_ms: http_ms,
        crypto_operations: crypto_ops,
        server_timing,
    })
}
