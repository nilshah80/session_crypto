use aws_lc_rs::{
    aead::{self, Aad, BoundKey, Nonce, NonceSequence, NONCE_LEN},
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey},
    hkdf::{Salt, HKDF_SHA256},
    rand::{SecureRandom, SystemRandom},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::env;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const SERVER_URL: &str = "http://localhost:3000";

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
    key_agreement: String,
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
}

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
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
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

fn print_benchmark_stats(label: &str, stats: &BenchmarkStats) {
    println!("{}:", label);
    println!("  Throughput:    {:.1} req/s", 1000.0 / stats.mean_ms);
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

    println!("═══════════════════════════════════════════════════════════════");
    println!("  Session Crypto PoC - Rust Client");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Server: {}", SERVER_URL);

    if is_benchmark {
        println!("  Mode: Benchmark ({} iterations)", benchmark_iterations);
    } else {
        println!("  Mode: Single run with metrics");
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
    let client = reqwest::Client::new();
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
    let mut init_durations: Vec<f64> = Vec::with_capacity(iterations);
    let mut purchase_durations: Vec<f64> = Vec::with_capacity(iterations);
    let mut combined_durations: Vec<f64> = Vec::with_capacity(iterations);

    // Reuse a single client for all iterations
    let client = reqwest::Client::new();

    println!("\n================================================================================");
    println!(
        "  Throughput Benchmark ({} iterations, {} warmup)",
        iterations, WARMUP
    );
    println!("================================================================================\n");

    for i in 0..(iterations + WARMUP) {
        let flow_start = Instant::now();

        let (session, init_metrics) = init_session(&client, false).await?;
        let purchase_metrics = make_purchase(
            &client,
            &session,
            PurchaseRequest {
                scheme_code: "AEF".to_string(),
                amount: 5000,
            },
            false,
        )
        .await?;

        let flow_duration = flow_start.elapsed().as_secs_f64() * 1000.0;

        if i >= WARMUP {
            init_durations.push(init_metrics.total_round_trip_ms);
            purchase_durations.push(purchase_metrics.total_round_trip_ms);
            combined_durations.push(flow_duration);
        }

        if (i + 1) % 10 == 0 || i == iterations + WARMUP - 1 {
            let progress = if i >= WARMUP { i + 1 - WARMUP } else { 0 };
            let progress = progress.min(iterations);
            print!("\r  Progress: {}/{} iterations completed", progress, iterations);
        }
    }

    println!("\n");

    print_benchmark_stats("/session/init", &calculate_stats(&init_durations));
    print_benchmark_stats(
        "/transaction/purchase",
        &calculate_stats(&purchase_durations),
    );
    print_benchmark_stats(
        "Combined (init + purchase)",
        &calculate_stats(&combined_durations),
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
            let private_key =
                EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
            let public_key = private_key.compute_public_key().unwrap();
            // ring returns uncompressed point format (65 bytes for P-256)
            let pub_bytes = public_key.as_ref().to_vec();
            (private_key, pub_bytes)
        });

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

    if verbose {
        println!("\n  📤 Sending POST /session/init");
        println!("     X-Nonce: {}", nonce);
        println!("     X-Timestamp: {}", timestamp);
    }

    let req_body = SessionInitRequest {
        key_agreement: "ECDH_P256".to_string(),
        client_public_key: BASE64.encode(&client_pub_bytes),
        ttl_sec: 1800,
    };

    let http_start = Instant::now();
    let response = client
        .post(format!("{}/session/init", SERVER_URL))
        .header("Content-Type", "application/json")
        .header("X-Nonce", &nonce)
        .header("X-Timestamp", &timestamp)
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
    let shared_secret: Vec<u8> = measure_sync("ecdh-compute", &mut crypto_ops, || {
        agreement::agree_ephemeral(
            client_private_key,
            &server_public_key,
            aws_lc_rs::error::Unspecified,
            |secret| Ok::<Vec<u8>, aws_lc_rs::error::Unspecified>(secret.to_vec()),
        )
        .unwrap()
    });

    if verbose {
        println!("\n  🔐 Computed ECDH shared secret");
    }

    // Derive session key using HKDF
    let session_key = measure_sync("hkdf", &mut crypto_ops, || {
        let salt = Salt::new(HKDF_SHA256, data.session_id.as_bytes());
        let prk = salt.extract(shared_secret.as_slice());
        let info = &[b"SESSION|A256GCM|AUTH".as_slice()];
        let okm = prk.expand(info, HKDF_SHA256).unwrap();
        let mut key = vec![0u8; 32];
        okm.fill(&mut key).unwrap();
        key
    });

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

    let plaintext = serde_json::to_vec(&purchase_data)?;

    if verbose {
        println!("  📝 Request payload:");
        println!("     {}", serde_json::to_string(&purchase_data)?);
    }

    // Generate IV and nonce
    let mut iv = [0u8; 12];
    rng.fill(&mut iv).unwrap();
    let nonce_str = uuid::Uuid::new_v4().to_string();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .to_string();

    // Build AAD
    let aad = format!(
        "POST|/transaction/purchase|{}|{}|{}",
        timestamp, nonce_str, session.kid
    );
    let aad_bytes = aad.as_bytes();

    if verbose {
        println!("\n  🔒 Encrypting request...");
        println!("     IV (base64): {}", BASE64.encode(&iv));
        println!(
            "     AAD: POST|/transaction/purchase|{}|{}...|session:{}...",
            timestamp,
            &nonce_str[..8],
            &session.session_id[..8]
        );
    }

    // Encrypt with AES-256-GCM
    let (ciphertext, tag) = measure_sync("aes-gcm-encrypt", &mut crypto_ops, || {
        let unbound_key =
            aead::UnboundKey::new(&aead::AES_256_GCM, &session.session_key).unwrap();
        let nonce_seq = SingleNonce::new(iv);
        let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_seq);

        let mut in_out = plaintext.clone();
        let aad = Aad::from(aad_bytes);
        let tag = sealing_key.seal_in_place_separate_tag(aad, &mut in_out).unwrap();

        (in_out, tag.as_ref().to_vec())
    });

    if verbose {
        println!("     Ciphertext length: {} bytes", ciphertext.len());
        println!("     Auth tag (base64): {}", BASE64.encode(&tag));
        println!("\n  📤 Sending encrypted POST /transaction/purchase");
    }

    let http_start = Instant::now();
    let response = client
        .post(format!("{}/transaction/purchase", SERVER_URL))
        .header("Content-Type", "application/octet-stream")
        .header("X-Kid", &session.kid)
        .header("X-Enc-Alg", "A256GCM")
        .header("X-IV", BASE64.encode(&iv))
        .header("X-Tag", BASE64.encode(&tag))
        .header("X-AAD", BASE64.encode(aad_bytes))
        .header("X-Nonce", &nonce_str)
        .header("X-Timestamp", &timestamp)
        .body(BASE64.encode(&ciphertext))
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
    let resp_iv_b64 = response
        .headers()
        .get("X-IV")
        .ok_or("Missing X-IV header")?
        .to_str()?
        .to_string();
    let resp_tag_b64 = response
        .headers()
        .get("X-Tag")
        .ok_or("Missing X-Tag header")?
        .to_str()?
        .to_string();
    let resp_aad_b64 = response
        .headers()
        .get("X-AAD")
        .ok_or("Missing X-AAD header")?
        .to_str()?
        .to_string();
    let resp_kid = response
        .headers()
        .get("X-Kid")
        .ok_or("Missing X-Kid header")?
        .to_str()?
        .to_string();
    let resp_enc_alg = response
        .headers()
        .get("X-Enc-Alg")
        .ok_or("Missing X-Enc-Alg header")?
        .to_str()?
        .to_string();

    if verbose {
        println!("     Response headers:");
        println!("       X-Kid: {}", resp_kid);
        println!("       X-Enc-Alg: {}", resp_enc_alg);
        println!("       X-IV: {}...", &resp_iv_b64[..16]);
        println!("       X-Tag: {}...", &resp_tag_b64[..20]);
    }

    let body = response.text().await?;

    if verbose {
        println!("\n  🔓 Decrypting response...");
    }

    // Decode response
    let resp_iv = BASE64.decode(&resp_iv_b64)?;
    let resp_tag = BASE64.decode(&resp_tag_b64)?;
    let resp_aad = BASE64.decode(&resp_aad_b64)?;
    let resp_ciphertext = BASE64.decode(&body)?;

    // Decrypt response
    let resp_plaintext = measure_sync("aes-gcm-decrypt", &mut crypto_ops, || {
        let unbound_key =
            aead::UnboundKey::new(&aead::AES_256_GCM, &session.session_key).unwrap();
        let mut resp_iv_arr = [0u8; 12];
        resp_iv_arr.copy_from_slice(&resp_iv);
        let nonce_seq = SingleNonce::new(resp_iv_arr);
        let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_seq);

        // Combine ciphertext and tag
        let mut in_out = resp_ciphertext.clone();
        in_out.extend_from_slice(&resp_tag);

        let aad = Aad::from(resp_aad.as_slice());
        let plaintext = opening_key.open_in_place(aad, &mut in_out).unwrap();
        plaintext.to_vec()
    });

    if verbose {
        let response_data: serde_json::Value = serde_json::from_slice(&resp_plaintext)?;
        println!("  ✅ Decryption successful!\n");
        println!("  📋 Decrypted response:");
        println!("  ─────────────────────────────────────────");
        println!("{}", serde_json::to_string_pretty(&response_data)?);
        println!("  ─────────────────────────────────────────");
    }

    Ok(EndpointMetrics {
        endpoint: "/transaction/purchase".to_string(),
        total_round_trip_ms: total_start.elapsed().as_secs_f64() * 1000.0,
        http_request_ms: http_ms,
        crypto_operations: crypto_ops,
        server_timing,
    })
}
