use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
// RustCrypto native crates
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey,
};
use sha2::Sha256;
use rand::RngCore;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, warn};

// Constants
const TIMESTAMP_WINDOW_MS: i64 = 5 * 60 * 1000; // ±5 minutes
const NONCE_TTL_SEC: u64 = 300; // 5 minutes
const NONCE_PREFIX: &str = "nonce:";
const SESSION_PREFIX: &str = "sess:";

// App state
struct AppState {
    redis: Mutex<redis::aio::MultiplexedConnection>,
}

// Types
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionInitRequest {
    client_public_key: String,
    ttl_sec: Option<i32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionInitResponse {
    session_id: String,
    server_public_key: String,
    enc_alg: String,
    expires_in_sec: i32,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    timestamp: String,
    redis: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionData {
    key: String,
    #[serde(rename = "type")]
    session_type: String,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionRequest {
    scheme_code: String,
    amount: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionResponse {
    status: String,
    transaction_id: String,
    scheme_code: String,
    amount: f64,
    timestamp: String,
    message: String,
}

// Metrics collector for Server-Timing header
struct MetricsCollector {
    start_time: Instant,
    operations: Vec<(String, f64)>,
}

impl MetricsCollector {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            operations: Vec::new(),
        }
    }

    fn measure<T, F: FnOnce() -> T>(&mut self, operation: &str, f: F) -> T {
        let start = Instant::now();
        let result = f();
        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        self.operations.push((operation.to_string(), duration_ms));
        result
    }

    async fn measure_async<T, F>(&mut self, operation: &str, f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        let start = Instant::now();
        let result = f.await;
        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        self.operations.push((operation.to_string(), duration_ms));
        result
    }

    fn to_server_timing_header(&self) -> String {
        let mut parts: Vec<String> = self
            .operations
            .iter()
            .map(|(op, dur)| format!("{};dur={:.3}", op.replace(' ', "-"), dur))
            .collect();
        let total_ms = self.start_time.elapsed().as_secs_f64() * 1000.0;
        parts.push(format!("total;dur={:.3}", total_ms));
        parts.join(", ")
    }
}

// Crypto helpers using RustCrypto
fn b64_encode(data: &[u8]) -> String {
    BASE64.encode(data)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64.decode(s)
}

fn generate_session_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("{}-{}", prefix, hex::encode(bytes))
}

fn generate_iv() -> [u8; 12] {
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    iv
}

fn generate_random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn current_timestamp_iso() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let secs = now / 1000;
    let millis = now % 1000;
    chrono_lite(secs as i64, millis as u32)
}

// Simple ISO timestamp formatter without chrono dependency
fn chrono_lite(secs: i64, millis: u32) -> String {
    const SECS_PER_DAY: i64 = 86400;
    const DAYS_PER_400Y: i64 = 146097;
    const DAYS_PER_100Y: i64 = 36524;
    const DAYS_PER_4Y: i64 = 1461;

    let mut days = secs / SECS_PER_DAY;
    let mut rem_secs = (secs % SECS_PER_DAY) as u32;
    if secs < 0 && rem_secs != 0 {
        days -= 1;
        rem_secs = (SECS_PER_DAY as u32) - rem_secs;
    }

    days += 719468;

    let mut year = 1;
    let mut q = days / DAYS_PER_400Y;
    year += q * 400;
    days -= q * DAYS_PER_400Y;

    q = days / DAYS_PER_100Y;
    if q == 4 { q = 3; }
    year += q * 100;
    days -= q * DAYS_PER_100Y;

    q = days / DAYS_PER_4Y;
    year += q * 4;
    days -= q * DAYS_PER_4Y;

    q = days / 365;
    if q == 4 { q = 3; }
    year += q;
    days -= q * 365;

    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days: [i64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0;
    for (i, &d) in month_days.iter().enumerate() {
        if days < d {
            month = i + 1;
            break;
        }
        days -= d;
    }
    let day = days + 1;

    let hour = rem_secs / 3600;
    rem_secs %= 3600;
    let minute = rem_secs / 60;
    let second = rem_secs % 60;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hour, minute, second, millis
    )
}

// HKDF using RustCrypto
fn hkdf32(shared_secret: &[u8], salt_bytes: &[u8], info: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt_bytes), shared_secret);
    let mut okm = vec![0u8; 32];
    hk.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}

// AES-256-GCM encryption - returns IV || ciphertext || tag
fn aes_gcm_encrypt(
    key: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let iv = generate_iv();
    let cipher = Aes256Gcm::new_from_slice(key).expect("Invalid key length");
    let nonce = Nonce::from_slice(&iv);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext_with_tag = cipher.encrypt(nonce, payload)?;

    // Return IV || ciphertext || tag (tag is already appended by aes_gcm)
    let mut result = Vec::with_capacity(12 + ciphertext_with_tag.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext_with_tag);
    Ok(result)
}

// AES-256-GCM decryption - expects IV || ciphertext || tag
fn aes_gcm_decrypt(
    key: &[u8],
    aad: &[u8],
    encrypted_body: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    if encrypted_body.len() < 12 + 16 {
        return Err(aes_gcm::Error);
    }

    let iv = &encrypted_body[..12];
    let ciphertext_with_tag = &encrypted_body[12..];

    let cipher = Aes256Gcm::new_from_slice(key).expect("Invalid key length");
    let nonce = Nonce::from_slice(iv);

    let payload = Payload {
        msg: ciphertext_with_tag,
        aad,
    };

    cipher.decrypt(nonce, payload)
}

// Build AAD from request components
fn build_aad(ts: &str, nonce: &str, kid: &str, client_id: &str) -> Vec<u8> {
    format!("{}|{}|{}|{}", ts, nonce, kid, client_id).into_bytes()
}

// Validate P-256 public key (65 bytes uncompressed format)
fn validate_p256_public_key(public_key_bytes: &[u8]) -> Result<PublicKey, &'static str> {
    if public_key_bytes.len() != 65 {
        return Err("INVALID_KEY_LENGTH");
    }

    if public_key_bytes[0] != 0x04 {
        return Err("INVALID_KEY_FORMAT");
    }

    PublicKey::from_sec1_bytes(public_key_bytes).map_err(|_| "INVALID_KEY")
}

// Replay protection
async fn validate_replay_protection(
    redis: &mut redis::aio::MultiplexedConnection,
    nonce: &str,
    timestamp: &str,
) -> Result<(), &'static str> {
    let ts: i64 = timestamp.parse().map_err(|_| "TIMESTAMP_INVALID")?;
    let now = current_timestamp_ms();

    if (now - ts).abs() > TIMESTAMP_WINDOW_MS {
        return Err("TIMESTAMP_INVALID");
    }

    let key = format!("{}{}", NONCE_PREFIX, nonce);
    let was_set: bool = redis::cmd("SET")
        .arg(&key)
        .arg("1")
        .arg("EX")
        .arg(NONCE_TTL_SEC)
        .arg("NX")
        .query_async(redis)
        .await
        .map_err(|_| "REDIS_ERROR")?;

    if !was_set {
        return Err("REPLAY_DETECTED");
    }

    Ok(())
}

// Session store operations
async fn store_session(
    redis: &mut redis::aio::MultiplexedConnection,
    session_id: &str,
    key: &[u8],
    session_type: &str,
    ttl_sec: i32,
) -> Result<(), redis::RedisError> {
    let expires_at = current_timestamp_ms() + (ttl_sec as i64) * 1000;
    let data = SessionData {
        key: b64_encode(key),
        session_type: session_type.to_string(),
        expires_at,
    };

    let json_data = serde_json::to_string(&data).unwrap();
    let redis_key = format!("{}{}", SESSION_PREFIX, session_id);

    redis
        .set_ex::<_, _, ()>(&redis_key, json_data, ttl_sec as u64)
        .await
}

async fn get_session(
    redis: &mut redis::aio::MultiplexedConnection,
    session_id: &str,
) -> Option<SessionData> {
    let redis_key = format!("{}{}", SESSION_PREFIX, session_id);
    let value: Option<String> = redis.get(&redis_key).await.ok()?;

    let value = value?;
    let data: SessionData = serde_json::from_str(&value).ok()?;

    if current_timestamp_ms() > data.expires_at {
        let _: Result<(), _> = redis.del::<_, ()>(&redis_key).await;
        return None;
    }

    Some(data)
}

// HTTP Handlers
async fn session_init_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SessionInitRequest>,
) -> impl IntoResponse {
    let mut metrics = MetricsCollector::new();

    let idempotency_key = headers.get("x-idempotency-key").and_then(|v| v.to_str().ok()).unwrap_or("");
    let client_id = headers.get("x-clientid").and_then(|v| v.to_str().ok()).unwrap_or("");

    if idempotency_key.is_empty() || client_id.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
    }

    // Parse X-Idempotency-Key: timestamp.nonce
    let parts: Vec<&str> = idempotency_key.split('.').collect();
    if parts.len() != 2 {
        return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
    }
    let timestamp = parts[0];
    let nonce = parts[1];

    // Replay protection
    {
        let mut redis = state.redis.lock().await;
        let result = metrics
            .measure_async("replay-protection", async {
                validate_replay_protection(&mut redis, nonce, timestamp).await
            })
            .await;

        if let Err(e) = result {
            warn!("Replay protection failed: {}", e);
            return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
        }
    }

    if req.client_public_key.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
    }

    // Decode and validate client public key
    let client_pub_key = match metrics.measure("validate-pubkey", || {
        let pub_bytes = b64_decode(&req.client_public_key)?;
        validate_p256_public_key(&pub_bytes).map_err(|_| base64::DecodeError::InvalidLength(0))
    }) {
        Ok(pk) => pk,
        Err(_) => {
            warn!("Client public key validation failed");
            return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
        }
    };

    // Generate server ECDH keypair using p256 crate
    let server_secret = metrics.measure("ecdh-keygen", || {
        EphemeralSecret::random(&mut rand::thread_rng())
    });
    let server_public = p256::PublicKey::from(&server_secret);
    let server_pub_bytes = server_public.to_encoded_point(false).as_bytes().to_vec();

    // Compute shared secret using ECDH
    let shared_secret = metrics.measure("ecdh-compute", || {
        server_secret.diffie_hellman(&client_pub_key)
    });

    // Generate session ID
    let session_id = generate_session_id("S");

    // Cap TTL between 5 minutes and 1 hour
    let ttl_sec = req.ttl_sec.unwrap_or(1800).clamp(300, 3600);

    // Derive session key using HKDF
    let salt = session_id.as_bytes();
    let info = format!("SESSION|A256GCM|{}", client_id);
    let session_key = metrics.measure("hkdf", || {
        hkdf32(shared_secret.raw_secret_bytes().as_slice(), salt, info.as_bytes())
    });

    // Store session in Redis
    {
        let mut redis = state.redis.lock().await;
        let result = metrics
            .measure_async("redis-store", async {
                store_session(&mut redis, &session_id, &session_key, "AUTH", ttl_sec).await
            })
            .await;

        if let Err(e) = result {
            warn!("Failed to store session: {:?}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &metrics);
        }
    }

    info!("Session created: {}, ttl: {}", session_id, ttl_sec);

    let response = SessionInitResponse {
        session_id,
        server_public_key: b64_encode(&server_pub_bytes),
        enc_alg: "A256GCM".to_string(),
        expires_in_sec: ttl_sec,
    };

    success_response(StatusCode::OK, response, &metrics)
}

async fn transaction_purchase_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let mut metrics = MetricsCollector::new();

    let kid = headers.get("x-kid").and_then(|v| v.to_str().ok()).unwrap_or("");
    let idempotency_key = headers.get("x-idempotency-key").and_then(|v| v.to_str().ok()).unwrap_or("");
    let client_id = headers.get("x-clientid").and_then(|v| v.to_str().ok()).unwrap_or("");

    if kid.is_empty() || idempotency_key.is_empty() || client_id.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
    }

    // Parse X-Idempotency-Key: timestamp.nonce
    let parts: Vec<&str> = idempotency_key.split('.').collect();
    if parts.len() != 2 {
        return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
    }
    let timestamp = parts[0];
    let nonce = parts[1];

    // Replay protection
    {
        let mut redis = state.redis.lock().await;
        let result = metrics
            .measure_async("replay-protection", async {
                validate_replay_protection(&mut redis, nonce, timestamp).await
            })
            .await;

        if let Err(e) = result {
            warn!("Replay protection failed: {}", e);
            return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
        }
    }

    let session_id = if kid.starts_with("session:") {
        &kid[8..]
    } else {
        return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
    };

    let session = {
        let mut redis = state.redis.lock().await;
        metrics
            .measure_async("redis-get", async { get_session(&mut redis, session_id).await })
            .await
    };

    let session = match session {
        Some(s) => s,
        None => return error_response(StatusCode::UNAUTHORIZED, "SESSION_EXPIRED", &metrics),
    };

    let session_key = match b64_decode(&session.key) {
        Ok(v) => v,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics),
    };

    // Build AAD from headers
    let aad = metrics.measure("aad-build", || build_aad(timestamp, nonce, kid, client_id));

    // Decrypt request body (IV || ciphertext || tag)
    let plaintext = match metrics.measure("aes-gcm-decrypt", || {
        aes_gcm_decrypt(&session_key, &aad, &body)
    }) {
        Ok(p) => p,
        Err(_) => {
            warn!("Decryption failed");
            return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
        }
    };

    let request_data: TransactionRequest = match serde_json::from_slice(&plaintext) {
        Ok(d) => d,
        Err(_) => {
            warn!("Failed to parse decrypted JSON");
            return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
        }
    };

    info!("Decrypted request: {:?}", request_data);

    let response_data = TransactionResponse {
        status: "SUCCESS".to_string(),
        transaction_id: format!("TXN-{}", generate_random_hex(8).to_uppercase()),
        scheme_code: request_data.scheme_code.clone(),
        amount: request_data.amount,
        timestamp: current_timestamp_iso(),
        message: format!(
            "Purchase of {:.2} in scheme {} completed successfully",
            request_data.amount, request_data.scheme_code
        ),
    };

    let response_plaintext = serde_json::to_vec(&response_data).unwrap();
    let response_nonce = uuid::Uuid::new_v4().to_string();
    let response_timestamp = current_timestamp_ms().to_string();
    let response_idempotency_key = format!("{}.{}", response_timestamp, response_nonce);

    let response_aad = build_aad(&response_timestamp, &response_nonce, kid, client_id);

    // Encrypt - returns IV || ciphertext || tag
    let encrypted_response = metrics.measure("aes-gcm-encrypt", || {
        aes_gcm_encrypt(&session_key, &response_aad, &response_plaintext).unwrap()
    });

    let mut response_headers = HeaderMap::new();
    response_headers.insert("X-Kid", HeaderValue::from_str(kid).unwrap());
    response_headers.insert("X-Idempotency-Key", HeaderValue::from_str(&response_idempotency_key).unwrap());
    response_headers.insert("Content-Type", HeaderValue::from_static("application/octet-stream"));
    response_headers.insert("Server-Timing", HeaderValue::from_str(&metrics.to_server_timing_header()).unwrap());

    (StatusCode::OK, response_headers, encrypted_response).into_response()
}

async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let redis_status = {
        let mut redis = state.redis.lock().await;
        match redis::cmd("PING").query_async::<String>(&mut *redis).await {
            Ok(_) => "ok",
            Err(_) => "disconnected",
        }
    };

    let status = if redis_status == "ok" { "ok" } else { "degraded" };

    Json(HealthResponse {
        status: status.to_string(),
        timestamp: current_timestamp_iso(),
        redis: redis_status.to_string(),
    })
}

fn error_response(status: StatusCode, message: &str, metrics: &MetricsCollector) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("application/json"));
    headers.insert("Server-Timing", HeaderValue::from_str(&metrics.to_server_timing_header()).unwrap());

    let body = serde_json::to_string(&ErrorResponse { error: message.to_string() }).unwrap();
    (status, headers, body).into_response()
}

fn success_response<T: Serialize>(status: StatusCode, data: T, metrics: &MetricsCollector) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("application/json"));
    headers.insert("Server-Timing", HeaderValue::from_str(&metrics.to_server_timing_header()).unwrap());

    let body = serde_json::to_string(&data).unwrap();
    (status, headers, body).into_response()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let redis_host = std::env::var("REDIS_HOST").unwrap_or_else(|_| "localhost".to_string());
    let redis_port = std::env::var("REDIS_PORT").unwrap_or_else(|_| "6379".to_string());
    let redis_url = format!("redis://{}:{}", redis_host, redis_port);

    let client = redis::Client::open(redis_url).expect("Failed to create Redis client");

    let mut conn = None;
    for i in 0..10 {
        match client.get_multiplexed_async_connection().await {
            Ok(c) => {
                info!("Connected to Redis");
                conn = Some(c);
                break;
            }
            Err(e) => {
                info!("Waiting for Redis... (attempt {}): {:?}", i + 1, e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    let conn = conn.expect("Failed to connect to Redis after 10 attempts");

    let state = Arc::new(AppState {
        redis: Mutex::new(conn),
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([
            "content-type".parse().unwrap(),
            "x-idempotency-key".parse().unwrap(),
            "x-clientid".parse().unwrap(),
            "x-kid".parse().unwrap(),
        ])
        .expose_headers([
            "server-timing".parse().unwrap(),
            "x-kid".parse().unwrap(),
            "x-idempotency-key".parse().unwrap(),
        ]);

    let app = Router::new()
        .route("/session/init", post(session_init_handler))
        .route("/transaction/purchase", post(transaction_purchase_handler))
        .route("/health", get(health_handler))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("Server listening on http://localhost:3000 (RustCrypto native)");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
    info!("Shutting down...");
}
