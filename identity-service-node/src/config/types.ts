export interface Config {
  // Server
  HOST: string;
  NODE_ENV: string;
  PORT: number;
  SERVICE_NAME: string;

  // Logging
  LOG_LEVEL: string;
  LOG_FORMAT: string;
  LOG_SAMPLE_RATE: number;
  SLOW_THRESHOLD_MS: number;
  MAX_LOG_BODY_SIZE_BYTES: number;

  // Database
  DATABASE_HOST: string;
  DATABASE_PORT: number;
  DATABASE_NAME: string;
  DATABASE_USER: string;
  DATABASE_PASSWORD: string;
  DATABASE_POOL_MIN: number;
  DATABASE_POOL_MAX: number;
  DATABASE_IDLE_TIMEOUT_MS: number;
  DATABASE_CONNECTION_TIMEOUT_MS: number;
  DATABASE_STATEMENT_TIMEOUT_MS: number;
  DATABASE_QUERY_TIMEOUT_MS: number;

  // Redis
  REDIS_URL: string;
  REDIS_PASSWORD?: string;
  REDIS_MAX_RECONNECT_ATTEMPTS: number;
  REDIS_RECONNECT_BASE_DELAY_MS: number;
  REDIS_RECONNECT_MAX_DELAY_MS: number;

  // Session Configuration
  SESSION_TTL_ANONYMOUS_SEC: number;
  SESSION_TTL_AUTHENTICATED_SEC: number;

  // Replay Protection Configuration
  REPLAY_TIMESTAMP_WINDOW_SEC: number;
  REPLAY_NONCE_TTL_SEC: number;

  // Cache Configuration
  CACHE_LRU_MAX_TTL_SECONDS: number;

  // Session Cleanup Job Configuration
  SESSION_CLEANUP_INTERVAL_MS: number;
  SESSION_CLEANUP_BATCH_SIZE: number;
  SESSION_CLEANUP_BATCH_DELAY_MS: number;
  SESSION_CLEANUP_WARNING_THRESHOLD_MS: number;

  // HTTP Server Timeouts
  CONNECTION_TIMEOUT_MS: number;
  REQUEST_TIMEOUT_MS: number;
  BODY_LIMIT_BYTES: number;
}
