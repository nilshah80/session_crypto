import * as dotenv from 'dotenv';
import { Config } from './types';

// Load environment variables
dotenv.config();

function getEnvVar(name: string, defaultValue?: string): string {
  const value = process.env[name];
  if (value === undefined) {
    if (defaultValue !== undefined) {
      return defaultValue;
    }
    throw new Error(`Environment variable ${name} is required`);
  }
  return value;
}

function getEnvNumber(name: string, defaultValue?: number): number {
  const value = process.env[name];
  if (value === undefined) {
    if (defaultValue !== undefined) {
      return defaultValue;
    }
    throw new Error(`Environment variable ${name} is required`);
  }
  const num = parseInt(value, 10);
  if (isNaN(num)) {
    throw new Error(`Environment variable ${name} must be a number`);
  }
  return num;
}

const redisPassword = process.env['REDIS_PASSWORD'];

export const config: Config = {
  // Server
  HOST: getEnvVar('HOST', '0.0.0.0'),
  NODE_ENV: getEnvVar('NODE_ENV', 'development'),
  PORT: getEnvNumber('PORT', 3000),
  SERVICE_NAME: getEnvVar('SERVICE_NAME', 'identity-service-node'),

  // Logging
  LOG_LEVEL: getEnvVar('LOG_LEVEL', 'info'),
  LOG_FORMAT: getEnvVar('LOG_FORMAT', 'json'),
  LOG_SAMPLE_RATE: getEnvNumber('LOG_SAMPLE_RATE', 100),
  SLOW_THRESHOLD_MS: getEnvNumber('SLOW_THRESHOLD_MS', 500),
  MAX_LOG_BODY_SIZE_BYTES: getEnvNumber('MAX_LOG_BODY_SIZE_BYTES', 10240),

  // Database
  DATABASE_HOST: getEnvVar('DATABASE_HOST', 'localhost'),
  DATABASE_PORT: getEnvNumber('DATABASE_PORT', 5432),
  DATABASE_NAME: getEnvVar('DATABASE_NAME', 'identity_db'),
  DATABASE_USER: getEnvVar('DATABASE_USER', 'postgres'),
  DATABASE_PASSWORD: getEnvVar('DATABASE_PASSWORD', 'postgres'),
  DATABASE_POOL_MIN: getEnvNumber('DATABASE_POOL_MIN', 2),
  DATABASE_POOL_MAX: getEnvNumber('DATABASE_POOL_MAX', 10),
  DATABASE_IDLE_TIMEOUT_MS: getEnvNumber('DATABASE_IDLE_TIMEOUT_MS', 30000),
  DATABASE_CONNECTION_TIMEOUT_MS: getEnvNumber(
    'DATABASE_CONNECTION_TIMEOUT_MS',
    30000
  ),
  DATABASE_STATEMENT_TIMEOUT_MS: getEnvNumber(
    'DATABASE_STATEMENT_TIMEOUT_MS',
    5000
  ),
  DATABASE_QUERY_TIMEOUT_MS: getEnvNumber('DATABASE_QUERY_TIMEOUT_MS', 10000),

  // Redis
  REDIS_URL: getEnvVar('REDIS_URL', 'redis://localhost:6379'),
  ...(redisPassword && { REDIS_PASSWORD: redisPassword }),
  REDIS_MAX_RECONNECT_ATTEMPTS: getEnvNumber(
    'REDIS_MAX_RECONNECT_ATTEMPTS',
    10
  ),
  REDIS_RECONNECT_BASE_DELAY_MS: getEnvNumber(
    'REDIS_RECONNECT_BASE_DELAY_MS',
    100
  ),
  REDIS_RECONNECT_MAX_DELAY_MS: getEnvNumber(
    'REDIS_RECONNECT_MAX_DELAY_MS',
    10000
  ),

  // Session Configuration
  SESSION_TTL_MIN_SEC: getEnvNumber('SESSION_TTL_MIN_SEC', 60), // 1 minute
  SESSION_TTL_MAX_SEC: getEnvNumber('SESSION_TTL_MAX_SEC', 3600), // 1 hour
  SESSION_TTL_DEFAULT_SEC: getEnvNumber('SESSION_TTL_DEFAULT_SEC', 900), // 15 minutes

  // Replay Protection Configuration
  REPLAY_TIMESTAMP_WINDOW_SEC: getEnvNumber('REPLAY_TIMESTAMP_WINDOW_SEC', 300), // 5 minutes
  REPLAY_NONCE_TTL_SEC: getEnvNumber('REPLAY_NONCE_TTL_SEC', 600), // 10 minutes

  // Cache Configuration
  CACHE_LRU_MAX_TTL_SECONDS: getEnvNumber('CACHE_LRU_MAX_TTL_SECONDS', 600), // 10 minutes

  // HTTP Server Timeouts
  CONNECTION_TIMEOUT_MS: getEnvNumber('CONNECTION_TIMEOUT_MS', 30000), // 30 seconds
  REQUEST_TIMEOUT_MS: getEnvNumber('REQUEST_TIMEOUT_MS', 60000), // 60 seconds
  BODY_LIMIT_BYTES: getEnvNumber('BODY_LIMIT_BYTES', 1048576), // 1 MB
};
