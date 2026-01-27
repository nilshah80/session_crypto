import { StructuredLogger } from '@abslamcpr-backend/structured-logger';
import { config } from '../config';

// Initialize structured logger (exact same as identity-service)
export const logger = new StructuredLogger({
  service: config.SERVICE_NAME,
  logLevel: (config.LOG_LEVEL as 'info' | 'warn' | 'error' | 'debug') || 'info',
  logFormat: 'json',
  sampleRate: config.LOG_SAMPLE_RATE,
  slowThresholdMs: config.SLOW_THRESHOLD_MS,
  maxBodySize: config.MAX_LOG_BODY_SIZE_BYTES,
});
