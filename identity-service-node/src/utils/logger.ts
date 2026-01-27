import winston from 'winston';
import { config } from '../config';

// Create Winston logger
const logger = winston.createLogger({
  level: config.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: 'identity-service-node' },
  transports: [
    // Console transport
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ level, message, timestamp, ...metadata }) => {
          let msg = `${timestamp} [${level}]: ${message}`;
          if (Object.keys(metadata).length > 0 && metadata['service'] !== undefined) {
            msg += ` ${JSON.stringify(metadata)}`;
          }
          return msg;
        })
      ),
    }),
  ],
});

// Export logger with utility methods
export const log = {
  info: (context: string, message: string, metadata?: Record<string, any>) => {
    logger.info(message, { context, ...metadata });
  },
  error: (
    context: string,
    message: string,
    error?: Error,
    metadata?: Record<string, any>
  ) => {
    logger.error(message, {
      context,
      error: error?.message,
      stack: error?.stack,
      ...metadata,
    });
  },
  warn: (context: string, message: string, metadata?: Record<string, any>) => {
    logger.warn(message, { context, ...metadata });
  },
  debug: (context: string, message: string, metadata?: Record<string, any>) => {
    logger.debug(message, { context, ...metadata });
  },
};

export default log;
