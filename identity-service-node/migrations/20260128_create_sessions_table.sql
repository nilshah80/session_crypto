-- Migration: Create sessions table
-- Date: 2026-01-28
-- Description: Creates sessions table for storing ECDH session data

-- Create sessions table with separate columns
CREATE TABLE IF NOT EXISTS sessions (
  session_id VARCHAR(255) PRIMARY KEY,
  session_key TEXT NOT NULL,
  session_type VARCHAR(50) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  principal VARCHAR(255),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_client_id ON sessions(client_id);

-- Add comments for documentation
COMMENT ON TABLE sessions IS 'Stores ECDH session data with encrypted keys';
COMMENT ON COLUMN sessions.session_id IS 'Session identifier (format: S-{32-hex-chars})';
COMMENT ON COLUMN sessions.session_key IS 'Derived AES-256-GCM session key (base64 encoded, 32 bytes)';
COMMENT ON COLUMN sessions.session_type IS 'Session type identifier (e.g., ecdh)';
COMMENT ON COLUMN sessions.client_id IS 'Client identifier from X-ClientId header';
COMMENT ON COLUMN sessions.principal IS 'Principal/user identifier (optional, for authenticated sessions)';
COMMENT ON COLUMN sessions.expires_at IS 'Session expiration timestamp';
COMMENT ON COLUMN sessions.created_at IS 'Session creation timestamp';
