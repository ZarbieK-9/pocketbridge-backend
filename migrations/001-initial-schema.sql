-- Migration: Initial schema
-- Version: 1
-- Description: Creates initial database schema

-- UP

-- Users table (stores Ed25519 public keys)
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY, -- Ed25519 public key (hex)
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  last_activity TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Devices table (legacy, kept for backward compatibility)
CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY, -- UUIDv4
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  device_name TEXT,
  device_type TEXT, -- 'browser', 'desktop'
  last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
  last_ack_device_seq BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Events table (metadata only, for replay index)
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY, -- UUIDv7
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  device_seq BIGINT NOT NULL,
  stream_id TEXT NOT NULL,
  stream_seq BIGINT NOT NULL,
  type TEXT NOT NULL,
  encrypted_payload TEXT NOT NULL, -- Base64-encoded ciphertext (opaque to server)
  payload_size INTEGER, -- Size of encrypted payload in bytes
  ttl TIMESTAMP, -- Optional TTL for self-destruct messages
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Stream sequences table (tracks stream_seq per stream)
CREATE TABLE IF NOT EXISTS stream_sequences (
  stream_id TEXT PRIMARY KEY,
  last_stream_seq BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Revoked devices table
CREATE TABLE IF NOT EXISTS revoked_devices (
  device_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  revoked_at TIMESTAMP NOT NULL DEFAULT NOW(),
  reason TEXT
);

-- Pairing codes table (temporary, expires after 10 minutes)
CREATE TABLE IF NOT EXISTS pairing_codes (
  code TEXT PRIMARY KEY,
  ws_url TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  device_name TEXT,
  public_key_hex TEXT NOT NULL,
  private_key_hex TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Conflict log table
CREATE TABLE IF NOT EXISTS conflict_log (
  id SERIAL PRIMARY KEY,
  stream_id TEXT NOT NULL,
  stream_seq BIGINT NOT NULL,
  device_id_1 TEXT NOT NULL,
  device_id_2 TEXT NOT NULL,
  timestamp_1 TIMESTAMP NOT NULL,
  timestamp_2 TIMESTAMP NOT NULL,
  resolution TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_events_user_id ON events(user_id);
CREATE INDEX IF NOT EXISTS idx_events_device_id ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_events_stream_id ON events(stream_id);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_events_ttl ON events(ttl) WHERE ttl IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pairing_codes_expires_at ON pairing_codes(expires_at);

-- DOWN
-- Note: This migration creates the initial schema, so rollback would drop everything
-- In production, you may want to keep data, so this is commented out
-- DROP TABLE IF EXISTS conflict_log;
-- DROP TABLE IF EXISTS pairing_codes;
-- DROP TABLE IF EXISTS revoked_devices;
-- DROP TABLE IF EXISTS stream_sequences;
-- DROP TABLE IF EXISTS events;
-- DROP TABLE IF EXISTS devices;
-- DROP TABLE IF EXISTS users;

