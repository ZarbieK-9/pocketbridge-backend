-- Migration: Create multi-device user tracking tables
-- Version: 2
-- Description: Adds multi-device support with user_devices and user_sessions tables

-- UP

-- Users table: Groups devices by user identity (Ed25519 public key)
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,              -- Ed25519 public key (hex)
  created_at TIMESTAMP DEFAULT NOW(),
  is_active BOOLEAN DEFAULT TRUE,
  last_activity TIMESTAMP DEFAULT NOW()
);

-- User devices: Track all devices connected to a user
CREATE TABLE IF NOT EXISTS user_devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  device_id UUID NOT NULL UNIQUE,         -- UUIDv4 from client
  device_name TEXT,                       -- "iPhone 15", "MacBook", etc
  device_type TEXT,                       -- 'mobile', 'desktop', 'web'
  device_os TEXT,                         -- 'ios', 'android', 'windows', 'macos', 'linux'
  is_online BOOLEAN DEFAULT FALSE,
  last_seen TIMESTAMP DEFAULT NOW(),
  ip_address INET,
  user_agent TEXT,
  public_key_hex TEXT,                    -- Device's Ed25519 public key (backup)
  registered_at TIMESTAMP DEFAULT NOW(),
  
  CONSTRAINT valid_device_name CHECK (length(device_name) <= 50),
  INDEX user_devices_user_id (user_id),
  INDEX user_devices_device_id (device_id)
);

-- User sessions: Track active WebSocket sessions
CREATE TABLE IF NOT EXISTS user_sessions (
  session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  device_id UUID NOT NULL REFERENCES user_devices(device_id) ON DELETE CASCADE,
  ip_address INET,
  user_agent TEXT,
  started_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL,
  last_activity TIMESTAMP DEFAULT NOW(),
  is_active BOOLEAN DEFAULT TRUE,
  
  INDEX user_sessions_user_id (user_id),
  INDEX user_sessions_device_id (device_id),
  INDEX user_sessions_expires_at (expires_at)
);

-- Event delivery tracking: Know which device received which event
CREATE TABLE IF NOT EXISTS device_event_delivery (
  event_id UUID NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
  device_id UUID NOT NULL REFERENCES user_devices(device_id) ON DELETE CASCADE,
  delivered_at TIMESTAMP,
  acknowledged_at TIMESTAMP,
  
  PRIMARY KEY (event_id, device_id),
  INDEX device_event_delivery_device_id (device_id),
  INDEX device_event_delivery_delivered_at (delivered_at)
);

-- Conflict log: Track events that had conflicts (for debugging/UI)
CREATE TABLE IF NOT EXISTS conflict_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  stream_id TEXT NOT NULL,
  stream_seq INT NOT NULL,
  device_id_a UUID NOT NULL,
  device_id_b UUID NOT NULL,
  timestamp_a TIMESTAMP,
  timestamp_b TIMESTAMP,
  resolution TEXT,  -- 'a_wins', 'b_wins', 'merged', etc
  created_at TIMESTAMP DEFAULT NOW(),
  
  INDEX conflict_log_user_id (user_id),
  INDEX conflict_log_stream_id (stream_id)
);

-- Ensure events table has device tracking
ALTER TABLE events
  ADD COLUMN IF NOT EXISTS device_id UUID,
  ADD COLUMN IF NOT EXISTS device_seq BIGINT,
  ADD COLUMN IF NOT EXISTS conflict_resolved_at TIMESTAMP;

-- Create indexes for efficient queries
CREATE INDEX IF NOT EXISTS events_device_id_seq ON events(device_id, device_seq DESC);
CREATE INDEX IF NOT EXISTS events_user_stream_ts ON events(user_id, stream_id, created_at DESC);
