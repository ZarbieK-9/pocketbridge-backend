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
  
  CONSTRAINT valid_device_name CHECK (length(device_name) <= 50)
);

CREATE INDEX IF NOT EXISTS user_devices_user_id ON user_devices(user_id);
CREATE INDEX IF NOT EXISTS user_devices_device_id ON user_devices(device_id);

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
  is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS user_sessions_device_id ON user_sessions(device_id);
CREATE INDEX IF NOT EXISTS user_sessions_expires_at ON user_sessions(expires_at);

-- Event delivery tracking: Know which device received which event
CREATE TABLE IF NOT EXISTS device_event_delivery (
  event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
  device_id UUID NOT NULL REFERENCES user_devices(device_id) ON DELETE CASCADE,
  delivered_at TIMESTAMP,
  acknowledged_at TIMESTAMP,
  
  PRIMARY KEY (event_id, device_id)
);

CREATE INDEX IF NOT EXISTS device_event_delivery_device_id ON device_event_delivery(device_id);
CREATE INDEX IF NOT EXISTS device_event_delivery_delivered_at ON device_event_delivery(delivered_at);

-- Conflict log: Track events that had conflicts (for debugging/UI)
-- Note: conflict_log already exists from migration 1, so we alter it to add new columns
ALTER TABLE conflict_log
  ADD COLUMN IF NOT EXISTS user_id TEXT REFERENCES users(user_id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS device_id_a UUID,
  ADD COLUMN IF NOT EXISTS device_id_b UUID,
  ADD COLUMN IF NOT EXISTS timestamp_a TIMESTAMP,
  ADD COLUMN IF NOT EXISTS timestamp_b TIMESTAMP,
  ADD COLUMN IF NOT EXISTS resolution TEXT;

-- Rename existing columns if they exist (for compatibility)
DO $$
BEGIN
  -- Rename device_id_1 to device_id_a if it exists and device_id_a doesn't
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='conflict_log' AND column_name='device_id_1')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='conflict_log' AND column_name='device_id_a') THEN
    ALTER TABLE conflict_log RENAME COLUMN device_id_1 TO device_id_a;
  END IF;
  
  -- Rename device_id_2 to device_id_b if it exists and device_id_b doesn't
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='conflict_log' AND column_name='device_id_2')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='conflict_log' AND column_name='device_id_b') THEN
    ALTER TABLE conflict_log RENAME COLUMN device_id_2 TO device_id_b;
  END IF;
  
  -- Rename timestamp_1 to timestamp_a if it exists
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='conflict_log' AND column_name='timestamp_1')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='conflict_log' AND column_name='timestamp_a') THEN
    ALTER TABLE conflict_log RENAME COLUMN timestamp_1 TO timestamp_a;
  END IF;
  
  -- Rename timestamp_2 to timestamp_b if it exists
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='conflict_log' AND column_name='timestamp_2')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='conflict_log' AND column_name='timestamp_b') THEN
    ALTER TABLE conflict_log RENAME COLUMN timestamp_2 TO timestamp_b;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS conflict_log_user_id ON conflict_log(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS conflict_log_stream_id ON conflict_log(stream_id);

-- Ensure events table has device tracking
-- Note: device_id already exists as TEXT from migration 1, so we only add new columns
ALTER TABLE events
  ADD COLUMN IF NOT EXISTS device_seq BIGINT,
  ADD COLUMN IF NOT EXISTS conflict_resolved_at TIMESTAMP;

-- Create indexes for efficient queries
-- Note: device_id is TEXT in events table, so we index it as TEXT
CREATE INDEX IF NOT EXISTS events_device_id_seq ON events(device_id, device_seq DESC);
CREATE INDEX IF NOT EXISTS events_user_stream_ts ON events(user_id, stream_id, created_at DESC);
