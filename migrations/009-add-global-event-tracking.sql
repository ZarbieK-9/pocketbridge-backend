-- Migration: Add global event tracking for device replay
-- Version: 9
-- Description: Adds last_received_at and last_received_created_at to track global event progress per device
--              This fixes the offline scenario where multiple devices go offline and come back online

-- UP

-- Add columns to track the most recent event received by each device (globally, not per-device)
ALTER TABLE user_devices
  ADD COLUMN IF NOT EXISTS last_received_created_at TIMESTAMP,
  ADD COLUMN IF NOT EXISTS last_received_event_id TEXT;

-- Create index for efficient replay queries by timestamp
CREATE INDEX IF NOT EXISTS user_devices_received_at ON user_devices(user_id, last_received_created_at DESC);

-- Create index on events for replay queries
CREATE INDEX IF NOT EXISTS events_user_created_at_id ON events(user_id, created_at ASC, event_id ASC);

-- DOWN
-- ALTER TABLE user_devices DROP COLUMN IF EXISTS last_received_created_at;
-- ALTER TABLE user_devices DROP COLUMN IF EXISTS last_received_event_id;
-- DROP INDEX IF EXISTS user_devices_received_at;
-- DROP INDEX IF EXISTS events_user_created_at_id;
