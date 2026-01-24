-- Migration: Add unique constraint to pairing codes
-- Version: 8
-- Description: Prevents pairing code collisions and ensures security

-- UP

-- Add unique constraint to pairing codes
-- This prevents multiple users from generating the same 6-digit code
-- If a collision occurs, the database will reject the insert with error code 23505
CREATE UNIQUE INDEX IF NOT EXISTS idx_pairing_codes_code_unique ON pairing_codes(code);

-- Add index to speed up lookups by user_id and device_id
CREATE INDEX IF NOT EXISTS idx_pairing_codes_user_device ON pairing_codes(user_id, device_id);

-- DOWN
-- DROP INDEX IF EXISTS idx_pairing_codes_user_device;
-- DROP INDEX IF EXISTS idx_pairing_codes_code_unique;
