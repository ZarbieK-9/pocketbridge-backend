-- Migration: Add device name uniqueness and device type validation
-- Created: 2024
-- Description: Enforces unique device names per user and validates device_type enum

-- Add unique constraint for device names per user
-- This ensures a user cannot have multiple devices with the same name
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_devices_user_name 
ON user_devices(user_id, device_name) 
WHERE device_name IS NOT NULL;

-- Add CHECK constraint for device_type validation
-- Only allows valid device types: 'mobile', 'desktop', 'web', or NULL
ALTER TABLE user_devices 
DROP CONSTRAINT IF EXISTS valid_device_type;

ALTER TABLE user_devices 
ADD CONSTRAINT valid_device_type 
CHECK (device_type IS NULL OR device_type IN ('mobile', 'desktop', 'web'));

