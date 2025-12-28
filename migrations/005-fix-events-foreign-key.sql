-- Migration: Fix events table foreign key to reference user_devices
-- Version: 5
-- Description: Updates events.device_id foreign key to reference user_devices instead of devices

-- UP

-- Step 1: Drop the old foreign key constraint
ALTER TABLE events DROP CONSTRAINT IF EXISTS events_device_id_fkey;

-- Step 2: Clean up orphaned events (events with device_ids that don't exist in user_devices)
-- First, delete events that reference device_ids not in user_devices
-- This handles the case where devices were deleted or migrated
DELETE FROM events 
WHERE device_id IS NOT NULL 
AND device_id::text NOT IN (
  SELECT device_id::text FROM user_devices
);

-- Step 3: Also clean up events with invalid UUID format
DELETE FROM events 
WHERE device_id IS NOT NULL 
AND device_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

-- Step 4: Change device_id column type from TEXT to UUID
-- This will only work if all remaining device_ids are valid UUIDs
ALTER TABLE events 
ALTER COLUMN device_id TYPE UUID USING device_id::uuid;

-- Step 5: Add new foreign key constraint to user_devices
ALTER TABLE events 
ADD CONSTRAINT events_device_id_fkey 
FOREIGN KEY (device_id) 
REFERENCES user_devices(device_id) 
ON DELETE CASCADE;

-- DOWN
-- Note: Rollback is complex due to type conversion, so we'll just drop the constraint
-- ALTER TABLE events DROP CONSTRAINT IF EXISTS events_device_id_fkey;
-- ALTER TABLE events ALTER COLUMN device_id TYPE TEXT;
-- ALTER TABLE events ADD CONSTRAINT events_device_id_fkey FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE;

