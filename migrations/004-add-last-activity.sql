-- Migration: Ensure last_activity column exists
-- Version: 4
-- Description: Adds last_activity column to users table if it doesn't exist

-- UP
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_activity TIMESTAMP DEFAULT NOW();

-- Update existing rows to have last_activity set to created_at or NOW()
UPDATE users SET last_activity = COALESCE(created_at, NOW()) WHERE last_activity IS NULL;

-- DOWN
-- Note: We don't drop the column in rollback to preserve data
-- ALTER TABLE users DROP COLUMN IF EXISTS last_activity;

