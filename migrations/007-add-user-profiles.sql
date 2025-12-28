-- Migration: Add user profiles table
-- Version: 7
-- Description: Stores user profile data server-side with validation

-- UP

-- User profiles table (stores user display name, preferences, etc.)
CREATE TABLE IF NOT EXISTS user_profiles (
  user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
  display_name TEXT,
  email TEXT,
  avatar_url TEXT,
  preferences JSONB DEFAULT '{}'::jsonb,
  onboarding_completed BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
  
  -- Constraints
  CONSTRAINT valid_display_name CHECK (display_name IS NULL OR (length(display_name) >= 1 AND length(display_name) <= 100)),
  CONSTRAINT valid_email CHECK (email IS NULL OR email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$')
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_profiles_last_seen ON user_profiles(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_user_profiles_onboarding ON user_profiles(onboarding_completed) WHERE onboarding_completed = TRUE;

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_user_profiles_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER user_profiles_updated_at
  BEFORE UPDATE ON user_profiles
  FOR EACH ROW
  EXECUTE FUNCTION update_user_profiles_updated_at();

-- DOWN
-- DROP TRIGGER IF EXISTS user_profiles_updated_at ON user_profiles;
-- DROP FUNCTION IF EXISTS update_user_profiles_updated_at();
-- DROP INDEX IF EXISTS idx_user_profiles_onboarding;
-- DROP INDEX IF EXISTS idx_user_profiles_last_seen;
-- DROP TABLE IF EXISTS user_profiles;

