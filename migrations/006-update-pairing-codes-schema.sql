-- UP
-- Add missing columns to pairing_codes table
ALTER TABLE pairing_codes ADD COLUMN IF NOT EXISTS ws_url TEXT;
ALTER TABLE pairing_codes ADD COLUMN IF NOT EXISTS device_name TEXT;
ALTER TABLE pairing_codes ADD COLUMN IF NOT EXISTS public_key_hex TEXT;
ALTER TABLE pairing_codes ADD COLUMN IF NOT EXISTS private_key_hex TEXT;

-- Make ws_url NOT NULL (after adding it, set default for existing rows)
UPDATE pairing_codes SET ws_url = 'ws://localhost:3001/ws' WHERE ws_url IS NULL;
ALTER TABLE pairing_codes ALTER COLUMN ws_url SET NOT NULL;

-- Make device_id NOT NULL (set default for existing rows)
UPDATE pairing_codes SET device_id = gen_random_uuid()::text WHERE device_id IS NULL;
ALTER TABLE pairing_codes ALTER COLUMN device_id SET NOT NULL;

-- Make public_key_hex NOT NULL (set default for existing rows - these will be invalid but prevents constraint errors)
UPDATE pairing_codes SET public_key_hex = repeat('0', 64) WHERE public_key_hex IS NULL;
ALTER TABLE pairing_codes ALTER COLUMN public_key_hex SET NOT NULL;

-- Make private_key_hex NOT NULL (set default for existing rows - these will be invalid but prevents constraint errors)
UPDATE pairing_codes SET private_key_hex = repeat('0', 64) WHERE private_key_hex IS NULL;
ALTER TABLE pairing_codes ALTER COLUMN private_key_hex SET NOT NULL;

-- DOWN
-- Note: This migration adds columns, so rollback would remove them
-- In production, you may want to keep data, so this is commented out
-- ALTER TABLE pairing_codes DROP COLUMN IF EXISTS private_key_hex;
-- ALTER TABLE pairing_codes DROP COLUMN IF EXISTS public_key_hex;
-- ALTER TABLE pairing_codes DROP COLUMN IF EXISTS device_name;
-- ALTER TABLE pairing_codes DROP COLUMN IF EXISTS ws_url;
-- ALTER TABLE pairing_codes ALTER COLUMN device_id DROP NOT NULL;

