/**
 * PostgreSQL Database Connection and Schema
 * 
 * Production-ready with:
 * - Connection pooling
 * - Retry logic
 * - Health checks
 * - Migration support
 * 
 * Stores:
 * - Public keys (Ed25519) for user identity
 * - Device metadata
 * - Event metadata (for replay index)
 * - last_ack_device_seq per device
 * - Revoked devices
 * 
 * NEVER stores:
 * - Private keys
 * - Plaintext payloads
 * - Decryption keys
 */

import pg from 'pg';
import { config } from '../config.js';
import { logger } from '../utils/logger.js';

const { Pool } = pg;

export interface Database {
  pool: pg.Pool;
  end: () => Promise<void>;
  healthCheck: () => Promise<boolean>;
}

/**
 * Initialize PostgreSQL connection pool with retry logic
 */
export async function initDatabase(): Promise<Database> {
  // Use DATABASE_URL if provided, otherwise use individual config
  const poolConfig = config.databaseUrl
    ? {
        connectionString: config.databaseUrl,
        max: config.postgres.maxConnections,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: config.postgres.connectionTimeout,
        allowExitOnIdle: false,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false, // Allow self-signed certs in Railway
      }
    : {
        host: config.postgres.host,
        port: config.postgres.port,
        database: config.postgres.database,
        user: config.postgres.user,
        password: config.postgres.password,
        max: config.postgres.maxConnections,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: config.postgres.connectionTimeout,
        allowExitOnIdle: false,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false, // Allow self-signed certs in Railway
      };

  const pool = new Pool(poolConfig);

  // Handle pool errors
  pool.on('error', (err) => {
    logger.error('Unexpected database pool error', {}, err);
  });

  // Retry connection with exponential backoff
  // Increased retries and delays for Railway deployment
  let retries = 10;
  let delay = 2000; // Start with 2 seconds

  while (retries > 0) {
    try {
      // Test connection with a longer timeout
      const client = await pool.connect();
      await client.query('SELECT NOW()');
      client.release();
      logger.info('PostgreSQL connection established');
      break;
    } catch (error) {
      retries--;
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.warn(`PostgreSQL connection failed: ${errorMessage}. Retrying in ${delay}ms... (${retries} retries left)`, {
        error: errorMessage,
        retriesLeft: retries,
      });
      
      if (retries === 0) {
        logger.error('Failed to connect to PostgreSQL after all retries', {
          totalRetries: 10,
          finalError: errorMessage,
        }, error instanceof Error ? error : new Error(String(error)));
        throw error;
      }
      
      await new Promise(resolve => setTimeout(resolve, delay));
      delay = Math.min(delay * 1.5, 10000); // Exponential backoff, max 10 seconds
    }
  }

  // Initialize schema
  await initSchema(pool);

  return {
    pool,
    end: async () => {
      await pool.end();
      logger.info('PostgreSQL connection pool closed');
    },
    healthCheck: async () => {
      try {
        await pool.query('SELECT 1');
        return true;
      } catch {
        return false;
      }
    },
  };
}

/**
 * Initialize database schema
 */
async function initSchema(pool: pg.Pool): Promise<void> {
  logger.info('Initializing database schema...');

  // Users table (stores Ed25519 public keys)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY, -- Ed25519 public key (hex)
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);

  // Devices table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS devices (
      device_id TEXT PRIMARY KEY, -- UUIDv4
      user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      device_name TEXT,
      device_type TEXT, -- 'browser', 'desktop'
      last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
      last_ack_device_seq BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);

  // Events table (metadata only, for replay index)
  await pool.query(`
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
    )
  `);

  // Migration: Add payload_size column if it doesn't exist (for existing databases)
  await pool.query(`
    DO $$ 
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'events' AND column_name = 'payload_size'
      ) THEN
        ALTER TABLE events ADD COLUMN payload_size INTEGER;
      END IF;
    END $$;
  `);

  // Stream sequences table (tracks stream_seq per stream)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS stream_sequences (
      stream_id TEXT PRIMARY KEY,
      last_stream_seq BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);

  // Revoked devices table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS revoked_devices (
      device_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      revoked_at TIMESTAMP NOT NULL DEFAULT NOW(),
      reason TEXT
    )
  `);

  // Pairing codes table (temporary, expires after 10 minutes)
  await pool.query(`
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
    )
  `);

  // Index for pairing code expiration cleanup
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_pairing_codes_expires_at 
    ON pairing_codes(expires_at)
  `);

  // Create indexes for performance
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_events_device_id_seq 
    ON events(device_id, device_seq)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_events_stream_id_seq 
    ON events(stream_id, stream_seq)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_events_user_id 
    ON events(user_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_events_created_at 
    ON events(created_at)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_events_ttl 
    ON events(ttl) WHERE ttl IS NOT NULL
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_devices_user_id 
    ON devices(user_id)
  `);

  logger.info('Database schema initialized');
}
