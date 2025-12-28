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
import { databaseCircuitBreaker } from '../services/circuit-breaker.js';
import { incrementCounter, recordHistogram, setGauge } from '../services/metrics.js';

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
  pool.on('error', err => {
    logger.error('Unexpected database pool error', {}, err);
    incrementCounter('database_pool_errors_total');
  });

  // Monitor pool health metrics every 5 seconds
  const poolMonitoringInterval = setInterval(() => {
    try {
      // Track pool metrics
      setGauge('database_pool_total', pool.totalCount);
      setGauge('database_pool_idle', pool.idleCount);
      setGauge('database_pool_active', pool.totalCount - pool.idleCount);
      setGauge('database_pool_waiting', pool.waitingCount);

      // Log warning if pool is getting exhausted
      const poolUtilization = (pool.totalCount - pool.idleCount) / pool.totalCount;
      if (poolUtilization > 0.8) {
        logger.warn('Database pool utilization high', {
          total: pool.totalCount,
          active: pool.totalCount - pool.idleCount,
          idle: pool.idleCount,
          waiting: pool.waitingCount,
          utilization: `${(poolUtilization * 100).toFixed(1)}%`,
        });
      }

      // Alert if there are waiting connections
      if (pool.waitingCount > 0) {
        logger.warn('Database pool has waiting connections', {
          waiting: pool.waitingCount,
          total: pool.totalCount,
          active: pool.totalCount - pool.idleCount,
          idle: pool.idleCount,
        });
        incrementCounter('database_pool_waiting_connections_total');
      }
    } catch (error) {
      logger.error(
        'Failed to monitor database pool',
        {},
        error instanceof Error ? error : new Error(String(error))
      );
    }
  }, 5000);

  // Store interval ID for cleanup (will be used in end function)
  (pool as any)._monitoringInterval = poolMonitoringInterval;

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
      logger.warn(
        `PostgreSQL connection failed: ${errorMessage}. Retrying in ${delay}ms... (${retries} retries left)`,
        {
          error: errorMessage,
          retriesLeft: retries,
        }
      );

      if (retries === 0) {
        logger.error(
          'Failed to connect to PostgreSQL after all retries',
          {
            totalRetries: 10,
            finalError: errorMessage,
          },
          error instanceof Error ? error : new Error(String(error))
        );
        throw error;
      }

      await new Promise(resolve => setTimeout(resolve, delay));
      delay = Math.min(delay * 1.5, 10000); // Exponential backoff, max 10 seconds
    }
  }

  // Initialize schema
  await initSchema(pool);

  // Wrap pool.query to add slow query logging
  const SLOW_QUERY_THRESHOLD_MS = 1000; // Log queries taking > 1 second
  const originalQuery = pool.query.bind(pool);

  (pool as any).query = function (text: any, params?: any, callback?: any): any {
    const startTime = Date.now();
    const queryText = typeof text === 'string' ? text : text?.text || text?.query || 'unknown';

    // If callback is provided, use callback-based API
    if (callback && typeof callback === 'function') {
      return originalQuery(text, params, (err: any, res: any) => {
        const duration = Date.now() - startTime;
        logQueryMetrics(queryText, duration, params);
        callback(err, res);
      });
    }

    // Otherwise, use promise-based API
    const result = originalQuery(text, params);

    if (result && typeof result.then === 'function') {
      return result.then(
        (res: any) => {
          const duration = Date.now() - startTime;
          logQueryMetrics(queryText, duration, params);
          return res;
        },
        (err: any) => {
          const duration = Date.now() - startTime;
          recordHistogram('database_query_duration_ms', duration, {
            operation: extractOperation(queryText),
            status: 'error',
          });
          incrementCounter('database_queries_total', {
            operation: extractOperation(queryText),
            status: 'error',
          });
          throw err;
        }
      );
    }

    return result;
  };

  /**
   * Log query metrics and slow query warnings
   */
  function logQueryMetrics(queryText: string, duration: number, params?: any): void {
    const operation = extractOperation(queryText);

    // Record query duration
    recordHistogram('database_query_duration_ms', duration, { operation });
    incrementCounter('database_queries_total', { operation, status: 'success' });

    // Log slow queries
    if (duration > SLOW_QUERY_THRESHOLD_MS) {
      logger.warn('Slow database query detected', {
        duration: `${duration}ms`,
        query: queryText.substring(0, 200), // Truncate long queries
        params: params ? (Array.isArray(params) ? `[${params.length} params]` : 'object') : 'none',
        operation,
      });
      incrementCounter('database_slow_queries_total', { operation });
    }
  }

  return {
    pool,
    end: async () => {
      // Clear pool monitoring interval
      if ((pool as any)._monitoringInterval) {
        clearInterval((pool as any)._monitoringInterval);
      }
      await pool.end();
      logger.info('PostgreSQL connection pool closed');
    },
    healthCheck: async () => {
      try {
        const startTime = Date.now();
        await databaseCircuitBreaker.execute(async () => {
          await pool.query('SELECT 1');
        }, 'database');
        const duration = Date.now() - startTime;
        recordHistogram('database_query_duration_ms', duration, { operation: 'health_check' });
        incrementCounter('database_queries_total', {
          operation: 'health_check',
          status: 'success',
        });
        return true;
      } catch (error) {
        incrementCounter('database_queries_total', { operation: 'health_check', status: 'error' });
        logger.error(
          'Database health check failed',
          {},
          error instanceof Error ? error : new Error(String(error))
        );
        return false;
      }
    },
  };
}

/**
 * Extract operation name from SQL query for metrics
 */
function extractOperation(queryText: string): string {
  const upperQuery = queryText.trim().toUpperCase();
  if (upperQuery.startsWith('SELECT')) return 'select';
  if (upperQuery.startsWith('INSERT')) return 'insert';
  if (upperQuery.startsWith('UPDATE')) return 'update';
  if (upperQuery.startsWith('DELETE')) return 'delete';
  if (
    upperQuery.startsWith('BEGIN') ||
    upperQuery.startsWith('COMMIT') ||
    upperQuery.startsWith('ROLLBACK')
  )
    return 'transaction';
  return 'other';
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
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      last_activity TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);

  // New multi-device table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_devices (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      device_id UUID NOT NULL UNIQUE, -- UUIDv4 from client
      device_name TEXT,
      device_type TEXT, -- 'mobile', 'desktop', 'web'
      device_os TEXT,
      is_online BOOLEAN NOT NULL DEFAULT FALSE,
      last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
      ip_address INET,
      user_agent TEXT,
      public_key_hex TEXT,
      registered_at TIMESTAMP NOT NULL DEFAULT NOW(),
      last_ack_device_seq BIGINT NOT NULL DEFAULT 0,
      CONSTRAINT valid_device_name CHECK (length(device_name) <= 50),
      CONSTRAINT valid_device_type CHECK (device_type IS NULL OR device_type IN ('mobile', 'desktop', 'web'))
    )
  `);

  // Add unique index for device names per user (if not exists)
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_user_devices_user_name 
    ON user_devices(user_id, device_name) 
    WHERE device_name IS NOT NULL
  `);

  // Backward-compatible legacy devices table (kept for older data)
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

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_user_devices_user_id 
    ON user_devices(user_id)
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_user_devices_last_seen 
    ON user_devices(last_seen DESC)
  `);

  logger.info('Database schema initialized');
}
