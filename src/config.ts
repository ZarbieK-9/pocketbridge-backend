/**
 * Configuration with environment validation
 *
 * In production, all values should come from environment variables.
 */

interface Config {
  port: number;
  nodeEnv: string;
  databaseUrl?: string;
  redisUrl?: string;
  postgres: {
    host: string;
    port: number;
    database: string;
    user: string;
    password: string;
    maxConnections: number;
    connectionTimeout: number;
  };
  redis: {
    host: string;
    port: number;
    password?: string;
    retryDelayOnFailover: number;
    maxRetriesPerRequest: number;
  };
  websocket: {
    sessionTimeout: number;
    replayWindowDays: number;
    maxConnectionsPerIP: number;
  };
  serverIdentity: {
    publicKey: string;
    privateKey: string;
    publicKeyHex: string;
    privateKeyHex?: string;
  };
  cors: {
    origin: string | string[];
    credentials: boolean;
  };
  rateLimit: {
    windowMs: number;
    maxRequests: number;
  };
}

/**
 * Parse DATABASE_URL into connection parameters
 */
function parseDatabaseUrl(url?: string): {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
} | null {
  if (!url) return null;

  try {
    const parsed = new URL(url);
    return {
      host: parsed.hostname,
      port: parseInt(parsed.port || '5432', 10),
      database: parsed.pathname.slice(1), // Remove leading '/'
      user: parsed.username,
      password: parsed.password,
    };
  } catch {
    return null;
  }
}

/**
 * Parse REDIS_URL into connection parameters
 */
function parseRedisUrl(url?: string): {
  host: string;
  port: number;
  password?: string;
} | null {
  if (!url) return null;

  try {
    const parsed = new URL(url);
    return {
      host: parsed.hostname,
      port: parseInt(parsed.port || '6379', 10),
      password: parsed.password || undefined,
    };
  } catch {
    return null;
  }
}

/**
 * Validate Ed25519 public key format (64 hex characters)
 */
function validateEd25519PublicKey(key: string): boolean {
  return /^[0-9a-f]{64}$/i.test(key);
}

/**
 * Validate Ed25519 private key format (64 hex characters or PEM)
 */
function validateEd25519PrivateKey(key: string): boolean {
  // Hex format (64 chars) or PEM format
  return (
    /^[0-9a-f]{64}$/i.test(key) ||
    key.includes('BEGIN PRIVATE KEY') ||
    key.includes('BEGIN PRIVATE KEY')
  );
}

/**
 * Validate port number (1-65535)
 */
function validatePort(port: number): boolean {
  return Number.isInteger(port) && port > 0 && port <= 65535;
}

/**
 * Validate URL format
 */
function validateUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate required environment variables and their formats
 */
function validateConfig(): void {
  const errors: string[] = [];
  const isProduction = process.env.NODE_ENV === 'production';

  // Database validation
  if (!process.env.DATABASE_URL) {
    const required = ['POSTGRES_HOST', 'POSTGRES_DB', 'POSTGRES_USER', 'POSTGRES_PASSWORD'];

    const missing = required.filter(key => !process.env[key]);

    if (missing.length > 0 && isProduction) {
      errors.push(
        `Missing required environment variables: ${missing.join(', ')} (or set DATABASE_URL)`
      );
    }
  }

  // Redis validation
  if (!process.env.REDIS_URL && !process.env.REDIS_HOST && isProduction) {
    errors.push('Missing required environment variable: REDIS_HOST (or set REDIS_URL)');
  }

  // Port validation
  const port = parseInt(process.env.PORT || '3001', 10);
  if (!validatePort(port)) {
    errors.push(`Invalid PORT: ${port} (must be 1-65535)`);
  }

  // Server identity keys validation
  const publicKey = process.env.SERVER_PUBLIC_KEY_HEX || process.env.SERVER_PUBLIC_KEY || '';
  const privateKey = process.env.SERVER_PRIVATE_KEY_HEX || process.env.SERVER_PRIVATE_KEY || '';

  if (isProduction) {
    if (!publicKey || !privateKey) {
      errors.push(
        'Missing required server identity keys: SERVER_PUBLIC_KEY_HEX and SERVER_PRIVATE_KEY_HEX'
      );
    } else {
      // Validate key formats (allow both hex and PEM for private key)
      if (!validateEd25519PublicKey(publicKey)) {
        errors.push('Invalid SERVER_PUBLIC_KEY_HEX format (must be 64 hex characters)');
      }
      if (!validateEd25519PrivateKey(privateKey)) {
        errors.push('Invalid SERVER_PRIVATE_KEY_HEX format (must be 64 hex characters or PEM)');
      }
    }
  }

  // CORS origin validation
  if (process.env.CORS_ORIGIN) {
    const origins = process.env.CORS_ORIGIN.split(',').map(o => o.trim());
    for (const origin of origins) {
      if (origin !== '*' && !validateUrl(origin)) {
        errors.push(`Invalid CORS_ORIGIN: ${origin} (must be a valid URL or *)`);
      }
    }
  } else if (isProduction) {
    errors.push('CORS_ORIGIN must be set in production');
  }

  // Numeric range validations
  const maxConnections = parseInt(process.env.POSTGRES_MAX_CONNECTIONS || '20', 10);
  if (maxConnections < 1 || maxConnections > 100) {
    errors.push(`POSTGRES_MAX_CONNECTIONS must be between 1 and 100, got ${maxConnections}`);
  }

  const connectionTimeout = parseInt(process.env.POSTGRES_CONNECTION_TIMEOUT || '10000', 10);
  if (connectionTimeout < 1000 || connectionTimeout > 60000) {
    errors.push(
      `POSTGRES_CONNECTION_TIMEOUT must be between 1000 and 60000ms, got ${connectionTimeout}`
    );
  }

  const rateLimitWindow = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
  if (rateLimitWindow < 1000 || rateLimitWindow > 3600000) {
    errors.push(`RATE_LIMIT_WINDOW_MS must be between 1000 and 3600000ms, got ${rateLimitWindow}`);
  }

  const rateLimitMax = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10);
  if (rateLimitMax < 1 || rateLimitMax > 10000) {
    errors.push(`RATE_LIMIT_MAX_REQUESTS must be between 1 and 10000, got ${rateLimitMax}`);
  }

  // Throw if any errors
  if (errors.length > 0) {
    throw new Error(`Configuration validation failed:\n${errors.join('\n')}`);
  }
}

validateConfig();

// Parse connection URLs if provided
const dbUrlConfig = parseDatabaseUrl(process.env.DATABASE_URL);
const redisUrlConfig = parseRedisUrl(process.env.REDIS_URL);

export const config: Config = {
  port: parseInt(process.env.PORT || '3001', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  databaseUrl: process.env.DATABASE_URL,
  redisUrl: process.env.REDIS_URL,

  // PostgreSQL (use DATABASE_URL if provided, otherwise use individual vars)
  postgres: dbUrlConfig
    ? {
        ...dbUrlConfig,
        maxConnections: parseInt(process.env.POSTGRES_MAX_CONNECTIONS || '20', 10),
        connectionTimeout: parseInt(process.env.POSTGRES_CONNECTION_TIMEOUT || '10000', 10), // Increased to 10s for Railway
      }
    : {
        host: process.env.POSTGRES_HOST || 'localhost',
        port: parseInt(process.env.POSTGRES_PORT || '5432', 10),
        database: process.env.POSTGRES_DB || 'pocketbridge',
        user: process.env.POSTGRES_USER || 'postgres',
        password: process.env.POSTGRES_PASSWORD || 'postgres',
        maxConnections: parseInt(process.env.POSTGRES_MAX_CONNECTIONS || '20', 10),
        connectionTimeout: parseInt(process.env.POSTGRES_CONNECTION_TIMEOUT || '10000', 10), // Increased to 10s for Railway
      },

  // Redis (use REDIS_URL if provided, otherwise use individual vars)
  redis: redisUrlConfig
    ? {
        ...redisUrlConfig,
        retryDelayOnFailover: parseInt(process.env.REDIS_RETRY_DELAY || '100', 10),
        maxRetriesPerRequest: parseInt(process.env.REDIS_MAX_RETRIES || '3', 10),
      }
    : {
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT || '6379', 10),
        password: process.env.REDIS_PASSWORD || undefined,
        retryDelayOnFailover: parseInt(process.env.REDIS_RETRY_DELAY || '100', 10),
        maxRetriesPerRequest: parseInt(process.env.REDIS_MAX_RETRIES || '3', 10),
      },

  // WebSocket
  websocket: {
    sessionTimeout: parseInt(process.env.WS_SESSION_TIMEOUT || String(24 * 60 * 60 * 1000), 10),
    replayWindowDays: parseInt(process.env.WS_REPLAY_WINDOW_DAYS || '30', 10),
    maxConnectionsPerIP: parseInt(process.env.WS_MAX_CONNECTIONS_PER_IP || '10', 10),
  },

  // Server identity (Ed25519 keypair) - using hex format
  serverIdentity: {
    publicKey: process.env.SERVER_PUBLIC_KEY_HEX || process.env.SERVER_PUBLIC_KEY || '',
    privateKey: process.env.SERVER_PRIVATE_KEY_HEX || process.env.SERVER_PRIVATE_KEY || '',
    publicKeyHex: process.env.SERVER_PUBLIC_KEY_HEX || process.env.SERVER_PUBLIC_KEY || '',
    privateKeyHex: process.env.SERVER_PRIVATE_KEY_HEX || process.env.SERVER_PRIVATE_KEY || '',
  },

  // CORS
  cors: {
    origin: process.env.CORS_ORIGIN
      ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
      : process.env.NODE_ENV === 'production'
        ? [] // Must be set in production
        : '*', // Allow all in development
    credentials: process.env.CORS_CREDENTIALS === 'true',
  },

  // Rate limiting
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
  },
};
