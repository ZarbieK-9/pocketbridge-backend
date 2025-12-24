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
 * Validate required environment variables
 */
function validateConfig(): void {
  // If DATABASE_URL is not set, require individual PostgreSQL vars
  if (!process.env.DATABASE_URL) {
    const required = [
      'POSTGRES_HOST',
      'POSTGRES_DB',
      'POSTGRES_USER',
      'POSTGRES_PASSWORD',
    ];

    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0 && process.env.NODE_ENV === 'production') {
      throw new Error(`Missing required environment variables: ${missing.join(', ')} (or set DATABASE_URL)`);
    }
  }

  // If REDIS_URL is not set, require REDIS_HOST
  if (!process.env.REDIS_URL && !process.env.REDIS_HOST && process.env.NODE_ENV === 'production') {
    throw new Error('Missing required environment variable: REDIS_HOST (or set REDIS_URL)');
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
  postgres: dbUrlConfig ? {
    ...dbUrlConfig,
    maxConnections: parseInt(process.env.POSTGRES_MAX_CONNECTIONS || '20', 10),
    connectionTimeout: parseInt(process.env.POSTGRES_CONNECTION_TIMEOUT || '10000', 10), // Increased to 10s for Railway
  } : {
    host: process.env.POSTGRES_HOST || 'localhost',
    port: parseInt(process.env.POSTGRES_PORT || '5432', 10),
    database: process.env.POSTGRES_DB || 'pocketbridge',
    user: process.env.POSTGRES_USER || 'postgres',
    password: process.env.POSTGRES_PASSWORD || 'postgres',
    maxConnections: parseInt(process.env.POSTGRES_MAX_CONNECTIONS || '20', 10),
    connectionTimeout: parseInt(process.env.POSTGRES_CONNECTION_TIMEOUT || '10000', 10), // Increased to 10s for Railway
  },

  // Redis (use REDIS_URL if provided, otherwise use individual vars)
  redis: redisUrlConfig ? {
    ...redisUrlConfig,
    retryDelayOnFailover: parseInt(process.env.REDIS_RETRY_DELAY || '100', 10),
    maxRetriesPerRequest: parseInt(process.env.REDIS_MAX_RETRIES || '3', 10),
  } : {
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
