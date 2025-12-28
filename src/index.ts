/**
 * PocketBridge Backend - Main Entry Point
 *
 * ALWAYS ACTIVE RELAY SYSTEM
 * ==========================
 * This backend is always running and acts as a relay system that connects devices.
 *
 * Core Functionality:
 * - Always active: Server runs continuously, ready to connect devices
 * - Device Relay: Automatically routes messages between devices of the same user
 * - Multi-User Support: Handles multiple users simultaneously
 * - User Isolation: Each user can only see and communicate with their own devices
 *
 * How It Works:
 * 1. Device A connects → identifies with user_id
 * 2. Device B connects → identifies with same user_id
 * 3. Backend automatically relays messages between Device A and Device B
 * 4. Users are completely isolated - User 1's devices never see User 2's devices
 *
 * Technical Stack:
 * - WebSocket gateway for real-time communication
 * - PostgreSQL for metadata and replay index
 * - Redis for Pub/Sub and presence
 * - End-to-end encryption (server never decrypts)
 * - Production-ready error handling, logging, and monitoring
 */

// Load environment variables from .env file
import 'dotenv/config';

import express from 'express';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import { initDatabase } from './db/postgres.js';
import { initRedis } from './db/redis.js';
import { createWebSocketGateway } from './gateway/websocket.js';
import { config } from './config.js';
import { logger } from './utils/logger.js';
import { errorHandler } from './utils/errors.js';
import { requestLogger } from './middleware/request-logger.js';
import { requestIdMiddleware } from './middleware/request-id.js';
import { apiVersionMiddleware } from './middleware/api-version.js';
import { generateServerIdentityKeypair } from './crypto/utils.js';
import { securityHeaders } from './middleware/security-headers.js';
import { startTTLCleanupJob } from './jobs/ttl-cleanup.js';
import { getMetrics } from './routes/metrics.js';
import adminRouter, { setDatabase } from './routes/admin.js';
import pairingRouter, { setDatabase as setPairingDatabase } from './routes/pairing.js';
import statusRouter, {
  setSessionsMap as setStatusSessionsMap,
  setDatabase as setStatusDatabase,
} from './routes/status.js';
import devicesRouter, {
  setDatabase as setDevicesDatabase,
  setSessionsMap as setDevicesSessionsMap,
} from './routes/devices.js';
import authRouter, { setDatabase as setAuthDatabase } from './routes/auth.js';
import userRouter, {
  setDatabase as setUserDatabase,
  setSessionsMap as setUserSessionsMap,
} from './routes/user.js';

const app = express();

// Trust proxy (for rate limiting behind reverse proxy)
app.set('trust proxy', 1);

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy: false, // WebSocket needs this disabled
    crossOriginEmbedderPolicy: false,
  })
);

// CORS - Must be before other middleware
// Build dynamic CORS options with whitelist + sensible defaults
const allowedOrigins = Array.isArray(config.cors.origin)
  ? (config.cors.origin as string[])
  : [config.cors.origin as string];
// Normalize to avoid trailing-slash mismatches
const normalizedAllowedOrigins = allowedOrigins.filter(Boolean).map(o => o.replace(/\/+$/, ''));

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    // Allow non-browser or same-origin requests
    if (!origin) return callback(null, true);
    // If no whitelist configured, allow all origins (recommended to set CORS_ORIGIN in production)
    if (allowedOrigins.length === 0) return callback(null, true);
    // If wildcard configured, allow all origins (credentials should be false when using '*')
    if (allowedOrigins.includes('*')) return callback(null, true);
    // Exact match against whitelist
    if (normalizedAllowedOrigins.includes((origin || '').replace(/\/+$/, '')))
      return callback(null, true);
    // Attempt relaxed host-only matching (handles trailing slashes/protocol differences)
    try {
      const o = new URL(origin);
      const originHost = `${o.protocol}//${o.host}`;
      if (normalizedAllowedOrigins.includes(originHost)) return callback(null, true);
    } catch {}
    // Don't error; respond without CORS headers so browser blocks without 500
    callback(null, false);
  },
  credentials: config.cors.credentials,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  // Include custom headers used by frontend
  allowedHeaders: ['Content-Type', 'Authorization', 'X-User-ID', 'X-Requested-With'],
  optionsSuccessStatus: 200,
  preflightContinue: false,
};

logger.info('CORS configuration', {
  origin: Array.isArray(corsOptions.origin) ? corsOptions.origin : corsOptions.origin,
  credentials: corsOptions.credentials,
});

app.use(cors(corsOptions));

// Handle CORS preflight for all routes
app.options('*', cors(corsOptions));

// Compression
app.use(compression());

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request ID middleware (must be before request logger)
app.use(requestIdMiddleware);

// API versioning middleware
app.use(apiVersionMiddleware);

// Request logging
app.use(requestLogger);

// Rate limiting - ENABLED for production
// Skip rate limiting in test environment
const shouldEnableRateLimit = config.nodeEnv !== 'test';
if (shouldEnableRateLimit) {
  const limiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.maxRequests,
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
    skip: req => {
      // Skip rate limiting for health checks and metrics
      return req.path === '/health' || req.path === '/metrics';
    },
  });
  app.use('/api', limiter);
  logger.info('Rate limiting enabled', {
    windowMs: config.rateLimit.windowMs,
    maxRequests: config.rateLimit.maxRequests,
  });
} else {
  logger.info('Rate limiting disabled (test environment)');
}

// Security headers
app.use(securityHeaders);

// REST API authentication middleware (JWT with X-User-ID fallback)
import { jwtAuthMiddleware } from './middleware/jwt-auth.js';
app.use('/api', jwtAuthMiddleware);

// Health check endpoint (no rate limiting, no auth)
// This endpoint is used by load balancers and monitoring systems
app.get('/health', async (req, res) => {
  try {
    const dbHealthy = db ? await db.healthCheck() : false;
    const redisHealthy = redis ? await redis.healthCheck() : false;

    const status = dbHealthy && redisHealthy ? 'ok' : 'degraded';
    const statusCode = status === 'ok' ? 200 : 503;

    // Add retry-after header if degraded
    if (status === 'degraded') {
      res.setHeader('Retry-After', '30');
    }

    res.status(statusCode).json({
      status,
      timestamp: Date.now(),
      uptime: process.uptime(),
      services: {
        database: dbHealthy ? 'connected' : 'disconnected',
        redis: redisHealthy ? 'connected' : 'disconnected',
      },
      version: process.env.npm_package_version || '1.0.0',
    });
  } catch (error) {
    logger.error(
      'Health check failed',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(503).json({
      status: 'error',
      timestamp: Date.now(),
      error: 'Health check failed',
    });
  }
});

// Metrics endpoint
app.get('/metrics', getMetrics);

// Admin routes (protected with authentication)
app.use('/admin', adminRouter);

// API routes with versioning
// Version can be specified in path (/api/v1/...) or header (X-API-Version: v1)
// Import user profile router
import userProfileRouter from './routes/user-profile.js';

app.use('/api/v1/auth', authRouter);
app.use('/api/v1/pairing', pairingRouter);
app.use('/api/v1', statusRouter);
app.use('/api/v1', devicesRouter);
app.use('/api/v1', userRouter);
app.use('/api/v1', userProfileRouter);

// Backward compatibility: also support /api/... (defaults to v1)
app.use('/api/auth', authRouter);
app.use('/api/pairing', pairingRouter);
app.use('/api', statusRouter);
app.use('/api', devicesRouter);
app.use('/api', userRouter);
app.use('/api', userProfileRouter);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    code: 'NOT_FOUND',
    path: req.path,
  });
});

// Error handler (must be last)
app.use(errorHandler);

const server = createServer(app);

// WebSocket server
const wss = new WebSocketServer({
  server,
  path: '/ws',
  perMessageDeflate: false, // Disable compression (security: CRIME attack)
  clientTracking: true,
});

// Initialize services
let db: Awaited<ReturnType<typeof initDatabase>> | null = null;
let redis: Awaited<ReturnType<typeof initRedis>> | null = null;
let isShuttingDown = false;

async function start() {
  try {
    logger.info('Starting PocketBridge backend...', {
      nodeEnv: config.nodeEnv,
      port: config.port,
    });

    // Validate or generate server identity keys
    // Extract serverIdentity to avoid type inference issues
    const serverIdentity = config.serverIdentity;
    if (!serverIdentity.publicKeyHex || !serverIdentity.privateKey) {
      logger.warn('Server identity keys missing! Generating new keys...');
      const newKeys = await generateServerIdentityKeypair();
      // Update config with new keys
      config.serverIdentity = {
        publicKey: newKeys.publicKey,
        privateKey: newKeys.privateKey,
        publicKeyHex: newKeys.publicKeyHex,
        privateKeyHex: newKeys.privateKeyHex,
      };
      logger.warn('⚠️  Generated new server identity. Save these keys securely!');
      logger.warn(`Public Key (hex): ${newKeys.publicKeyHex}`);
      logger.warn(`Private Key (hex): ${newKeys.privateKeyHex}`);
      logger.warn(
        'Set SERVER_PUBLIC_KEY_HEX and SERVER_PRIVATE_KEY_HEX environment variables in production!'
      );
    } else {
      // Convert PEM keys to hex if needed, or use hex directly
      if (serverIdentity.publicKey && !serverIdentity.publicKeyHex) {
        // If we have PEM but not hex, we need to convert (for backward compatibility)
        // For now, assume hex is set
        logger.info('Server identity keys loaded (using hex format)');
      } else {
        logger.info('Server identity keys loaded');
      }
    }

    // Initialize database
    db = await initDatabase();
    logger.info('PostgreSQL connected');

    // Run migrations
    const { runMigrations } = await import('./db/migrations.js');
    await runMigrations(db);
    logger.info('Database migrations completed');

    // Set database for admin routes
    setDatabase(db);

    // Set database for pairing routes
    setPairingDatabase(db);

    // Set database for devices routes
    setDevicesDatabase(db);

    // Set database for user profile routes
    const { setDatabase: setUserProfileDatabase } = await import('./routes/user-profile.js');
    setUserProfileDatabase(db);

    // Initialize Redis
    redis = await initRedis();
    logger.info('Redis connected');

    // Create WebSocket gateway
    const sessions = createWebSocketGateway(wss, { db, redis });
    setDevicesSessionsMap(sessions);
    setUserSessionsMap(sessions);
    setStatusSessionsMap(sessions);
    setStatusDatabase(db);
    logger.info('WebSocket gateway ready');

    // Start TTL cleanup job
    startTTLCleanupJob(db, 3600000); // Every hour
    logger.info('TTL cleanup job started');

    // Start data retention job
    const { startDataRetentionJob } = await import('./jobs/data-retention.js');
    startDataRetentionJob(db, 24 * 60 * 60 * 1000); // Daily
    logger.info('Data retention job started');

    // Handle server listen errors (MUST be set up BEFORE server.listen())
    server.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EADDRINUSE') {
        logger.error(`Port ${config.port} is already in use`, {
          port: config.port,
          code: error.code,
        });
        logger.error(
          'Please stop the process using this port or change the PORT environment variable'
        );
        console.error(`\n❌ Port ${config.port} is already in use!\n`);
        console.error('To fix this, run:');
        console.error(`  netstat -ano | grep ":${config.port}" | grep LISTENING`);
        console.error('  Then kill the process using: taskkill //F //PID <PID>\n');
      } else {
        logger.error(
          'Server error',
          {
            code: error.code,
            message: error.message,
          },
          error
        );
      }
      gracefulShutdown('server_error');
    });

    // Start server
    server.listen(config.port, '0.0.0.0', () => {
      logger.info(`Server listening on port ${config.port}`, {
        environment: config.nodeEnv,
        pid: process.pid,
      });
    });

    // Handle uncaught errors
    process.on('uncaughtException', error => {
      logger.error(
        'Uncaught exception',
        {
          name: error.name,
          message: error.message,
          stack: error.stack,
          code: (error as any).code,
        },
        error
      );
      console.error('Uncaught Exception Details:', error);
      gracefulShutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason, promise) => {
      const error = reason instanceof Error ? reason : new Error(String(reason));
      logger.error(
        'Unhandled rejection',
        {
          promise: promise.toString(),
          name: error.name,
          message: error.message,
          stack: error.stack,
        },
        error
      );
      console.error('Unhandled Rejection Details:', reason);
      gracefulShutdown('unhandledRejection');
    });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error(
      'Failed to start server',
      {
        message: err.message,
        stack: err.stack,
        name: err.name,
      },
      err
    );
    console.error('Startup Error Details:', {
      message: err.message,
      stack: err.stack,
      name: err.name,
    });
    process.exit(1);
  }
}

/**
 * Graceful shutdown with proper cleanup
 * Waits for in-flight requests and closes connections gracefully
 */
async function gracefulShutdown(signal: string): Promise<void> {
  if (isShuttingDown) {
    logger.warn('Shutdown already in progress');
    return;
  }

  isShuttingDown = true;
  logger.info(`Received ${signal}, shutting down gracefully...`);

  // Stop accepting new connections immediately
  server.close(() => {
    logger.info('HTTP server stopped accepting new connections');
  });

  // Close all WebSocket connections gracefully
  wss.clients.forEach(ws => {
    if (ws.readyState === ws.OPEN || ws.readyState === ws.CONNECTING) {
      ws.close(1001, 'Server shutting down');
    }
  });

  // Wait for in-flight requests to complete (with timeout)
  const shutdownTimeout = 30000; // 30 seconds
  const shutdownStart = Date.now();

  const waitForInFlight = async (): Promise<void> => {
    // Wait for WebSocket connections to close
    while (wss.clients.size > 0 && Date.now() - shutdownStart < shutdownTimeout) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    // Additional small delay for any final cleanup
    await new Promise(resolve => setTimeout(resolve, 1000));
  };

  try {
    await Promise.race([
      waitForInFlight(),
      new Promise<void>(resolve => {
        setTimeout(() => {
          logger.warn('Shutdown timeout reached, forcing closure');
          resolve();
        }, shutdownTimeout);
      }),
    ]);
  } catch (error) {
    logger.error(
      'Error during shutdown wait',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
  }

  // Close database connections
  if (db) {
    try {
      await db.end();
      logger.info('Database connections closed');
    } catch (error) {
      logger.error(
        'Error closing database',
        {},
        error instanceof Error ? error : new Error(String(error))
      );
    }
  }

  // Close Redis connections
  if (redis) {
    try {
      await redis.quit();
      logger.info('Redis connections closed');
    } catch (error) {
      logger.error(
        'Error closing Redis',
        {},
        error instanceof Error ? error : new Error(String(error))
      );
    }
  }

  logger.info('Graceful shutdown complete');
  process.exit(0);
}

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

start();
