/**
 * PocketBridge Backend - Main Entry Point
 * 
 * Production-grade event-driven backend with:
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
import { generateServerIdentityKeypair } from './crypto/utils.js';
import { securityHeaders } from './middleware/security-headers.js';
import { startTTLCleanupJob } from './jobs/ttl-cleanup.js';
import { getMetrics } from './routes/metrics.js';
import adminRouter, { setDatabase } from './routes/admin.js';
import pairingRouter, { setDatabase as setPairingDatabase } from './routes/pairing.js';
import statusRouter, { setSessionsMap } from './routes/status.js';

const app = express();

// Trust proxy (for rate limiting behind reverse proxy)
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // WebSocket needs this disabled
  crossOriginEmbedderPolicy: false,
}));

// CORS - Must be before other middleware
// Build dynamic CORS options with whitelist + sensible defaults
const allowedOrigins = Array.isArray(config.cors.origin)
  ? (config.cors.origin as string[])
  : [config.cors.origin as string];

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    // Allow non-browser or same-origin requests
    if (!origin) return callback(null, true);
    // If no whitelist configured, allow all origins (recommended to set CORS_ORIGIN in production)
    if (allowedOrigins.length === 0) return callback(null, true);
    // If wildcard configured, allow all origins (credentials should be false when using '*')
    if (allowedOrigins.includes('*')) return callback(null, true);
    // Exact match against whitelist
    if (allowedOrigins.includes(origin)) return callback(null, true);
    // Attempt relaxed host-only matching (handles trailing slashes/protocol differences)
    try {
      const o = new URL(origin);
      const originHost = `${o.protocol}//${o.host}`;
      if (allowedOrigins.includes(originHost)) return callback(null, true);
    } catch {}
    callback(new Error(`CORS: Origin ${origin} not allowed`));
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

// Request logging
app.use(requestLogger);

// Rate limiting (DISABLED FOR TESTING)
// const limiter = rateLimit({
//   windowMs: config.rateLimit.windowMs,
//   max: config.rateLimit.maxRequests,
//   message: 'Too many requests from this IP, please try again later.',
//   standardHeaders: true,
//   legacyHeaders: false,
// });
// app.use('/api', limiter);

// Security headers
app.use(securityHeaders);

// Health check endpoint (no rate limiting)
app.get('/health', async (req, res) => {
  const dbHealthy = db ? await db.healthCheck() : false;
  const redisHealthy = redis ? await redis.healthCheck() : false;

  const status = dbHealthy && redisHealthy ? 'ok' : 'degraded';
  const statusCode = status === 'ok' ? 200 : 503;

  res.status(statusCode).json({
    status,
    timestamp: Date.now(),
    uptime: process.uptime(),
    services: {
      database: dbHealthy,
      redis: redisHealthy,
    },
    version: process.env.npm_package_version || '1.0.0',
  });
});

// Metrics endpoint
app.get('/metrics', getMetrics);

// Admin routes (add authentication in production!)
app.use('/admin', adminRouter);

// Pairing routes
app.use('/api/pairing', pairingRouter);

// Status routes
app.use('/api', statusRouter);

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
      logger.warn('Set SERVER_PUBLIC_KEY_HEX and SERVER_PRIVATE_KEY_HEX environment variables in production!');
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
    
    // Set database for admin routes
    setDatabase(db);
    
    // Set database for pairing routes
    setPairingDatabase(db);

    // Initialize Redis
    redis = await initRedis();
    logger.info('Redis connected');

    // Create WebSocket gateway
    const sessions = createWebSocketGateway(wss, { db, redis });
    setSessionsMap(sessions);
    logger.info('WebSocket gateway ready');

    // Start TTL cleanup job
    startTTLCleanupJob(db, 3600000); // Every hour
    logger.info('TTL cleanup job started');

    // Handle server listen errors (MUST be set up BEFORE server.listen())
    server.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EADDRINUSE') {
        logger.error(`Port ${config.port} is already in use`, {
          port: config.port,
          code: error.code,
        });
        logger.error('Please stop the process using this port or change the PORT environment variable');
        console.error(`\n❌ Port ${config.port} is already in use!\n`);
        console.error('To fix this, run:');
        console.error(`  netstat -ano | grep ":${config.port}" | grep LISTENING`);
        console.error('  Then kill the process using: taskkill //F //PID <PID>\n');
      } else {
        logger.error('Server error', {
          code: error.code,
          message: error.message,
        }, error);
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
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception', {
        name: error.name,
        message: error.message,
        stack: error.stack,
        code: (error as any).code,
      }, error);
      console.error('Uncaught Exception Details:', error);
      gracefulShutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason, promise) => {
      const error = reason instanceof Error ? reason : new Error(String(reason));
      logger.error('Unhandled rejection', {
        promise: promise.toString(),
        name: error.name,
        message: error.message,
        stack: error.stack,
      }, error);
      console.error('Unhandled Rejection Details:', reason);
      gracefulShutdown('unhandledRejection');
    });

  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error('Failed to start server', {
      message: err.message,
      stack: err.stack,
      name: err.name,
    }, err);
    console.error('Startup Error Details:', {
      message: err.message,
      stack: err.stack,
      name: err.name,
    });
    process.exit(1);
  }
}

/**
 * Graceful shutdown
 */
async function gracefulShutdown(signal: string): Promise<void> {
  if (isShuttingDown) {
    logger.warn('Shutdown already in progress');
    return;
  }

  isShuttingDown = true;
  logger.info(`Received ${signal}, shutting down gracefully...`);

  // Stop accepting new connections
  server.close(async () => {
    logger.info('HTTP server closed');

    // Close database connections
    if (db) {
      try {
        await db.end();
        logger.info('Database connections closed');
      } catch (error) {
        logger.error('Error closing database', {}, error instanceof Error ? error : new Error(String(error)));
      }
    }

    // Close Redis connections
    if (redis) {
      try {
        await redis.quit();
        logger.info('Redis connections closed');
      } catch (error) {
        logger.error('Error closing Redis', {}, error instanceof Error ? error : new Error(String(error)));
      }
    }

    logger.info('Graceful shutdown complete');
    process.exit(0);
  });

  // Force shutdown after 30 seconds
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 30000);
}

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

start();
