/**
 * Connection Status Routes
 *
 * Provides API endpoints to query connection status
 * NOTE: In production, add authentication/authorization middleware
 */

import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger.js';
import { ValidationError } from '../utils/errors.js';
import type { SessionState, ConnectionStatus } from '../types/index.js';
import type { Database } from '../db/postgres.js';
import type { RedisConnection } from '../db/redis.js';
import { config } from '../config.js';

// Store reference to sessions Map from WebSocket gateway
let sessionsMap: Map<string, SessionState> | null = null;
let database: Database | null = null;
let redisConnection: RedisConnection | null = null;

export function setSessionsMap(sessions: Map<string, SessionState>): void {
  sessionsMap = sessions;
}

export function setDatabase(db: Database): void {
  database = db;
}

export function setRedis(redis: RedisConnection): void {
  redisConnection = redis;
}

const router = Router();

/**
 * Get connection status for a device or user
 * GET /api/connection-status?deviceId=... OR ?userId=...
 */
router.get('/connection-status', async (req: Request, res: Response) => {
  try {
    const { deviceId, userId } = req.query;
    const authenticatedUserId = (req as any).userId as string | undefined;

    if (!deviceId && !userId) {
      throw new ValidationError('deviceId or userId query parameter is required');
    }

    // Update user activity if authenticated user ID is available
    if (authenticatedUserId && database) {
      try {
        await database.pool.query(`UPDATE users SET last_activity = NOW() WHERE user_id = $1`, [
          authenticatedUserId,
        ]);
      } catch {
        // Ignore errors - activity tracking is not critical
      }
    }

    if (!sessionsMap) {
      logger.warn('Sessions map not initialized');
      return res.status(503).json({
        error: 'Service unavailable',
        connected: false,
      });
    }

    let session: SessionState | undefined;

    if (deviceId) {
      // Query by deviceId (exact match)
      session = sessionsMap.get(deviceId as string);
    } else if (userId) {
      // Query by userId (find any device for user)
      session = Array.from(sessionsMap.values()).find(s => s.userId === (userId as string));
    }

    if (!session) {
      // Edge case: Device/user not connected or doesn't exist yet
      // This is normal for new users or devices that haven't connected
      return res.json({
        connected: false,
        deviceId: (deviceId as string) || undefined,
        userId: (userId as string) || undefined,
        status: 'disconnected' as ConnectionStatus,
        message: deviceId
          ? 'Device is currently offline or has no active session. Connect the device to start syncing.'
          : userId
            ? 'No active devices found for this user. Connect a device to get started.'
            : 'Device or user not found. Connect a device to create a new session.',
        is_empty: true,
      });
    }

    const now = Date.now();
    const sessionAge = now - session.createdAt;
    const expiresAt = session.createdAt + config.websocket.sessionTimeout;

    return res.json({
      connected: true,
      deviceId: session.deviceId,
      userId: session.userId,
      lastSeen: now, // TODO: Track actual lastSeen from heartbeat
      sessionAge,
      expiresAt,
      expiresIn: expiresAt - now, // Milliseconds until expiration
      status: 'connected' as ConnectionStatus,
    });
  } catch (error) {
    logger.error(
      'Failed to get connection status',
      { query: req.query },
      error instanceof Error ? error : new Error(String(error))
    );
    if (error instanceof ValidationError) {
      res.status(400).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Failed to get connection status' });
    }
  }
});

/**
 * Health check endpoint
 * GET /api/health
 */
router.get('/health', async (req: Request, res: Response) => {
  try {
    const health: {
      status: string;
      timestamp: number;
      version: string;
      database?: string;
      redis?: string;
    } = {
      status: 'healthy',
      timestamp: Date.now(),
      version: process.env.npm_package_version || '1.0.0',
    };

    // Check database connectivity
    if (database) {
      try {
        await database.pool.query('SELECT 1');
        health.database = 'connected';
      } catch (error) {
        logger.error('Database health check failed', {}, error instanceof Error ? error : new Error(String(error)));
        health.database = 'error';
        health.status = 'degraded';
      }
    } else {
      health.database = 'not_initialized';
      health.status = 'degraded';
    }

    // Check Redis connectivity
    if (redisConnection) {
      try {
        await redisConnection.healthCheck();
        health.redis = 'connected';
      } catch (error) {
        logger.error('Redis health check failed', {}, error instanceof Error ? error : new Error(String(error)));
        health.redis = 'error';
        health.status = 'degraded';
      }
    } else {
      health.redis = 'not_initialized';
    }

    const statusCode = health.status === 'healthy' ? 200 : 503;
    res.status(statusCode).json(health);
  } catch (error) {
    logger.error('Health check failed', {}, error instanceof Error ? error : new Error(String(error)));
    res.status(503).json({
      status: 'error',
      timestamp: Date.now(),
      error: error instanceof Error ? error.message : 'Health check failed',
    });
  }
});

export default router;
