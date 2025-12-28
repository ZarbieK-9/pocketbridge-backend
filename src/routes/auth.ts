/**
 * Authentication Routes
 *
 * Provides token generation and refresh endpoints
 */

import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger.js';
import { generateToken, verifyToken } from '../middleware/jwt-auth.js';
import { AuthenticationError, ValidationError } from '../utils/errors.js';
import type { Database } from '../db/postgres.js';

// Store reference to database
let database: Database | null = null;

export function setDatabase(db: Database): void {
  database = db;
}

const router = Router();

/**
 * Generate JWT token for authenticated user
 * POST /api/auth/token
 * Headers: X-User-ID (for initial token generation after WebSocket handshake)
 * Response: { token, expiresAt, expiresIn }
 */
router.post('/token', async (req: Request, res: Response) => {
  try {
    const userId = req.headers['x-user-id'] as string | undefined;

    if (!userId) {
      throw new ValidationError('X-User-ID header is required for token generation');
    }

    // Validate user ID format
    if (!/^[0-9a-f]{64}$/i.test(userId)) {
      throw new ValidationError('Invalid user ID format (must be 64 hex characters)');
    }

    // Update user activity
    if (database) {
      await database.pool
        .query(`UPDATE users SET last_activity = NOW() WHERE user_id = $1`, [userId])
        .catch(() => {
          // Ignore errors - activity tracking is not critical
        });
    }

    // Generate token (1 hour expiration)
    const expiresInMs = 3600000; // 1 hour
    const token = await generateToken(userId, expiresInMs);
    const expiresAt = new Date(Date.now() + expiresInMs);

    logger.info('Token generated', {
      requestId: (req as any).requestId,
      userId: userId.substring(0, 16) + '...',
    });

    res.json({
      token,
      expiresAt: expiresAt.toISOString(),
      expiresIn: expiresInMs,
    });
  } catch (error) {
    logger.error(
      'Failed to generate token',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    if (error instanceof ValidationError) {
      res.status(400).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Failed to generate token' });
    }
  }
});

/**
 * Refresh JWT token
 * POST /api/auth/refresh
 * Headers: Authorization: Bearer <token>
 * Response: { token, expiresAt, expiresIn }
 */
router.post('/refresh', async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AuthenticationError('Authorization header with Bearer token required');
    }

    const token = authHeader.substring(7);
    const payload = await verifyToken(token);

    // Update user activity
    if (database) {
      await database.pool
        .query(`UPDATE users SET last_activity = NOW() WHERE user_id = $1`, [payload.user_id])
        .catch(() => {
          // Ignore errors - activity tracking is not critical
        });
    }

    // Generate new token
    const expiresInMs = 3600000; // 1 hour
    const newToken = await generateToken(payload.user_id, expiresInMs);
    const expiresAt = new Date(Date.now() + expiresInMs);

    logger.info('Token refreshed', {
      requestId: (req as any).requestId,
      userId: payload.user_id.substring(0, 16) + '...',
    });

    res.json({
      token: newToken,
      expiresAt: expiresAt.toISOString(),
      expiresIn: expiresInMs,
    });
  } catch (error) {
    logger.error(
      'Failed to refresh token',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    if (error instanceof AuthenticationError) {
      res.status(401).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Failed to refresh token' });
    }
  }
});

/**
 * Verify token
 * GET /api/auth/verify
 * Headers: Authorization: Bearer <token>
 * Response: { valid, payload }
 */
router.get('/verify', async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.json({ valid: false, error: 'No token provided' });
    }

    const token = authHeader.substring(7);
    const payload = await verifyToken(token);

    res.json({
      valid: true,
      payload: {
        user_id: payload.user_id,
        iat: payload.iat,
        exp: payload.exp,
      },
    });
  } catch (error) {
    res.json({
      valid: false,
      error: error instanceof Error ? error.message : 'Invalid token',
    });
  }
});

export default router;
