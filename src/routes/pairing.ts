/**
 * Pairing Code Routes
 *
 * Handles pairing code generation and lookup
 * Pairing codes are temporary (expire after 10 minutes)
 */

import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger.js';
import { ValidationError } from '../utils/errors.js';
import type { Database } from '../db/postgres.js';
import type { RedisConnection } from '../db/redis.js';

let dbInstance: Database | null = null;
let redisInstance: RedisConnection | null = null;

export function setDatabase(db: Database): void {
  dbInstance = db;
}

export function setRedis(redis: RedisConnection): void {
  redisInstance = redis;
}

const router = Router();

/**
 * Store a pairing code
 * POST /api/pairing/store
 * Body: { code, data: { wsUrl, userId, deviceId, deviceName, publicKeyHex, privateKeyHex } }
 */
router.post('/store', async (req: Request, res: Response) => {
  try {
    const { code, data } = req.body;

    if (!code || !data) {
      throw new ValidationError('code and data are required');
    }

    if (
      !data.wsUrl ||
      !data.userId ||
      !data.deviceId ||
      !data.publicKeyHex ||
      !data.privateKeyHex
    ) {
      throw new ValidationError(
        'wsUrl, userId, deviceId, publicKeyHex, and privateKeyHex are required'
      );
    }

    if (!dbInstance) {
      throw new Error('Database not initialized');
    }

    // Store pairing code with 10-minute expiration
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Delete any existing pairing codes for this user/device to prevent duplicates
    await dbInstance.pool.query(`DELETE FROM pairing_codes WHERE user_id = $1 AND device_id = $2`, [
      data.userId,
      data.deviceId,
    ]);

    await dbInstance.pool.query(
      `INSERT INTO pairing_codes (code, ws_url, user_id, device_id, device_name, public_key_hex, private_key_hex, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        code,
        data.wsUrl,
        data.userId,
        data.deviceId,
        data.deviceName || 'Device',
        data.publicKeyHex,
        data.privateKeyHex,
        expiresAt,
      ]
    );

    logger.info('Pairing code stored', {
      code,
      userId: data.userId.substring(0, 16) + '...',
      expiresAt,
    });

    res.json({
      success: true,
      message: 'Pairing code stored',
      expiresAt: expiresAt.toISOString(),
      expiresIn: 10 * 60 * 1000, // 10 minutes in milliseconds
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;
    
    logger.error(
      'Failed to store pairing code',
      { 
        body: req.body,
        error: errorMessage,
        stack: errorStack,
        errorName: error instanceof Error ? error.name : 'Unknown',
      },
      error instanceof Error ? error : new Error(String(error))
    );
    
    if (error instanceof ValidationError) {
      res.status(400).json({ error: error.message });
    } else {
      // Include more details in development
      const isDevelopment = process.env.NODE_ENV !== 'production';
      res.status(500).json({ 
        error: 'Failed to store pairing code',
        ...(isDevelopment && { details: errorMessage, stack: errorStack })
      });
    }
  }
});

/**
 * Retrieve pairing code data
 * GET /api/pairing/lookup/:code
 */
router.get('/lookup/:code', async (req: Request, res: Response) => {
  try {
    const { code } = req.params;

    if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
      throw new ValidationError('Invalid pairing code format');
    }

    if (!dbInstance) {
      throw new Error('Database not initialized');
    }

    // Look up pairing code
    const result = await dbInstance.pool.query(
      `SELECT ws_url, user_id, device_id, device_name, public_key_hex, private_key_hex, expires_at
       FROM pairing_codes
       WHERE code = $1 AND expires_at > NOW()`,
      [code]
    );

    if (result.rows.length === 0) {
      logger.warn('Pairing code not found or expired', { code });
      res.status(404).json({ error: 'Pairing code not found or expired' });
      return;
    }

    const row = result.rows[0];

    // Store pairing session in Redis for completePairing() to use
    // This bridges the data from DB lookup to the WebSocket handler
    if (redisInstance) {
      const REDIS_PAIRING_PREFIX = 'pairing:';
      const pairingSession = {
        initiatingUserId: row.user_id,
        initiatingDeviceId: row.device_id,
        code: code,
        createdAt: Date.now(),
        expiresAt: new Date(row.expires_at).getTime(),
        used: false,
        deviceName: row.device_name,
        publicKeyHex: row.public_key_hex,
        privateKeyHex: row.private_key_hex,
        wsUrl: row.ws_url,
      };

      // Calculate remaining TTL in seconds (max 10 minutes)
      const ttlSeconds = Math.ceil((new Date(row.expires_at).getTime() - Date.now()) / 1000);
      const finalTtl = Math.max(1, Math.min(ttlSeconds, 600)); // 1 to 600 seconds

      try {
        await redisInstance.client.setEx(
          `${REDIS_PAIRING_PREFIX}${code}`,
          finalTtl,
          JSON.stringify(pairingSession)
        );
        logger.info('Pairing session stored in Redis', {
          code,
          ttl: finalTtl,
          initiatingUserId: row.user_id.substring(0, 16) + '...',
        });
      } catch (redisError) {
        logger.warn('Failed to store pairing session in Redis', { code }, redisError);
        // Continue anyway - completePairing will fail if Redis is needed but we'll log the error
      }
    }

    // Delete the code after retrieval (one-time use)
    await dbInstance.pool.query('DELETE FROM pairing_codes WHERE code = $1', [code]);

    logger.info('Pairing code retrieved and deleted', {
      code,
      userId: row.user_id.substring(0, 16) + '...',
    });

    res.json({
      success: true,
      data: {
        wsUrl: row.ws_url,
        userId: row.user_id,
        deviceId: row.device_id,
        deviceName: row.device_name,
        publicKeyHex: row.public_key_hex,
        privateKeyHex: row.private_key_hex,
      },
    });
  } catch (error) {
    logger.error(
      'Failed to lookup pairing code',
      { code: req.params.code },
      error instanceof Error ? error : new Error(String(error))
    );
    if (error instanceof ValidationError) {
      res.status(400).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Failed to lookup pairing code' });
    }
  }
});

export default router;
