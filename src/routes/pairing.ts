/**
 * Pairing Code Routes
 *
 * Handles pairing code generation and lookup
 * Pairing codes are temporary (expire after 10 minutes)
 */

import { Router, Request, Response } from 'express';
import os from 'os';
import { logger } from '../utils/logger.js';
import { ValidationError } from '../utils/errors.js';
import type { Database } from '../db/postgres.js';
import type { RedisConnection } from '../db/redis.js';

/**
 * Get the machine's LAN IPv4 address, skipping virtual/container adapters.
 * Used to replace "localhost" in pairing URLs so external devices can connect.
 */
function getLocalLanIp(): string | null {
  const interfaces = os.networkInterfaces();
  const candidates: { name: string; address: string }[] = [];

  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name] || []) {
      if (iface.family === 'IPv4' && !iface.internal) {
        candidates.push({ name, address: iface.address });
      }
    }
  }

  if (candidates.length === 0) return null;
  if (candidates.length === 1) return candidates[0].address;

  // Skip virtual/container network adapters that external devices can't reach
  const virtualNamePatterns = [
    /virtualbox/i, /vbox/i, /vmware/i, /vmnet/i,
    /docker/i, /wsl/i, /hyper-v/i, /vethernet/i,
  ];
  const virtualIpPrefixes = ['192.168.56.', '172.17.', '172.18.'];

  const real = candidates.filter(({ name, address }) => {
    if (virtualNamePatterns.some(p => p.test(name))) return false;
    if (virtualIpPrefixes.some(p => address.startsWith(p))) return false;
    return true;
  });

  const chosen = real.length > 0 ? real[0] : candidates[0];
  logger.info('getLocalLanIp resolved', {
    chosen: chosen.address,
    interface: chosen.name,
    allCandidates: candidates.map(c => `${c.name}=${c.address}`),
  });
  return chosen.address;
}

/**
 * Replace localhost/127.0.0.1 in a WebSocket URL with the machine's LAN IP.
 * This ensures external devices (phones) can reach the server.
 */
function normalizeWsUrlForSharing(wsUrl: string): string {
  try {
    const parsed = new URL(wsUrl);
    if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
      const lanIp = getLocalLanIp();
      if (lanIp) {
        parsed.hostname = lanIp;
        logger.info('Normalized localhost wsUrl for pairing', {
          original: wsUrl,
          normalized: parsed.toString(),
          lanIp,
        });
        return parsed.toString().replace(/\/$/, ''); // Remove trailing slash
      }
    }
  } catch {
    // If URL parsing fails, return as-is
  }
  return wsUrl;
}

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

    // Normalize localhost URLs to LAN IP so external devices (phones) can connect
    const shareableWsUrl = normalizeWsUrlForSharing(data.wsUrl);

    // Store pairing code with 10-minute expiration
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Ensure user exists in users table (for foreign key constraint)
    // This allows mobile-first pairing where the mobile device generates the identity
    await dbInstance.pool.query(
      `INSERT INTO users (user_id, created_at, last_activity, is_active)
       VALUES ($1, NOW(), NOW(), true)
       ON CONFLICT (user_id) DO NOTHING`,
      [data.userId]
    );

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
        shareableWsUrl,
        data.userId,
        data.deviceId,
        data.deviceName || 'Device',
        data.publicKeyHex,
        data.privateKeyHex,
        expiresAt,
      ]
    );

    // Also store in Redis so that the WebSocket complete_pairing handler can find it.
    // The mobile app may use the QR identity directly (skipping /lookup), so Redis
    // must be populated at creation time, not just on lookup.
    if (redisInstance) {
      const REDIS_PAIRING_PREFIX = 'pairing:';
      const pairingSession = {
        code,
        initiatingUserId: data.userId,
        initiatingDeviceId: data.deviceId,
        createdAt: Date.now(),
        expiresAt: expiresAt.getTime(),
        used: false,
      };

      const ttlSeconds = 10 * 60; // 10 minutes
      try {
        await redisInstance.client.setEx(
          `${REDIS_PAIRING_PREFIX}${code}`,
          ttlSeconds,
          JSON.stringify(pairingSession)
        );
        logger.info('Pairing session stored in Redis at creation', { code });
      } catch (redisError) {
        logger.warn('Failed to store pairing session in Redis', { code }, redisError);
      }
    }

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
      shareableWsUrl, // Normalized URL for external devices (localhost → LAN IP)
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
