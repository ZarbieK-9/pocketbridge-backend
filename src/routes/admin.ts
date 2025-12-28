/**
 * Admin Routes
 *
 * Device revocation and admin operations
 * NOTE: In production, add authentication/authorization middleware
 */

import { Router, Request, Response } from 'express';
import { revokeDevice, unrevokeDevice, getRevokedDevices } from '../services/device-revocation.js';
import { logger } from '../utils/logger.js';
import { ValidationError } from '../utils/errors.js';
import { adminAuthMiddleware } from '../middleware/admin-auth.js';

// NOTE: In production, inject db via dependency injection
// For now, we'll need to pass it from index.ts
let dbInstance: any = null;

export function setDatabase(db: any) {
  dbInstance = db;
}

const router = Router();

// Protect all admin routes with authentication
router.use(adminAuthMiddleware);

/**
 * Revoke a device
 * POST /admin/revoke-device
 * Body: { deviceId, userId, reason?, revokedBy? }
 * Headers: X-Admin-API-Key: <admin_api_key>
 */
router.post('/revoke-device', async (req: Request, res: Response) => {
  try {
    const { deviceId, userId, reason, revokedBy } = req.body;

    if (!deviceId || !userId) {
      throw new ValidationError('deviceId and userId are required');
    }

    if (!dbInstance) {
      throw new Error('Database not initialized');
    }
    await revokeDevice(dbInstance, deviceId, userId, reason, revokedBy);

    res.json({ success: true, message: 'Device revoked' });
  } catch (error) {
    logger.error(
      'Failed to revoke device',
      { body: req.body },
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to revoke device' });
  }
});

/**
 * Unrevoke a device
 * POST /admin/unrevoke-device
 * Body: { deviceId }
 */
router.post('/unrevoke-device', async (req: Request, res: Response) => {
  try {
    const { deviceId } = req.body;

    if (!deviceId) {
      throw new ValidationError('deviceId is required');
    }

    if (!dbInstance) {
      throw new Error('Database not initialized');
    }
    await unrevokeDevice(dbInstance, deviceId);

    res.json({ success: true, message: 'Device unrevoked' });
  } catch (error) {
    logger.error(
      'Failed to unrevoke device',
      { body: req.body },
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to unrevoke device' });
  }
});

/**
 * Get revoked devices for a user
 * GET /admin/revoked-devices?userId=...
 */
router.get('/revoked-devices', async (req: Request, res: Response) => {
  try {
    const { userId } = req.query;

    if (!userId || typeof userId !== 'string') {
      throw new ValidationError('userId query parameter is required');
    }

    if (!dbInstance) {
      throw new Error('Database not initialized');
    }
    const revoked = await getRevokedDevices(dbInstance, userId);

    res.json({ revoked });
  } catch (error) {
    logger.error(
      'Failed to get revoked devices',
      { query: req.query },
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to get revoked devices' });
  }
});

export default router;
