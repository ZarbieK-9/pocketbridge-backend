/**
 * Device Management Routes
 *
 * APIs for multi-device management:
 * - List user's devices
 * - Get device details and online status
 * - Rename devices
 * - Remove/revoke devices
 * - Get real-time presence
 */

import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger.js';
import { ValidationError } from '../utils/errors.js';
import { sanitizeDeviceName } from '../utils/validation.js';
import type { SessionState, DeviceInfo } from '../types/index.js';
import { config } from '../config.js';

// Store reference to sessions Map from WebSocket gateway
let sessionsMap: Map<string, SessionState> | null = null;
let database: any = null;

export function setSessionsMap(sessions: Map<string, SessionState>): void {
  sessionsMap = sessions;
}

export function setDatabase(db: any): void {
  database = db;
}

const router = Router();

/**
 * Get all devices for current user
 * GET /api/devices
 */
router.get('/devices', async (req: Request, res: Response) => {
  try {
    // In production, extract user_id from JWT token
    // For now, query from authenticated session
    const userId = (req as any).userId as string | undefined;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized: No user context' });
    }

    // Validate user ID format (Ed25519 public key: 64 hex characters)
    if (!/^[0-9a-f]{64}$/i.test(userId)) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    // Update user activity
    await database.pool.query(`UPDATE users SET last_activity = NOW() WHERE user_id = $1`, [
      userId,
    ]);

    // Get all devices for user (from devices table)
    const result = await database.pool.query(
      `SELECT 
        device_id, device_name, device_type, device_os,
        last_seen, registered_at, ip_address
       FROM user_devices
       WHERE user_id = $1
       ORDER BY last_seen DESC`,
      [userId]
    );

    const devices: DeviceInfo[] = result.rows.map((row: any) => ({
      device_id: row.device_id,
      device_name: row.device_name,
      device_type: row.device_type,
      device_os: row.device_os,
      is_online: sessionsMap ? sessionsMap.has(row.device_id) : false,
      last_seen: new Date(row.last_seen).getTime(),
      ip_address: row.ip_address || undefined,
    }));

    // Handle empty state
    const is_empty = devices.length === 0;
    return res.json({
      devices,
      count: devices.length,
      is_empty,
      message: is_empty ? 'No devices connected. Connect a device to start syncing.' : undefined,
    });
  } catch (error) {
    logger.error(
      'Failed to get devices',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to get devices' });
  }
});

/**
 * Get device details
 * GET /api/devices/:deviceId
 */
router.get('/devices/:deviceId', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId as string | undefined;
    const { deviceId } = req.params;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    // Update user activity
    await database.pool.query(`UPDATE users SET last_activity = NOW() WHERE user_id = $1`, [
      userId,
    ]);

    const result = await database.pool.query(
      `SELECT * FROM user_devices
       WHERE device_id = $1::uuid AND user_id = $2`,
      [deviceId, userId]
    );

    if (result.rows.length === 0) {
      // Edge case: Device doesn't exist or doesn't belong to user
      // This is normal for new devices that haven't connected yet
      return res.status(404).json({
        error: 'Device not found',
        is_empty: true,
        message:
          'The requested device was not found or does not belong to you. Connect the device to register it.',
      });
    }

    const device = result.rows[0];
    res.json({
      device_id: device.device_id,
      device_name: device.device_name,
      device_type: device.device_type,
      device_os: device.device_os,
      is_online: sessionsMap ? sessionsMap.has(device.device_id) : false,
      last_seen: new Date(device.last_seen).getTime(),
      registered_at: new Date(device.registered_at).getTime(),
    });
  } catch (error) {
    logger.error(
      'Failed to get device',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to get device' });
  }
});

/**
 * Rename device
 * POST /api/devices/:deviceId/rename
 */
router.post('/devices/:deviceId/rename', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId as string | undefined;
    const { deviceId } = req.params;
    const { device_name } = req.body;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!device_name || typeof device_name !== 'string' || device_name.length === 0) {
      throw new ValidationError('Device name must be 1-50 characters');
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    // Update user activity
    await database.pool.query(`UPDATE users SET last_activity = NOW() WHERE user_id = $1`, [
      userId,
    ]);

    // Sanitize device name (remove invalid UTF-8, truncate to 50 chars)
    const sanitizedName = sanitizeDeviceName(device_name, 50);
    if (sanitizedName.length === 0) {
      throw new ValidationError('Device name contains invalid characters');
    }

    // Verify device belongs to user
    const checkResult = await database.pool.query(
      `SELECT user_id FROM user_devices WHERE device_id = $1::uuid`,
      [deviceId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }

    if (checkResult.rows[0].user_id !== userId) {
      return res.status(403).json({ error: "Cannot rename another user's device" });
    }

    // Check if another device with the same name already exists for this user
    const duplicateCheck = await database.pool.query(
      `SELECT device_id FROM user_devices 
       WHERE user_id = $1 
       AND device_name = $2 
       AND device_id != $3::uuid`,
      [userId, sanitizedName, deviceId]
    );

    if (duplicateCheck.rows.length > 0) {
      throw new ValidationError('Another device with this name already exists');
    }

    // Update device name
    const updateResult = await database.pool.query(
      `UPDATE user_devices
       SET device_name = $1
       WHERE device_id = $2::uuid
       RETURNING *`,
      [sanitizedName, deviceId]
    );

    logger.info('Device renamed', { userId, deviceId, device_name });

    res.json({
      success: true,
      device_id: updateResult.rows[0].device_id,
      device_name: updateResult.rows[0].device_name,
    });
  } catch (error) {
    logger.error(
      'Failed to rename device',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    if (error instanceof ValidationError) {
      res.status(400).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Failed to rename device' });
    }
  }
});

/**
 * Remove/revoke device
 * DELETE /api/devices/:deviceId
 */
router.delete('/devices/:deviceId', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId as string | undefined;
    const { deviceId } = req.params;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    // Update user activity
    await database.pool.query(`UPDATE users SET last_activity = NOW() WHERE user_id = $1`, [
      userId,
    ]);

    // Verify device belongs to user
    const checkResult = await database.pool.query(
      `SELECT user_id FROM user_devices WHERE device_id = $1::uuid`,
      [deviceId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }

    if (checkResult.rows[0].user_id !== userId) {
      return res.status(403).json({ error: "Cannot remove another user's device" });
    }

    // Hard delete device; events referencing it will cascade if configured
    await database.pool.query(
      `DELETE FROM user_devices WHERE device_id = $1::uuid AND user_id = $2`,
      [deviceId, userId]
    );

    logger.info('Device removed', { userId, deviceId });

    res.json({
      success: true,
      message: `Device ${deviceId} has been removed`,
    });
  } catch (error) {
    logger.error(
      'Failed to remove device',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to remove device' });
  }
});

/**
 * Get real-time presence (online/offline status of all user's devices)
 * GET /api/presence
 *
 * Could also be WebSocket for real-time:
 * - Client: { type: 'subscribe_presence' }
 * - Server: { type: 'presence_update', online_devices: [...] }
 */
router.get('/presence', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId as string | undefined;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    // Update user activity
    await database.pool.query(`UPDATE users SET last_activity = NOW() WHERE user_id = $1`, [
      userId,
    ]);

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    const result = await database.pool.query(
      `SELECT device_id, device_name, last_seen
       FROM user_devices
       WHERE user_id = $1
       ORDER BY last_seen DESC`,
      [userId]
    );

    const devices = result.rows.map((row: any) => ({
      device_id: row.device_id,
      device_name: row.device_name,
      is_online: sessionsMap ? sessionsMap.has(row.device_id) : false,
      last_seen: new Date(row.last_seen).getTime(),
    }));

    // Handle empty state
    const is_empty = devices.length === 0;
    res.json({
      user_id: userId,
      devices,
      online_count: devices.filter((d: any) => d.is_online).length,
      total_count: devices.length,
      is_empty,
      message: is_empty ? 'No devices found. Connect your first device to get started.' : undefined,
    });
  } catch (error) {
    logger.error(
      'Failed to get presence',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to get presence' });
  }
});

export default router;
