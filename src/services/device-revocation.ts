/**
 * Device Revocation Service
 * 
 * Manages device blacklist for compromised devices
 */

import type { Database } from '../db/postgres.js';
import { logger } from '../utils/logger.js';
import { auditLog, AuditEventType } from '../utils/audit-log.js';

/**
 * Check if device is revoked
 */
export async function isDeviceRevoked(
  db: Database,
  deviceId: string
): Promise<boolean> {
  try {
    const result = await db.pool.query(
      'SELECT device_id FROM revoked_devices WHERE device_id = $1',
      [deviceId]
    );
    return result.rows.length > 0;
  } catch (error) {
    logger.error('Failed to check device revocation', { deviceId }, error instanceof Error ? error : new Error(String(error)));
    // Fail open - if we can't check, allow connection (but log it)
    return false;
  }
}

/**
 * Revoke a device
 */
export async function revokeDevice(
  db: Database,
  deviceId: string,
  userId: string,
  reason?: string,
  revokedBy?: string
): Promise<void> {
  try {
    await db.pool.query(
      `INSERT INTO revoked_devices (device_id, user_id, reason, revoked_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (device_id) DO UPDATE
       SET revoked_at = NOW(), reason = $3, revoked_by = $4`,
      [deviceId, userId, reason || 'Security concern', revokedBy || userId]
    );

    auditLog(AuditEventType.DEVICE_REVOKED, {
      userId,
      deviceId,
      details: { reason, revokedBy },
    });

    logger.info('Device revoked', { deviceId, userId, reason });
  } catch (error) {
    logger.error('Failed to revoke device', { deviceId, userId }, error instanceof Error ? error : new Error(String(error)));
    throw error;
  }
}

/**
 * Unrevoke a device (restore access)
 */
export async function unrevokeDevice(
  db: Database,
  deviceId: string
): Promise<void> {
  try {
    await db.pool.query(
      'DELETE FROM revoked_devices WHERE device_id = $1',
      [deviceId]
    );

    logger.info('Device unrevoked', { deviceId });
  } catch (error) {
    logger.error('Failed to unrevoke device', { deviceId }, error instanceof Error ? error : new Error(String(error)));
    throw error;
  }
}

/**
 * Get all revoked devices for a user
 */
export async function getRevokedDevices(
  db: Database,
  userId: string
): Promise<Array<{ deviceId: string; revokedAt: Date; reason?: string }>> {
  try {
    const result = await db.pool.query(
      'SELECT device_id, revoked_at, reason FROM revoked_devices WHERE user_id = $1',
      [userId]
    );

    return result.rows.map(row => ({
      deviceId: row.device_id,
      revokedAt: new Date(row.revoked_at),
      reason: row.reason,
    }));
  } catch (error) {
    logger.error('Failed to get revoked devices', { userId }, error instanceof Error ? error : new Error(String(error)));
    return [];
  }
}















