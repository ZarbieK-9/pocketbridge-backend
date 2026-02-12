/**
 * Device Pairing Service
 *
 * Handles pairing of devices through 6-digit codes:
 * - Generate pairing code
 * - Verify pairing code
 * - Link devices to same user after pairing
 * - Manage pairing sessions (temporary storage)
 *
 * Architecture:
 * Device A (User 1) -> generatePairingCode() -> code:543045
 * Device B (User 2) -> completePairing(code) -> verifies -> links to User 1
 * After pairing: events relay between all devices of User 1
 */

import crypto from 'crypto';
import type { Database } from '../db/postgres.js';
import type { RedisConnection } from '../db/redis.js';
import { ValidationError } from '../utils/errors.js';
import { logger } from '../utils/logger.js';
import { auditLog, AuditEventType } from '../utils/audit-log.js';

interface PairingSession {
  code: string;
  initiatingUserId: string;
  initiatingDeviceId: string;
  createdAt: number;
  expiresAt: number;
  used: boolean;
  completedAt?: number;
  pairedUserId?: string;
  pairedDeviceId?: string;
}

const PAIRING_CODE_LENGTH = 6;
const PAIRING_CODE_EXPIRY = 10 * 60 * 1000; // 10 minutes (aligned with DB TTL)
const REDIS_PAIRING_PREFIX = 'pairing:';
const REDIS_PAIRING_INDEX_PREFIX = 'pairing_index:';

/**
 * Generate a cryptographically secure 6-digit pairing code
 * Uses crypto.randomBytes() instead of Math.random() for security
 */
function generateCode(): string {
  const buffer = crypto.randomBytes(4);
  const number = buffer.readUInt32BE(0) % 1000000;
  return number.toString().padStart(PAIRING_CODE_LENGTH, '0');
}

/**
 * Initiate pairing - generate a new pairing code
 * Called by Device A (initiator)
 */
export async function initiatePairing(
  redis: RedisConnection,
  userId: string,
  deviceId: string
): Promise<string> {
  const code = generateCode();
  const now = Date.now();

  const pairingSession: PairingSession = {
    code,
    initiatingUserId: userId,
    initiatingDeviceId: deviceId,
    createdAt: now,
    expiresAt: now + PAIRING_CODE_EXPIRY,
    used: false,
  };

  // Store in Redis with expiry
  const key = `${REDIS_PAIRING_PREFIX}${code}`;
  const indexKey = `${REDIS_PAIRING_INDEX_PREFIX}${userId}:${deviceId}`;

  try {
    await redis.client.setEx(key, Math.ceil(PAIRING_CODE_EXPIRY / 1000), JSON.stringify(pairingSession));
    // Also store index for lookup by user+device
    await redis.client.setEx(indexKey, Math.ceil(PAIRING_CODE_EXPIRY / 1000), code);

    logger.info('Pairing code generated', {
      code,
      userId: userId.substring(0, 16) + '...',
      deviceId,
    });

    auditLog(AuditEventType.SECURITY_VIOLATION, {
      userId,
      deviceId,
      details: { event: 'pairing_code_generated', code },
    });

    return code;
  } catch (error) {
    logger.error('Failed to generate pairing code', { error, userId, deviceId });
    throw new ValidationError('Failed to generate pairing code');
  }
}

/**
 * Complete pairing - verify code and link devices
 * Called by Device B (joiner)
 *
 * After this:
 * - Device A (User 1) and Device B (User 2) share same user_id
 * - Events will relay between both devices
 */
export async function completePairing(
  redis: RedisConnection,
  db: Database,
  pairingCode: string,
  joiningUserId: string,
  joiningDeviceId: string
): Promise<{ success: boolean; linkedUserId: string; message: string }> {
  // Validate code format
  if (!/^\d{6}$/.test(pairingCode)) {
    throw new ValidationError('Invalid pairing code format');
  }

  const key = `${REDIS_PAIRING_PREFIX}${pairingCode}`;
  const lockKey = `${REDIS_PAIRING_PREFIX}${pairingCode}:lock`;

  try {
    // ATOMIC LOCK: Use SETNX to prevent race conditions
    // Only one device can acquire the lock and complete pairing
    const lockAcquired = await redis.client.setNX(lockKey, joiningDeviceId);
    if (!lockAcquired) {
      // Another device is already completing this pairing
      throw new ValidationError('Pairing code already used');
    }

    // Set lock expiry to prevent deadlocks (30 seconds should be plenty)
    await redis.client.expire(lockKey, 30);

    try {
      // Retrieve pairing session
      const pairingData = await redis.client.get(key);
      if (!pairingData) {
        auditLog(AuditEventType.SECURITY_VIOLATION, {
          userId: joiningUserId,
          deviceId: joiningDeviceId,
          details: { event: 'pairing_failed', reason: 'code_not_found', code: pairingCode },
        });
        throw new ValidationError('Pairing code not found or expired');
      }

      const pairingSession: PairingSession = JSON.parse(pairingData);

      // Check if code already used (double-check after lock)
      if (pairingSession.used) {
        throw new ValidationError('Pairing code already used');
      }

      // Check if code expired
      if (pairingSession.expiresAt < Date.now()) {
        throw new ValidationError('Pairing code expired');
      }

      // If same user is trying to pair again, they're already paired — treat as success
      if (pairingSession.initiatingUserId === joiningUserId) {
        pairingSession.used = true;
        pairingSession.completedAt = Date.now();
        await redis.client.setEx(key, Math.ceil(PAIRING_CODE_EXPIRY / 1000), JSON.stringify(pairingSession));
        return { success: true, linkedUserId: joiningUserId, message: 'Devices already paired under the same user.' };
      }

      const initiatingUserId = pairingSession.initiatingUserId;
      const initiatingDeviceId = pairingSession.initiatingDeviceId;

      // Mark pairing code as used BEFORE database operation
      // This ensures even if DB fails, the code can't be reused
      pairingSession.used = true;
      pairingSession.completedAt = Date.now();
      pairingSession.pairedUserId = joiningUserId;
      pairingSession.pairedDeviceId = joiningDeviceId;

      await redis.client.setEx(key, Math.ceil(PAIRING_CODE_EXPIRY / 1000), JSON.stringify(pairingSession));

      // PAIRING LOGIC: Link Device B to Device A's user
      // After this, Device B events will relay to Device A (and vice versa)
      // IMPORTANT: All operations are wrapped in a transaction with row-level locking
      // to prevent race conditions with concurrent pairing operations

      const client = await db.pool.connect();
      let updateResult;
      let deviceName: string | null = null;

      try {
        await client.query('BEGIN');

        // Step 1: Ensure initiating user exists
        await client.query('INSERT INTO users (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING', [
          initiatingUserId,
        ]);

        // Step 2: Get and lock existing device names for the target user
        // FOR UPDATE prevents concurrent pairing from reading stale names
        const existingNames = await client.query(
          `SELECT device_name FROM user_devices WHERE user_id = $1 AND device_name IS NOT NULL FOR UPDATE`,
          [initiatingUserId]
        );
        const existingNameSet = new Set(existingNames.rows.map((r: { device_name: string }) => r.device_name));

        // Step 3: Get the current device name for the joining device
        const joiningDeviceResult = await client.query(
          `SELECT device_name FROM user_devices WHERE device_id = $1::uuid FOR UPDATE`,
          [joiningDeviceId]
        );
        deviceName = joiningDeviceResult.rows[0]?.device_name || null;

        // Step 4: If the device has a name, check for conflicts and auto-rename if needed
        if (deviceName && existingNameSet.has(deviceName)) {
          // Find a unique name by appending a number suffix
          const baseName = deviceName.replace(/\s*\(\d+\)$/, ''); // Remove existing suffix like " (2)"
          let suffix = 2;
          let newName = `${baseName} (${suffix})`;
          while (existingNameSet.has(newName)) {
            suffix++;
            newName = `${baseName} (${suffix})`;
          }
          const originalName = deviceName;
          deviceName = newName;
          logger.info('Auto-renamed device due to name conflict', {
            originalName,
            newName: deviceName,
            joiningDeviceId,
          });
        }

        // Step 5: Insert/update device with proper transaction isolation
        // CRITICAL: Reset last_ack_device_seq to 0 on pairing to prevent "Device sequence not monotonic" errors
        // After pairing, the client resets its device_seq counter, so the server must also reset
        updateResult = await client.query(
          `INSERT INTO user_devices (device_id, user_id, device_name, last_ack_device_seq, is_online, last_seen)
           VALUES ($2::uuid, $1, $3, 0, TRUE, NOW())
           ON CONFLICT (device_id)
           DO UPDATE SET user_id = $1, device_name = $3, last_ack_device_seq = 0
           RETURNING user_id`,
          [initiatingUserId, joiningDeviceId, deviceName]
        );

        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }

      // Verify update succeeded
      if (updateResult.rows.length === 0 || updateResult.rows[0].user_id !== initiatingUserId) {
        const actualUserId = updateResult.rows.length > 0 ? updateResult.rows[0].user_id : 'none';
        logger.error('Device link verification failed', {
          joiningDeviceId,
          expectedUserId: initiatingUserId,
          actualUserId,
        });
        throw new ValidationError(`Failed to link devices: device ${joiningDeviceId} not updated to user ${initiatingUserId.substring(0, 12)}...`);
      }

      logger.info('Pairing completed successfully', {
        initiatingUserId: initiatingUserId.substring(0, 16) + '...',
        initiatingDeviceId,
        joiningUserId: joiningUserId.substring(0, 16) + '...',
        joiningDeviceId,
      });

      auditLog(AuditEventType.SECURITY_VIOLATION, {
        userId: initiatingUserId,
        deviceId: initiatingDeviceId,
        details: {
          event: 'pairing_completed',
          pairedWith: joiningDeviceId,
          pairedUserOriginalId: joiningUserId,
        },
      });

      auditLog(AuditEventType.SECURITY_VIOLATION, {
        userId: initiatingUserId, // Now linked to initiator's user
        deviceId: joiningDeviceId,
        details: {
          event: 'device_linked_via_pairing',
          linkedFrom: joiningUserId,
          linkedTo: initiatingUserId,
        },
      });

      return {
        success: true,
        linkedUserId: initiatingUserId,
        message: `Device paired successfully. Events will now sync between devices of user ${initiatingUserId.substring(0, 8)}...`,
      };
    } finally {
      // Always release the lock, even if pairing fails
      await redis.client.del(lockKey).catch((err) => {
        logger.warn('Failed to release pairing lock', { lockKey, error: err });
      });
    }
  } catch (error) {
    const pgErrorCode = (error as any)?.code;
    const errorMessage = error instanceof Error ? (error.message || 'Failed to complete pairing') : String(error);

    logger.error(`Failed to complete pairing: ${errorMessage}`, {
      errorType: error instanceof Error ? error.constructor.name : typeof error,
      errorMessage,
      pgErrorCode,
      code: pairingCode,
      joiningUserId,
      joiningDeviceId,
    }, error);

    auditLog(AuditEventType.SECURITY_VIOLATION, {
      userId: joiningUserId,
      deviceId: joiningDeviceId,
      details: {
        event: 'pairing_failed',
        error: errorMessage,
      },
    });
    if (pgErrorCode === '23505') {
      throw new ValidationError('Device name already exists on the target account. Please rename this device and try pairing again.');
    }

    if (error instanceof ValidationError) {
      throw error;
    }

    const message = error instanceof Error
      ? (error.message || 'Failed to complete pairing')
      : 'Failed to complete pairing';

    throw new ValidationError(message);
  }
}

/**
 * Get pairing code status (for debugging/UI)
 */
export async function getPairingStatus(redis: RedisConnection, pairingCode: string): Promise<PairingSession | null> {
  const key = `${REDIS_PAIRING_PREFIX}${pairingCode}`;

  try {
    const data = await redis.client.get(key);
    if (!data) {
      return null;
    }
    return JSON.parse(data);
  } catch (error) {
    logger.error('Failed to get pairing status', { error, code: pairingCode });
    return null;
  }
}

/**
 * Cancel pairing code (before it's used)
 */
export async function cancelPairing(
  redis: RedisConnection,
  userId: string,
  pairingCode: string
): Promise<boolean> {
  const key = `${REDIS_PAIRING_PREFIX}${pairingCode}`;

  try {
    const data = await redis.client.get(key);
    if (!data) {
      return false;
    }

    const pairingSession: PairingSession = JSON.parse(data);

    // Only the initiator can cancel
    if (pairingSession.initiatingUserId !== userId) {
      throw new ValidationError('Only pairing initiator can cancel');
    }

    // Can't cancel already-used codes
    if (pairingSession.used) {
      throw new ValidationError('Cannot cancel pairing that is already completed');
    }

    // Delete from Redis
    await redis.client.del(key);

    logger.info('Pairing code cancelled', {
      userId: userId.substring(0, 16) + '...',
      code: pairingCode,
    });

    auditLog(AuditEventType.SECURITY_VIOLATION, {
      userId,
      details: {
        event: 'pairing_cancelled',
        code: pairingCode,
      },
    });

    return true;
  } catch (error) {
    logger.error('Failed to cancel pairing', { error, userId, code: pairingCode });
    if (error instanceof ValidationError) {
      throw error;
    }
    return false;
  }
}

export default {
  initiatePairing,
  completePairing,
  getPairingStatus,
  cancelPairing,
  generateCode,
};
