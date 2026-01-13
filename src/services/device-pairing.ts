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
const PAIRING_CODE_EXPIRY = 5 * 60 * 1000; // 5 minutes
const REDIS_PAIRING_PREFIX = 'pairing:';
const REDIS_PAIRING_INDEX_PREFIX = 'pairing_index:';

/**
 * Generate a 6-digit pairing code
 */
function generateCode(): string {
  return Math.floor(Math.random() * 1000000)
    .toString()
    .padStart(PAIRING_CODE_LENGTH, '0');
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

    // Check if code already used
    if (pairingSession.used) {
      throw new ValidationError('Pairing code already used');
    }

    // Check if code expired
    if (pairingSession.expiresAt < Date.now()) {
      throw new ValidationError('Pairing code expired');
    }

    // Check if same user trying to pair with self
    if (pairingSession.initiatingUserId === joiningUserId) {
      throw new ValidationError('Cannot pair device with same user');
    }

    const initiatingUserId = pairingSession.initiatingUserId;
    const initiatingDeviceId = pairingSession.initiatingDeviceId;

    // PAIRING LOGIC: Link Device B to Device A's user
    // After this, Device B events will relay to Device A (and vice versa)

    // Step 1: Update Device B's user_id in database
    // This makes Device B part of User A's device group
    await db.pool.query(
      `UPDATE user_devices 
       SET user_id = $1
       WHERE device_id = $2 AND user_id = $3`,
      [initiatingUserId, joiningDeviceId, joiningUserId]
    );

    // Verify update succeeded
    const updateCheck = await db.pool.query(
      `SELECT user_id FROM user_devices WHERE device_id = $1`,
      [joiningDeviceId]
    );

    if (updateCheck.rows.length === 0 || updateCheck.rows[0].user_id !== initiatingUserId) {
      throw new ValidationError('Failed to link devices');
    }

    // Step 2: Mark pairing code as used
    pairingSession.used = true;
    pairingSession.completedAt = Date.now();
    pairingSession.pairedUserId = joiningUserId;
    pairingSession.pairedDeviceId = joiningDeviceId;

    await redis.client.setEx(key, Math.ceil(PAIRING_CODE_EXPIRY / 1000), JSON.stringify(pairingSession));

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
  } catch (error) {
    logger.error('Failed to complete pairing', {
      error,
      code: pairingCode,
      joiningUserId,
      joiningDeviceId,
    });

    auditLog(AuditEventType.SECURITY_VIOLATION, {
      userId: joiningUserId,
      deviceId: joiningDeviceId,
      details: {
        event: 'pairing_failed',
        error: error instanceof Error ? error.message : String(error),
      },
    });

    if (error instanceof ValidationError) {
      throw error;
    }
    throw new ValidationError('Failed to complete pairing');
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
