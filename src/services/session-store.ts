/**
 * Session Store Service
 *
 * Stores sessions in Redis for horizontal scaling
 * Falls back to in-memory if Redis unavailable
 */

import type { RedisConnection } from '../db/redis.js';
import type { SessionState } from '../types/index.js';
import { logger } from '../utils/logger.js';

const SESSION_KEY_PREFIX = 'session:';
const SESSION_TTL = 24 * 60 * 60; // 24 hours in seconds

/**
 * Store session in Redis
 */
export async function storeSession(
  redis: RedisConnection,
  sessionState: SessionState
): Promise<void> {
  try {
    const key = `${SESSION_KEY_PREFIX}${sessionState.deviceId}`;
    const value = JSON.stringify({
      userId: sessionState.userId,
      deviceId: sessionState.deviceId,
      lastAckDeviceSeq: sessionState.lastAckDeviceSeq,
      createdAt: sessionState.createdAt,
      // Note: Session keys are NOT stored (they're in memory only for security)
      // Keys are re-derived on reconnect if needed
    });

    await redis.client.setEx(key, SESSION_TTL, value);
  } catch (error) {
    logger.error(
      'Failed to store session in Redis',
      { deviceId: sessionState.deviceId },
      error instanceof Error ? error : new Error(String(error))
    );
    // Fallback: continue without Redis storage
  }
}

/**
 * Load session from Redis
 */
export async function loadSession(
  redis: RedisConnection,
  deviceId: string
): Promise<Partial<SessionState> | null> {
  try {
    const key = `${SESSION_KEY_PREFIX}${deviceId}`;
    const value = await redis.client.get(key);

    if (!value) {
      return null;
    }

    return JSON.parse(value) as Partial<SessionState>;
  } catch (error) {
    logger.error(
      'Failed to load session from Redis',
      { deviceId },
      error instanceof Error ? error : new Error(String(error))
    );
    return null;
  }
}

/**
 * Delete session from Redis
 */
export async function deleteSession(redis: RedisConnection, deviceId: string): Promise<void> {
  try {
    const key = `${SESSION_KEY_PREFIX}${deviceId}`;
    await redis.client.del(key);
  } catch (error) {
    logger.error(
      'Failed to delete session from Redis',
      { deviceId },
      error instanceof Error ? error : new Error(String(error))
    );
  }
}

/**
 * Update session in Redis (refresh TTL)
 */
export async function updateSession(
  redis: RedisConnection,
  sessionState: SessionState
): Promise<void> {
  await storeSession(redis, sessionState);
}
