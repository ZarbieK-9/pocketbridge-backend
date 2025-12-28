/**
 * Connection Limits
 *
 * Enforces maximum concurrent connections per user/device
 */

import { logger } from '../utils/logger.js';

interface ConnectionCounts {
  [key: string]: number;
}

const MAX_CONNECTIONS_PER_USER = 10;
const MAX_CONNECTIONS_PER_DEVICE = 3;

const userConnections = new Map<string, number>();
const deviceConnections = new Map<string, number>();

/**
 * Check if new connection is allowed
 */
export function checkConnectionLimit(
  userId: string,
  deviceId: string
): { allowed: boolean; error?: string } {
  const userCount = userConnections.get(userId) || 0;
  const deviceCount = deviceConnections.get(deviceId) || 0;

  if (userCount >= MAX_CONNECTIONS_PER_USER) {
    logger.warn('User connection limit exceeded', { userId: userId.substring(0, 16) + '...' });
    return {
      allowed: false,
      error: 'Maximum connections per user exceeded',
    };
  }

  if (deviceCount >= MAX_CONNECTIONS_PER_DEVICE) {
    logger.warn('Device connection limit exceeded', { deviceId });
    return {
      allowed: false,
      error: 'Maximum connections per device exceeded',
    };
  }

  return { allowed: true };
}

/**
 * Increment connection count
 */
export function incrementConnection(userId: string, deviceId: string): void {
  const userCount = userConnections.get(userId) || 0;
  const deviceCount = deviceConnections.get(deviceId) || 0;

  userConnections.set(userId, userCount + 1);
  deviceConnections.set(deviceId, deviceCount + 1);
}

/**
 * Decrement connection count
 */
export function decrementConnection(userId: string, deviceId: string): void {
  const userCount = userConnections.get(userId) || 0;
  const deviceCount = deviceConnections.get(deviceId) || 0;

  if (userCount > 0) {
    userConnections.set(userId, userCount - 1);
  }
  if (deviceCount > 0) {
    deviceConnections.set(deviceId, deviceCount - 1);
  }
}
