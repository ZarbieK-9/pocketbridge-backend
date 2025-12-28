/**
 * Device Relay Service
 *
 * Core relay system that connects devices of the same user.
 * - Automatically routes messages between user's devices
 * - Ensures strict user isolation (users only see their own devices)
 * - Always active (runs continuously)
 * - Supports multiple users simultaneously
 */

import type { SessionState, EncryptedEvent } from '../types/index.js';
import type { WebSocket } from 'ws';
import MultiDeviceSessionManager from './multi-device-sessions.js';
import { logger } from '../utils/logger.js';

export class DeviceRelay {
  private sessionManager: MultiDeviceSessionManager;

  constructor(sessionManager: MultiDeviceSessionManager) {
    this.sessionManager = sessionManager;
  }

  /**
   * Relay an event from one device to all other devices of the same user
   * This is the core relay function - it ensures user isolation
   * Optimized: Uses parallel WebSocket sends for better performance
   */
  async relayEventToUserDevices(
    event: EncryptedEvent,
    senderDeviceId: string,
    senderUserId: string
  ): Promise<{ relayed: number; failed: number; targetDevices: string[] }> {
    // CRITICAL: Verify user_id matches sender (prevent cross-user relay)
    if (event.user_id !== senderUserId) {
      logger.error('SECURITY: Attempted cross-user relay blocked', {
        eventUserId: event.user_id.substring(0, 16) + '...',
        senderUserId: senderUserId.substring(0, 16) + '...',
        deviceId: senderDeviceId,
      });
      return { relayed: 0, failed: 0, targetDevices: [] };
    }

    // Get all online devices for this user
    const userDevices = this.sessionManager.getOnlineDevices(senderUserId);
    const targetDevices = userDevices.filter(deviceId => deviceId !== senderDeviceId);

    if (targetDevices.length === 0) {
      // Edge case: User has only one device active, or other devices haven't connected yet
      // This is normal and expected - events are still stored for replay when devices connect later
      logger.debug(
        'No other devices online for user (single device or devices not yet connected)',
        {
          userId: senderUserId.substring(0, 16) + '...',
          senderDeviceId,
          message: 'Event will be stored for replay when other devices connect',
        }
      );
      return { relayed: 0, failed: 0, targetDevices: [] };
    }

    logger.info('Relaying event to user devices', {
      userId: senderUserId.substring(0, 16) + '...',
      senderDeviceId,
      targetDevices,
      eventType: event.type,
    });

    // Relay to all other devices (parallel sends)
    const message = JSON.stringify({
      type: 'event',
      payload: event,
    });

    const result = await this.sessionManager.broadcastToUser(
      senderUserId,
      message,
      senderDeviceId // Exclude sender
    );

    return {
      relayed: result.sent,
      failed: result.failed,
      targetDevices,
    };
  }

  /**
   * Get all online devices for a user (user can only see their own devices)
   */
  getUserDevices(userId: string): Array<{ deviceId: string; sessionState: SessionState }> {
    const userSessions = this.sessionManager.getUserSessions(userId);
    const devices: Array<{ deviceId: string; sessionState: SessionState }> = [];

    for (const [deviceId, sessionState] of userSessions.entries()) {
      const ws = this.sessionManager.getWebSocket(userId, deviceId);
      // Only include devices with active WebSocket connections
      if (ws && ws.readyState === ws.OPEN) {
        devices.push({ deviceId, sessionState });
      }
    }

    return devices;
  }

  /**
   * Check if user has multiple devices online
   */
  hasMultipleDevices(userId: string): boolean {
    const devices = this.getUserDevices(userId);
    return devices.length > 1;
  }

  /**
   * Send a direct message to a specific device of a user
   * Used for device-to-device communication
   */
  sendToDevice(userId: string, targetDeviceId: string, message: unknown): boolean {
    const ws = this.sessionManager.getWebSocket(userId, targetDeviceId);
    if (!ws || ws.readyState !== ws.OPEN) {
      logger.warn('Cannot send to device: not connected', {
        userId: userId.substring(0, 16) + '...',
        targetDeviceId,
      });
      return false;
    }

    try {
      ws.send(JSON.stringify(message));
      return true;
    } catch (error) {
      logger.error(
        'Failed to send message to device',
        {
          userId: userId.substring(0, 16) + '...',
          targetDeviceId,
        },
        error instanceof Error ? error : new Error(String(error))
      );
      return false;
    }
  }

  /**
   * Broadcast a system message to all devices of a user
   * (e.g., device status changes, presence updates)
   * Optimized: Uses parallel WebSocket sends
   */
  async broadcastSystemMessage(
    userId: string,
    message: { type: string; payload: unknown },
    excludeDeviceId?: string
  ): Promise<{ sent: number; failed: number }> {
    const messageStr = JSON.stringify(message);
    return await this.sessionManager.broadcastToUser(userId, messageStr, excludeDeviceId);
  }

  /**
   * Verify user isolation - ensure a device can only access its own user's data
   */
  verifyUserAccess(userId: string, deviceId: string, requestedUserId: string): boolean {
    if (userId !== requestedUserId) {
      logger.warn('User isolation violation attempted', {
        deviceUserId: userId.substring(0, 16) + '...',
        requestedUserId: requestedUserId.substring(0, 16) + '...',
        deviceId,
      });
      return false;
    }
    return true;
  }
}

export default DeviceRelay;
