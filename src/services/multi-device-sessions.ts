/**
 * Multi-Device Session Manager
 * 
 * Manages sessions grouped by user_id, with per-device tracking
 * Structure: sessions[user_id][device_id] = SessionState
 * 
 * Key operations:
 * - Add device session
 * - Remove device session
 * - Get all devices for user
 * - Broadcast device status changes
 */

import type { SessionState } from '../types/index.js';
import type { WebSocket } from 'ws';
import { logger } from '../utils/logger.js';

interface UserSessions {
  [device_id: string]: SessionState;
}

export class MultiDeviceSessionManager {
  // Sessions organized by user_id -> device_id -> SessionState
  private sessions = new Map<string, UserSessions>();
  
  // Track WebSocket connections per session for cleanup
  private sessionWebSockets = new Map<string, WebSocket>(); // Key: `${user_id}:${device_id}`

  /**
   * Add or update a session
   */
  addSession(userId: string, deviceId: string, sessionState: SessionState, ws: WebSocket): void {
    if (!this.sessions.has(userId)) {
      this.sessions.set(userId, {});
    }

    const userSessions = this.sessions.get(userId)!;
    userSessions[deviceId] = sessionState;
    this.sessionWebSockets.set(`${userId}:${deviceId}`, ws);

    logger.info('Session added', {
      userId: userId.substring(0, 16) + '...',
      deviceId,
      totalDevicesForUser: Object.keys(userSessions).length,
    });
  }

  /**
   * Remove a session
   */
  removeSession(userId: string, deviceId: string): SessionState | null {
    const userSessions = this.sessions.get(userId);
    if (!userSessions) {
      return null;
    }

    const session = userSessions[deviceId];
    delete userSessions[deviceId];
    this.sessionWebSockets.delete(`${userId}:${deviceId}`);

    // Clean up empty user entry
    if (Object.keys(userSessions).length === 0) {
      this.sessions.delete(userId);
    }

    if (session) {
      logger.info('Session removed', {
        userId: userId.substring(0, 16) + '...',
        deviceId,
        remainingDevicesForUser: Object.keys(userSessions).length,
      });
    }

    return session || null;
  }

  /**
   * Get session by user and device
   */
  getSession(userId: string, deviceId: string): SessionState | null {
    return this.sessions.get(userId)?.[deviceId] || null;
  }

  /**
   * Get all sessions for a user
   */
  getUserSessions(userId: string): Map<string, SessionState> {
    const userSessions = this.sessions.get(userId) || {};
    return new Map(Object.entries(userSessions));
  }

  /**
   * Get all online devices for a user
   */
  getOnlineDevices(userId: string): string[] {
    const userSessions = this.sessions.get(userId) || {};
    return Object.keys(userSessions);
  }

  /**
   * Get all users with active sessions
   */
  getAllUsers(): string[] {
    return Array.from(this.sessions.keys());
  }

  /**
   * Get total session count across all users
   */
  getTotalSessions(): number {
    let total = 0;
    for (const userSessions of this.sessions.values()) {
      total += Object.keys(userSessions).length;
    }
    return total;
  }

  /**
   * Get session statistics
   */
  getStats() {
    return {
      total_users: this.sessions.size,
      total_sessions: this.getTotalSessions(),
      users_with_multiple_devices: Array.from(this.sessions.entries())
        .filter(([_, sessions]) => Object.keys(sessions).length > 1)
        .length,
    };
  }

  /**
   * Get WebSocket for session (for sending messages)
   */
  getWebSocket(userId: string, deviceId: string): WebSocket | null {
    return this.sessionWebSockets.get(`${userId}:${deviceId}`) || null;
  }

  /**
   * Broadcast message to all devices of a user (except optionally one device)
   */
  broadcastToUser(
    userId: string,
    message: string,
    excludeDeviceId?: string
  ): { sent: number; failed: number } {
    const userSessions = this.sessions.get(userId) || {};
    let sent = 0;
    let failed = 0;

    for (const [deviceId, _session] of Object.entries(userSessions)) {
      if (excludeDeviceId && deviceId === excludeDeviceId) {
        continue;
      }

      const ws = this.getWebSocket(userId, deviceId);
      if (ws && ws.readyState === ws.OPEN) {
        try {
          ws.send(message);
          sent++;
        } catch (error) {
          logger.error('Failed to send message to device', { deviceId }, error);
          failed++;
        }
      } else {
        failed++;
      }
    }

    return { sent, failed };
  }

  /**
   * Invalidate all sessions for a user (logout all devices)
   */
  invalidateAllUserSessions(userId: string): number {
    const userSessions = this.sessions.get(userId);
    if (!userSessions) {
      return 0;
    }

    const deviceIds = Object.keys(userSessions);
    for (const deviceId of deviceIds) {
      this.removeSession(userId, deviceId);
    }

    logger.info('All sessions invalidated for user', {
      userId: userId.substring(0, 16) + '...',
      invalidatedDevices: deviceIds.length,
    });

    return deviceIds.length;
  }

  /**
   * Invalidate specific device for user
   */
  invalidateDevice(userId: string, deviceId: string): boolean {
    const ws = this.getWebSocket(userId, deviceId);
    if (ws) {
      ws.close(1000, 'Device revoked');
    }
    return this.removeSession(userId, deviceId) !== null;
  }

  /**
   * Check if user has session from another device
   * (useful for detecting concurrent logins)
   */
  hasOtherSessions(userId: string, excludeDeviceId: string): boolean {
    const userSessions = this.sessions.get(userId);
    if (!userSessions) {
      return false;
    }

    for (const deviceId of Object.keys(userSessions)) {
      if (deviceId !== excludeDeviceId) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get all sessions as a flat Map (for backward compatibility)
   * Key: deviceId, Value: SessionState
   */
  getAllSessionsFlat(): Map<string, SessionState> {
    const flatMap = new Map<string, SessionState>();

    for (const userSessions of this.sessions.values()) {
      for (const [deviceId, session] of Object.entries(userSessions)) {
        flatMap.set(deviceId, session);
      }
    }

    return flatMap;
  }

  /**
   * Clean up expired sessions
   */
  cleanup(expirationTime: number): number {
    const now = Date.now();
    let cleaned = 0;

    for (const [userId, userSessions] of this.sessions.entries()) {
      for (const [deviceId, session] of Object.entries(userSessions)) {
        if (now - session.createdAt > expirationTime) {
          logger.info('Cleaning up expired session', {
            userId: userId.substring(0, 16) + '...',
            deviceId,
            age: now - session.createdAt,
          });
          this.removeSession(userId, deviceId);
          cleaned++;
        }
      }
    }

    return cleaned;
  }
}

export default MultiDeviceSessionManager;
