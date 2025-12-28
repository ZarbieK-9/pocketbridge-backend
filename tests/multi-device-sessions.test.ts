/**
 * Multi-Device Session Manager Tests
 * 
 * Comprehensive tests for session management across multiple devices
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { MultiDeviceSessionManager } from '../src/services/multi-device-sessions.js';
import type { SessionState } from '../src/types/index.js';
import type { WebSocket } from 'ws';

// Mock WebSocket - must match WebSocket.OPEN constant
class MockWebSocket {
  static readonly OPEN = 1;
  static readonly CLOSED = 3;
  readyState = MockWebSocket.OPEN;
  send = vi.fn();
  close = vi.fn();
  on = vi.fn();
  
  // Add OPEN as instance property for ws.readyState === ws.OPEN check
  get OPEN() {
    return MockWebSocket.OPEN;
  }
}

describe('MultiDeviceSessionManager', () => {
  let manager: MultiDeviceSessionManager;
  let mockWs1: MockWebSocket;
  let mockWs2: MockWebSocket;
  let mockWs3: MockWebSocket;
  const userId1 = 'a'.repeat(64);
  const userId2 = 'b'.repeat(64);
  const deviceId1 = '550e8400-e29b-41d4-a716-446655440000';
  const deviceId2 = '550e8400-e29b-41d4-a716-446655440001';
  const deviceId3 = '550e8400-e29b-41d4-a716-446655440002';

  function createSessionState(userId: string, deviceId: string, lastAck: number = 0): SessionState {
    return {
      userId,
      deviceId,
      sessionKeys: {
        clientKey: Buffer.from('client-key'),
        serverKey: Buffer.from('server-key'),
      },
      lastAckDeviceSeq: lastAck,
      createdAt: Date.now(),
    };
  }

  beforeEach(() => {
    manager = new MultiDeviceSessionManager();
    mockWs1 = new MockWebSocket();
    mockWs2 = new MockWebSocket();
    mockWs3 = new MockWebSocket();
    vi.clearAllMocks();
  });

  describe('addSession', () => {
    it('should add a session for a new user', () => {
      const session = createSessionState(userId1, deviceId1);
      manager.addSession(userId1, deviceId1, session, mockWs1 as any);

      const retrieved = manager.getSession(userId1, deviceId1);
      expect(retrieved).toEqual(session);
      expect(manager.getAllUsers()).toContain(userId1);
    });

    it('should add multiple devices for the same user', () => {
      const session1 = createSessionState(userId1, deviceId1);
      const session2 = createSessionState(userId1, deviceId2);

      manager.addSession(userId1, deviceId1, session1, mockWs1 as any);
      manager.addSession(userId1, deviceId2, session2, mockWs2 as any);

      expect(manager.getSession(userId1, deviceId1)).toEqual(session1);
      expect(manager.getSession(userId1, deviceId2)).toEqual(session2);
      expect(manager.getOnlineDevices(userId1)).toHaveLength(2);
    });

    it('should update existing session when adding same device again', () => {
      const session1 = createSessionState(userId1, deviceId1, 0);
      const session2 = createSessionState(userId1, deviceId1, 5);

      manager.addSession(userId1, deviceId1, session1, mockWs1 as any);
      manager.addSession(userId1, deviceId1, session2, mockWs1 as any);

      const retrieved = manager.getSession(userId1, deviceId1);
      expect(retrieved?.lastAckDeviceSeq).toBe(5);
    });
  });

  describe('removeSession', () => {
    it('should remove a session', () => {
      const session = createSessionState(userId1, deviceId1);
      manager.addSession(userId1, deviceId1, session, mockWs1 as any);

      const removed = manager.removeSession(userId1, deviceId1);
      expect(removed).toEqual(session);
      expect(manager.getSession(userId1, deviceId1)).toBeNull();
    });

    it('should return null when removing non-existent session', () => {
      const removed = manager.removeSession(userId1, deviceId1);
      expect(removed).toBeNull();
    });

    it('should clean up user entry when last device is removed', () => {
      const session = createSessionState(userId1, deviceId1);
      manager.addSession(userId1, deviceId1, session, mockWs1 as any);

      manager.removeSession(userId1, deviceId1);
      expect(manager.getAllUsers()).not.toContain(userId1);
    });

    it('should keep user entry when other devices remain', () => {
      const session1 = createSessionState(userId1, deviceId1);
      const session2 = createSessionState(userId1, deviceId2);

      manager.addSession(userId1, deviceId1, session1, mockWs1 as any);
      manager.addSession(userId1, deviceId2, session2, mockWs2 as any);

      manager.removeSession(userId1, deviceId1);
      expect(manager.getAllUsers()).toContain(userId1);
      expect(manager.getSession(userId1, deviceId2)).toEqual(session2);
    });
  });

  describe('getUserSessions', () => {
    it('should return all sessions for a user', () => {
      const session1 = createSessionState(userId1, deviceId1);
      const session2 = createSessionState(userId1, deviceId2);

      manager.addSession(userId1, deviceId1, session1, mockWs1 as any);
      manager.addSession(userId1, deviceId2, session2, mockWs2 as any);

      const sessions = manager.getUserSessions(userId1);
      expect(sessions.size).toBe(2);
      expect(sessions.get(deviceId1)).toEqual(session1);
      expect(sessions.get(deviceId2)).toEqual(session2);
    });

    it('should return empty map for user with no sessions', () => {
      const sessions = manager.getUserSessions(userId1);
      expect(sessions.size).toBe(0);
    });
  });

  describe('getOnlineDevices', () => {
    it('should return list of online device IDs', () => {
      manager.addSession(userId1, deviceId1, createSessionState(userId1, deviceId1), mockWs1 as any);
      manager.addSession(userId1, deviceId2, createSessionState(userId1, deviceId2), mockWs2 as any);

      const devices = manager.getOnlineDevices(userId1);
      expect(devices).toContain(deviceId1);
      expect(devices).toContain(deviceId2);
      expect(devices).toHaveLength(2);
    });

    it('should return empty array for user with no devices', () => {
      const devices = manager.getOnlineDevices(userId1);
      expect(devices).toEqual([]);
    });
  });

  describe('getAllUsers', () => {
    it('should return all users with active sessions', () => {
      manager.addSession(userId1, deviceId1, createSessionState(userId1, deviceId1), mockWs1 as any);
      manager.addSession(userId2, deviceId2, createSessionState(userId2, deviceId2), mockWs2 as any);

      const users = manager.getAllUsers();
      expect(users).toContain(userId1);
      expect(users).toContain(userId2);
      expect(users).toHaveLength(2);
    });

    it('should return empty array when no users', () => {
      const users = manager.getAllUsers();
      expect(users).toEqual([]);
    });
  });

  describe('getTotalSessions', () => {
    it('should count total sessions across all users', () => {
      manager.addSession(userId1, deviceId1, createSessionState(userId1, deviceId1), mockWs1 as any);
      manager.addSession(userId1, deviceId2, createSessionState(userId1, deviceId2), mockWs2 as any);
      manager.addSession(userId2, deviceId3, createSessionState(userId2, deviceId3), mockWs3 as any);

      expect(manager.getTotalSessions()).toBe(3);
    });

    it('should return 0 when no sessions', () => {
      expect(manager.getTotalSessions()).toBe(0);
    });
  });

  describe('getStats', () => {
    it('should return correct statistics', () => {
      manager.addSession(userId1, deviceId1, createSessionState(userId1, deviceId1), mockWs1 as any);
      manager.addSession(userId1, deviceId2, createSessionState(userId1, deviceId2), mockWs2 as any);
      manager.addSession(userId2, deviceId3, createSessionState(userId2, deviceId3), mockWs3 as any);

      const stats = manager.getStats();
      expect(stats.total_users).toBe(2);
      expect(stats.total_sessions).toBe(3);
      expect(stats.users_with_multiple_devices).toBe(1); // userId1 has 2 devices
    });
  });

  describe('getWebSocket', () => {
    it('should return WebSocket for session', () => {
      const session = createSessionState(userId1, deviceId1);
      manager.addSession(userId1, deviceId1, session, mockWs1 as any);

      const ws = manager.getWebSocket(userId1, deviceId1);
      expect(ws).toBe(mockWs1);
    });

    it('should return null for non-existent session', () => {
      const ws = manager.getWebSocket(userId1, deviceId1);
      expect(ws).toBeNull();
    });
  });

  describe('broadcastToUser', () => {
    it('should send message to all devices of a user', async () => {
      mockWs1.readyState = MockWebSocket.OPEN;
      mockWs2.readyState = MockWebSocket.OPEN;

      manager.addSession(userId1, deviceId1, createSessionState(userId1, deviceId1), mockWs1 as any);
      manager.addSession(userId1, deviceId2, createSessionState(userId1, deviceId2), mockWs2 as any);

      const message = JSON.stringify({ type: 'test', data: 'hello' });
      const result = await manager.broadcastToUser(userId1, message);

      expect(result.sent).toBe(2);
      expect(result.failed).toBe(0);
      expect(mockWs1.send).toHaveBeenCalledWith(message);
      expect(mockWs2.send).toHaveBeenCalledWith(message);
    });

    it('should exclude specified device from broadcast', async () => {
      mockWs1.readyState = MockWebSocket.OPEN;
      mockWs2.readyState = MockWebSocket.OPEN;

      manager.addSession(userId1, deviceId1, createSessionState(userId1, deviceId1), mockWs1 as any);
      manager.addSession(userId1, deviceId2, createSessionState(userId1, deviceId2), mockWs2 as any);

      const message = JSON.stringify({ type: 'test', data: 'hello' });
      const result = await manager.broadcastToUser(userId1, message, deviceId1);

      expect(result.sent).toBe(1);
      expect(mockWs1.send).not.toHaveBeenCalled();
      expect(mockWs2.send).toHaveBeenCalledWith(message);
    });

    it('should not send to closed WebSocket connections', async () => {
      mockWs1.readyState = MockWebSocket.CLOSED;
      mockWs2.readyState = MockWebSocket.OPEN;

      manager.addSession(userId1, deviceId1, createSessionState(userId1, deviceId1), mockWs1 as any);
      manager.addSession(userId1, deviceId2, createSessionState(userId1, deviceId2), mockWs2 as any);

      const message = JSON.stringify({ type: 'test', data: 'hello' });
      const result = await manager.broadcastToUser(userId1, message);

      expect(result.sent).toBe(1);
      expect(result.failed).toBe(0);
      expect(mockWs1.send).not.toHaveBeenCalled();
      expect(mockWs2.send).toHaveBeenCalled();
    });

    it('should handle send errors gracefully', async () => {
      mockWs1.readyState = MockWebSocket.OPEN;
      mockWs1.send.mockImplementation(() => {
        throw new Error('Send failed');
      });

      manager.addSession(userId1, deviceId1, createSessionState(userId1, deviceId1), mockWs1 as any);

      const message = JSON.stringify({ type: 'test', data: 'hello' });
      const result = await manager.broadcastToUser(userId1, message);

      expect(result.sent).toBe(0);
      expect(result.failed).toBe(1);
    });

    it('should return zero counts when no devices', async () => {
      const message = JSON.stringify({ type: 'test', data: 'hello' });
      const result = await manager.broadcastToUser(userId1, message);

      expect(result.sent).toBe(0);
      expect(result.failed).toBe(0);
    });
  });

  describe('invalidateAllUserSessions', () => {
    it('should remove all sessions for a user', () => {
      manager.addSession(userId1, deviceId1, createSessionState(userId1, deviceId1), mockWs1 as any);
      manager.addSession(userId1, deviceId2, createSessionState(userId1, deviceId2), mockWs2 as any);

      const count = manager.invalidateAllUserSessions(userId1);

      expect(count).toBe(2);
      expect(manager.getSession(userId1, deviceId1)).toBeNull();
      expect(manager.getSession(userId1, deviceId2)).toBeNull();
      expect(manager.getAllUsers()).not.toContain(userId1);
    });

    it('should return 0 for user with no sessions', () => {
      const count = manager.invalidateAllUserSessions(userId1);
      expect(count).toBe(0);
    });
  });

  describe('invalidateDevice', () => {
    it('should close WebSocket and remove session', () => {
      const session = createSessionState(userId1, deviceId1);
      manager.addSession(userId1, deviceId1, session, mockWs1 as any);

      const result = manager.invalidateDevice(userId1, deviceId1);

      expect(result).toBe(true);
      expect(mockWs1.close).toHaveBeenCalledWith(1000, 'Device revoked');
      expect(manager.getSession(userId1, deviceId1)).toBeNull();
    });

    it('should return false for non-existent device', () => {
      const result = manager.invalidateDevice(userId1, deviceId1);
      expect(result).toBe(false);
    });
  });

  describe('hasOtherSessions', () => {
    it('should return true when user has other devices', () => {
      manager.addSession(userId1, deviceId1, createSessionState(userId1, deviceId1), mockWs1 as any);
      manager.addSession(userId1, deviceId2, createSessionState(userId1, deviceId2), mockWs2 as any);

      expect(manager.hasOtherSessions(userId1, deviceId1)).toBe(true);
    });

    it('should return false when user has only one device', () => {
      manager.addSession(userId1, deviceId1, createSessionState(userId1, deviceId1), mockWs1 as any);

      expect(manager.hasOtherSessions(userId1, deviceId1)).toBe(false);
    });

    it('should return false for non-existent user', () => {
      expect(manager.hasOtherSessions(userId1, deviceId1)).toBe(false);
    });
  });

  describe('getAllSessionsFlat', () => {
    it('should return flat map of all sessions', () => {
      const session1 = createSessionState(userId1, deviceId1);
      const session2 = createSessionState(userId1, deviceId2);
      const session3 = createSessionState(userId2, deviceId3);

      manager.addSession(userId1, deviceId1, session1, mockWs1 as any);
      manager.addSession(userId1, deviceId2, session2, mockWs2 as any);
      manager.addSession(userId2, deviceId3, session3, mockWs3 as any);

      const flatMap = manager.getAllSessionsFlat();
      expect(flatMap.size).toBe(3);
      expect(flatMap.get(deviceId1)).toEqual(session1);
      expect(flatMap.get(deviceId2)).toEqual(session2);
      expect(flatMap.get(deviceId3)).toEqual(session3);
    });

    it('should return empty map when no sessions', () => {
      const flatMap = manager.getAllSessionsFlat();
      expect(flatMap.size).toBe(0);
    });
  });

  describe('cleanup', () => {
    it('should remove expired sessions', () => {
      const oldSession = createSessionState(userId1, deviceId1);
      oldSession.createdAt = Date.now() - 25 * 60 * 60 * 1000; // 25 hours ago

      const newSession = createSessionState(userId1, deviceId2);
      newSession.createdAt = Date.now() - 1 * 60 * 60 * 1000; // 1 hour ago

      manager.addSession(userId1, deviceId1, oldSession, mockWs1 as any);
      manager.addSession(userId1, deviceId2, newSession, mockWs2 as any);

      const expirationTime = 24 * 60 * 60 * 1000; // 24 hours
      const cleaned = manager.cleanup(expirationTime);

      expect(cleaned).toBe(1);
      expect(manager.getSession(userId1, deviceId1)).toBeNull();
      expect(manager.getSession(userId1, deviceId2)).toEqual(newSession);
    });

    it('should not remove non-expired sessions', () => {
      const session = createSessionState(userId1, deviceId1);
      session.createdAt = Date.now() - 1 * 60 * 60 * 1000; // 1 hour ago

      manager.addSession(userId1, deviceId1, session, mockWs1 as any);

      const expirationTime = 24 * 60 * 60 * 1000; // 24 hours
      const cleaned = manager.cleanup(expirationTime);

      expect(cleaned).toBe(0);
      expect(manager.getSession(userId1, deviceId1)).toEqual(session);
    });
  });
});

