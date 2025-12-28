/**
 * Device Relay Service Tests
 * 
 * Tests for device relay, user isolation, and event routing
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import DeviceRelay from '../src/services/device-relay.js';
import type { SessionState } from '../src/types/index.js';
import MultiDeviceSessionManager from '../src/services/multi-device-sessions.js';

// Mock dependencies
const mockRedis: Partial<RedisConnection> = {
  client: {
    publish: vi.fn().mockResolvedValue(1),
  } as any,
};

const mockDb: Partial<Database> = {
  pool: {
    query: vi.fn(),
  } as any,
};

const sessionManager = new MultiDeviceSessionManager();

describe('Device Relay Service', () => {
  let deviceRelay: DeviceRelay;
  const userId1 = 'a'.repeat(64);
  const userId2 = 'b'.repeat(64);
  const deviceId1 = '550e8400-e29b-41d4-a716-446655440000';
  const deviceId2 = '660e8400-e29b-41d4-a716-446655440001';
  const deviceId3 = '770e8400-e29b-41d4-a716-446655440002';
  let sessionManager: MultiDeviceSessionManager;

  beforeEach(() => {
    vi.clearAllMocks();
    sessionManager = new MultiDeviceSessionManager();
    deviceRelay = new DeviceRelay(sessionManager);
  });

  describe('User Isolation', () => {
    it('should enforce user isolation when relaying events', async () => {
      const session1: SessionState = {
        userId: userId1,
        deviceId: deviceId1,
        sessionKeys: { clientKey: Buffer.from('key1'), serverKey: Buffer.from('key1') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const event = {
        event_id: '01234567-89ab-7def-0123-456789abcdef',
        user_id: userId2, // Different user
        device_id: deviceId1,
        device_seq: 1,
        stream_id: 'stream-123',
        stream_seq: 1,
        type: 'clipboard',
        encrypted_payload: Buffer.from('test').toString('base64'),
        created_at: Date.now(),
      };

      sessionManager.addSession(userId1, deviceId1, session1, {} as any);

      const result = await deviceRelay.relayEventToUserDevices(
        event as any,
        deviceId1,
        userId1
      );

      // Should block cross-user relay
      expect(result.relayed).toBe(0);
      expect(result.failed).toBe(0);
      expect(result.targetDevices).toHaveLength(0);
    });

    it('should allow events from same user', async () => {
      const session1: SessionState = {
        userId: userId1,
        deviceId: deviceId1,
        sessionKeys: { clientKey: Buffer.from('key1'), serverKey: Buffer.from('key1') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const session2: SessionState = {
        userId: userId1,
        deviceId: deviceId2,
        sessionKeys: { clientKey: Buffer.from('key2'), serverKey: Buffer.from('key2') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const event = {
        event_id: '01234567-89ab-7def-0123-456789abcdef',
        user_id: userId1,
        device_id: deviceId1,
        device_seq: 1,
        stream_id: 'stream-123',
        stream_seq: 1,
        type: 'clipboard',
        encrypted_payload: Buffer.from('test').toString('base64'),
        created_at: Date.now(),
      };

      const mockWs1 = { send: vi.fn(), readyState: 1, OPEN: 1 } as any;
      const mockWs2 = { send: vi.fn(), readyState: 1, OPEN: 1 } as any;

      sessionManager.addSession(userId1, deviceId1, session1, mockWs1);
      sessionManager.addSession(userId1, deviceId2, session2, mockWs2);

      const result = await deviceRelay.relayEventToUserDevices(
        event as any,
        deviceId1,
        userId1
      );

      expect(result.relayed).toBe(1); // Sent to deviceId2
      expect(result.failed).toBe(0);
      expect(mockWs2.send).toHaveBeenCalled();
    });
  });

  describe('Event Routing', () => {
    it('should not send event back to sender', async () => {
      const session1: SessionState = {
        userId: userId1,
        deviceId: deviceId1,
        sessionKeys: { clientKey: Buffer.from('key1'), serverKey: Buffer.from('key1') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const session2: SessionState = {
        userId: userId1,
        deviceId: deviceId2,
        sessionKeys: { clientKey: Buffer.from('key2'), serverKey: Buffer.from('key2') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const event = {
        event_id: '01234567-89ab-7def-0123-456789abcdef',
        user_id: userId1,
        device_id: deviceId1,
        device_seq: 1,
        stream_id: 'stream-123',
        stream_seq: 1,
        type: 'clipboard',
        encrypted_payload: Buffer.from('test').toString('base64'),
        created_at: Date.now(),
      };

      const mockWs1 = { send: vi.fn(), readyState: 1, OPEN: 1 } as any;
      const mockWs2 = { send: vi.fn(), readyState: 1, OPEN: 1 } as any;

      sessionManager.addSession(userId1, deviceId1, session1, mockWs1);
      sessionManager.addSession(userId1, deviceId2, session2, mockWs2);

      const result = await deviceRelay.relayEventToUserDevices(
        event as any,
        deviceId1,
        userId1
      );

      // Should only send to deviceId2, not deviceId1
      expect(result.relayed).toBe(1);
      expect(mockWs1.send).not.toHaveBeenCalled();
      expect(mockWs2.send).toHaveBeenCalled();
    });

    it('should relay to multiple devices', async () => {
      const session1: SessionState = {
        userId: userId1,
        deviceId: deviceId1,
        sessionKeys: { clientKey: Buffer.from('key1'), serverKey: Buffer.from('key1') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const session2: SessionState = {
        userId: userId1,
        deviceId: deviceId2,
        sessionKeys: { clientKey: Buffer.from('key2'), serverKey: Buffer.from('key2') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const session3: SessionState = {
        userId: userId1,
        deviceId: deviceId3,
        sessionKeys: { clientKey: Buffer.from('key3'), serverKey: Buffer.from('key3') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const event = {
        event_id: '01234567-89ab-7def-0123-456789abcdef',
        user_id: userId1,
        device_id: deviceId1,
        device_seq: 1,
        stream_id: 'stream-123',
        stream_seq: 1,
        type: 'clipboard',
        encrypted_payload: Buffer.from('test').toString('base64'),
        created_at: Date.now(),
      };

      const mockWs1 = { send: vi.fn(), readyState: 1, OPEN: 1 } as any;
      const mockWs2 = { send: vi.fn(), readyState: 1, OPEN: 1 } as any;
      const mockWs3 = { send: vi.fn(), readyState: 1, OPEN: 1 } as any;

      sessionManager.addSession(userId1, deviceId1, session1, mockWs1);
      sessionManager.addSession(userId1, deviceId2, session2, mockWs2);
      sessionManager.addSession(userId1, deviceId3, session3, mockWs3);

      const result = await deviceRelay.relayEventToUserDevices(
        event as any,
        deviceId1,
        userId1
      );

      // Should send to deviceId2 and deviceId3 (2 devices)
      expect(result.relayed).toBe(2);
      expect(mockWs2.send).toHaveBeenCalled();
      expect(mockWs3.send).toHaveBeenCalled();
    });

    it('should handle relay failures gracefully', async () => {
      const session1: SessionState = {
        userId: userId1,
        deviceId: deviceId1,
        sessionKeys: { clientKey: Buffer.from('key1'), serverKey: Buffer.from('key1') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const session2: SessionState = {
        userId: userId1,
        deviceId: deviceId2,
        sessionKeys: { clientKey: Buffer.from('key2'), serverKey: Buffer.from('key2') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const event = {
        event_id: '01234567-89ab-7def-0123-456789abcdef',
        user_id: userId1,
        device_id: deviceId1,
        device_seq: 1,
        stream_id: 'stream-123',
        stream_seq: 1,
        type: 'clipboard',
        encrypted_payload: Buffer.from('test').toString('base64'),
        created_at: Date.now(),
      };

      const mockWs1 = { send: vi.fn(), readyState: 1, OPEN: 1 } as any;
      const mockWs2 = { send: vi.fn().mockImplementation(() => { throw new Error('Send failed'); }), readyState: 1, OPEN: 1 } as any;

      sessionManager.addSession(userId1, deviceId1, session1, mockWs1);
      sessionManager.addSession(userId1, deviceId2, session2, mockWs2);

      const result = await deviceRelay.relayEventToUserDevices(
        event as any,
        deviceId1,
        userId1
      );

      expect(result.relayed).toBe(0);
      expect(result.failed).toBe(1);
    });
  });

  describe('Get User Devices', () => {
    it('should return devices for a user', () => {
      const session1: SessionState = {
        userId: userId1,
        deviceId: deviceId1,
        sessionKeys: { clientKey: Buffer.from('key1'), serverKey: Buffer.from('key1') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const session2: SessionState = {
        userId: userId1,
        deviceId: deviceId2,
        sessionKeys: { clientKey: Buffer.from('key2'), serverKey: Buffer.from('key2') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const mockWs1 = { send: vi.fn(), readyState: 1, OPEN: 1 } as any;
      const mockWs2 = { send: vi.fn(), readyState: 1, OPEN: 1 } as any;

      sessionManager.addSession(userId1, deviceId1, session1, mockWs1);
      sessionManager.addSession(userId1, deviceId2, session2, mockWs2);

      const devices = deviceRelay.getUserDevices(userId1);

      expect(devices).toHaveLength(2);
      expect(devices[0].deviceId).toBe(deviceId1);
      expect(devices[1].deviceId).toBe(deviceId2);
    });

    it('should only return devices for specified user', () => {
      const session1: SessionState = {
        userId: userId1,
        deviceId: deviceId1,
        sessionKeys: { clientKey: Buffer.from('key1'), serverKey: Buffer.from('key1') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const session2: SessionState = {
        userId: userId2,
        deviceId: deviceId2,
        sessionKeys: { clientKey: Buffer.from('key2'), serverKey: Buffer.from('key2') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      };

      const mockWs1 = { send: vi.fn(), readyState: 1, OPEN: 1 } as any;
      const mockWs2 = { send: vi.fn(), readyState: 1, OPEN: 1 } as any;

      sessionManager.addSession(userId1, deviceId1, session1, mockWs1);
      sessionManager.addSession(userId2, deviceId2, session2, mockWs2);

      const devices = deviceRelay.getUserDevices(userId1);

      expect(devices).toHaveLength(1);
      expect(devices[0].deviceId).toBe(deviceId1);
    });
  });

  describe('User Access Verification', () => {
    it('should verify user access', () => {
      const hasAccess = deviceRelay.verifyUserAccess(userId1, deviceId1, userId1);
      expect(hasAccess).toBe(true);
    });

    it('should reject access for different user', () => {
      const hasAccess = deviceRelay.verifyUserAccess(userId1, deviceId1, userId2);
      expect(hasAccess).toBe(false);
    });
  });
});

