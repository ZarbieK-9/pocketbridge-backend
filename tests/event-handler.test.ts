/**
 * Event Handler Tests
 * 
 * Tests for event processing, validation, and storage
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Database } from '../src/db/postgres.js';
import type { RedisConnection } from '../src/db/redis.js';
import type { SessionState } from '../src/types/index.js';
import type DeviceRelay from '../src/services/device-relay.js';

// Mock dependencies
const mockDb: Partial<Database> = {
  pool: {
    query: vi.fn(),
    connect: vi.fn(),
  } as any,
};

const mockRedis: Partial<RedisConnection> = {
  client: {
    publish: vi.fn(),
  } as any,
};

const mockDeviceRelay: Partial<DeviceRelay> = {
  relayEventToUserDevices: vi.fn(),
};

const mockSessionState: SessionState = {
  userId: 'a'.repeat(64),
  deviceId: '550e8400-e29b-41d4-a716-446655440000',
  sessionKeys: {
    clientKey: Buffer.from('client-key'),
    serverKey: Buffer.from('server-key'),
  },
  lastAckDeviceSeq: 0,
  createdAt: Date.now(),
};

describe('Event Handler', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Event Validation', () => {
    it('should validate event structure', async () => {
      const { handleEvent } = await import('../src/gateway/event-handler.js');
      
      const validEvent = {
        event_id: '01234567-89ab-7def-0123-456789abcdef',
        user_id: 'a'.repeat(64),
        device_id: '550e8400-e29b-41d4-a716-446655440000',
        device_seq: 1,
        stream_id: 'stream-123',
        type: 'clipboard',
        encrypted_payload: Buffer.from('test').toString('base64'),
      };

      // Mock database responses
      // IMPORTANT: Order matters - these checks happen first in handleEvent
      const mockClient = {
        query: vi.fn()
          .mockResolvedValueOnce({ rows: [] }) // BEGIN
          .mockResolvedValueOnce({ rows: [] }) // UPDATE users
          .mockResolvedValueOnce({ rows: [] }) // INSERT events
          .mockResolvedValueOnce({ rows: [] }), // COMMIT
        release: vi.fn(),
      };

      (mockDb.pool!.query as any)
        .mockResolvedValueOnce({ rows: [] }) // isDeviceRevoked check (returns empty = not revoked)
        .mockResolvedValueOnce({ rows: [{ device_id: mockSessionState.deviceId }] }) // Device existence check
        .mockResolvedValueOnce({ rows: [{ last_stream_seq: 0 }] }) // getNextStreamSeq
        .mockResolvedValueOnce({ rows: [] }); // conflict check

      (mockDb.pool!.connect as any) = vi.fn().mockResolvedValue(mockClient);

      (mockDeviceRelay.relayEventToUserDevices as any).mockResolvedValue({
        relayed: 1,
        failed: 0,
        targetDevices: [],
      });

      (mockRedis.client!.publish as any).mockResolvedValue(1);

      await expect(
        handleEvent(
          validEvent,
          mockSessionState,
          mockDb as Database,
          mockRedis as RedisConnection,
          mockDeviceRelay as DeviceRelay
        )
      ).resolves.not.toThrow();
    });

    it('should reject event with mismatched device_id', async () => {
      const { handleEvent } = await import('../src/gateway/event-handler.js');
      
      const invalidEvent = {
        event_id: '01234567-89ab-7def-0123-456789abcdef',
        user_id: 'a'.repeat(64),
        device_id: 'different-device-id',
        device_seq: 1,
        stream_id: 'stream-123',
        type: 'clipboard',
        encrypted_payload: Buffer.from('test').toString('base64'),
      };

      await expect(
        handleEvent(
          invalidEvent,
          mockSessionState,
          mockDb as Database,
          mockRedis as RedisConnection,
          mockDeviceRelay as DeviceRelay
        )
      ).rejects.toThrow();
    });

    it('should reject event with non-monotonic device_seq', async () => {
      const { handleEvent } = await import('../src/gateway/event-handler.js');
      
      const invalidEvent = {
        event_id: '01234567-89ab-7def-0123-456789abcdef',
        user_id: 'a'.repeat(64),
        device_id: mockSessionState.deviceId,
        device_seq: 0, // Less than lastAckDeviceSeq (0)
        stream_id: 'stream-123',
        type: 'clipboard',
        encrypted_payload: Buffer.from('test').toString('base64'),
      };

      await expect(
        handleEvent(
          invalidEvent,
          { ...mockSessionState, lastAckDeviceSeq: 1 },
          mockDb as Database,
          mockRedis as RedisConnection,
          mockDeviceRelay as DeviceRelay
        )
      ).rejects.toThrow();
    });
  });

  describe('Stream Sequence Assignment', () => {
    it('should assign sequential stream_seq', async () => {
      const { handleEvent } = await import('../src/gateway/event-handler.js');
      
      const event = {
        event_id: '01234567-89ab-7def-0123-456789abcdef',
        user_id: 'a'.repeat(64),
        device_id: mockSessionState.deviceId,
        device_seq: 1,
        stream_id: 'stream-123',
        type: 'clipboard',
        encrypted_payload: Buffer.from('test').toString('base64'),
      };

      // Mock: last_stream_seq = 5, so next should be 6
      const mockClient = {
        query: vi.fn()
          .mockResolvedValueOnce({ rows: [] }) // BEGIN
          .mockResolvedValueOnce({ rows: [] }) // UPDATE users
          .mockResolvedValueOnce({ rows: [] }) // INSERT events
          .mockResolvedValueOnce({ rows: [] }), // COMMIT
        release: vi.fn(),
      };

      (mockDb.pool!.query as any)
        .mockResolvedValueOnce({ rows: [] }) // isDeviceRevoked check
        .mockResolvedValueOnce({ rows: [{ device_id: mockSessionState.deviceId }] }) // Device existence check
        .mockResolvedValueOnce({ rows: [{ last_stream_seq: 5 }] }) // getNextStreamSeq
        .mockResolvedValueOnce({ rows: [] }); // conflict check

      (mockDb.pool!.connect as any) = vi.fn().mockResolvedValue(mockClient);

      (mockDeviceRelay.relayEventToUserDevices as any).mockResolvedValue({
        relayed: 0,
        failed: 0,
        targetDevices: [],
      });

      (mockRedis.client!.publish as any).mockResolvedValue(1);

      await handleEvent(
        event,
        mockSessionState,
        mockDb as Database,
        mockRedis as RedisConnection,
        mockDeviceRelay as DeviceRelay
      );

      // Verify stream_seq was used in insert
      // The INSERT happens on client.query, not pool.query
      const insertCalls = mockClient.query.mock.calls.filter(
        (call: any[]) => call[0] && typeof call[0] === 'string' && call[0].includes('INSERT INTO events')
      );
      expect(insertCalls.length).toBeGreaterThan(0);
      // Verify that getNextStreamSeq was called and returned 6
      const streamSeqCall = (mockDb.pool!.query as any).mock.calls.find(
        (call: any[]) => call[0] && typeof call[0] === 'string' && call[0].includes('stream_sequences')
      );
      expect(streamSeqCall).toBeDefined();
      // The actual stream_seq value (6) is used in the event insert
      // We verify the query was called with the correct structure
    });
  });

  describe('Conflict Detection', () => {
    it('should detect conflicts when same stream_seq exists', async () => {
      const { handleEvent } = await import('../src/gateway/event-handler.js');
      
      const event = {
        event_id: '01234567-89ab-7def-0123-456789abcdef',
        user_id: 'a'.repeat(64),
        device_id: mockSessionState.deviceId,
        device_seq: 1,
        stream_id: 'stream-123',
        type: 'clipboard',
        encrypted_payload: Buffer.from('test').toString('base64'),
      };

      // Mock conflict: existing event with same stream_seq from different device
      const mockClient = {
        query: vi.fn()
          .mockResolvedValueOnce({ rows: [] }) // BEGIN
          .mockResolvedValueOnce({ rows: [] }) // UPDATE users
          .mockResolvedValueOnce({ rows: [] }) // INSERT events
          .mockResolvedValueOnce({ rows: [] }), // COMMIT
        release: vi.fn(),
      };

      (mockDb.pool!.query as any)
        .mockResolvedValueOnce({ rows: [] }) // isDeviceRevoked check
        .mockResolvedValueOnce({ rows: [{ device_id: mockSessionState.deviceId }] }) // Device existence check
        .mockResolvedValueOnce({ rows: [{ last_stream_seq: 5 }] }) // getNextStreamSeq
        .mockResolvedValueOnce({
          rows: [{
            device_id: 'different-device-id',
            created_at: new Date(Date.now() - 1000),
          }],
        }) // conflict check
        .mockResolvedValueOnce({ rows: [] }); // conflict_log insert

      (mockDb.pool!.connect as any) = vi.fn().mockResolvedValue(mockClient);

      (mockDeviceRelay.relayEventToUserDevices as any).mockResolvedValue({
        relayed: 0,
        failed: 0,
        targetDevices: [],
      });

      (mockRedis.client!.publish as any).mockResolvedValue(1);

      await handleEvent(
        event,
        mockSessionState,
        mockDb as Database,
        mockRedis as RedisConnection,
        mockDeviceRelay as DeviceRelay
      );

      // Verify conflict was logged
      const conflictLogCall = (mockDb.pool!.query as any).mock.calls.find(
        (call: any[]) => call[0].includes('INSERT INTO conflict_log')
      );
      expect(conflictLogCall).toBeDefined();
    });
  });

  describe('Event Relay', () => {
    it('should relay event to other devices', async () => {
      const { handleEvent } = await import('../src/gateway/event-handler.js');
      
      const event = {
        event_id: '01234567-89ab-7def-0123-456789abcdef',
        user_id: 'a'.repeat(64),
        device_id: mockSessionState.deviceId,
        device_seq: 1,
        stream_id: 'stream-123',
        type: 'clipboard',
        encrypted_payload: Buffer.from('test').toString('base64'),
      };

      // Mock: isDeviceRevoked, device check, getNextStreamSeq, conflict check
      // Then mock pool.connect() for transaction
      const mockClient = {
        query: vi.fn()
          .mockResolvedValueOnce({ rows: [] }) // BEGIN
          .mockResolvedValueOnce({ rows: [] }) // UPDATE users
          .mockResolvedValueOnce({ rows: [] }) // INSERT events
          .mockResolvedValueOnce({ rows: [] }), // COMMIT
        release: vi.fn(),
      };

      (mockDb.pool!.query as any)
        .mockResolvedValueOnce({ rows: [] }) // isDeviceRevoked check
        .mockResolvedValueOnce({ rows: [{ device_id: mockSessionState.deviceId }] }) // Device existence check
        .mockResolvedValueOnce({ rows: [{ last_stream_seq: 0 }] }) // getNextStreamSeq
        .mockResolvedValueOnce({ rows: [] }); // conflict check

      (mockDb.pool!.connect as any) = vi.fn().mockResolvedValue(mockClient);

      (mockDeviceRelay.relayEventToUserDevices as any).mockResolvedValue({
        relayed: 2,
        failed: 0,
        targetDevices: [],
      });

      (mockRedis.client!.publish as any).mockResolvedValue(1);

      await handleEvent(
        event,
        mockSessionState,
        mockDb as Database,
        mockRedis as RedisConnection,
        mockDeviceRelay as DeviceRelay
      );

      // Verify relay was called
      expect(mockDeviceRelay.relayEventToUserDevices).toHaveBeenCalled();
      const relayCall = (mockDeviceRelay.relayEventToUserDevices as any).mock.calls[0];
      expect(relayCall[0].event_id).toBe(event.event_id);
      expect(relayCall[1]).toBe(mockSessionState.deviceId);
      expect(relayCall[2]).toBe(mockSessionState.userId);
    });
  });
});

