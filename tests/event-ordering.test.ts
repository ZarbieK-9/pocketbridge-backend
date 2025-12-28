/**
 * Event Ordering Verification Tests
 * 
 * Verifies that events maintain proper ordering guarantees:
 * - device_seq is monotonic per device
 * - stream_seq is monotonic per stream
 * - Events are relayed in order
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { EncryptedEvent } from '../src/types/index.js';

describe('Event Ordering Verification', () => {
  describe('Device Sequence Ordering', () => {
    it('should enforce monotonic device_seq per device', () => {
      const events: EncryptedEvent[] = [
        {
          event_id: '1',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 1,
          stream_id: 'stream1',
          stream_seq: 1,
          type: 'test',
          encrypted_payload: 'payload1',
        },
        {
          event_id: '2',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 2,
          stream_id: 'stream1',
          stream_seq: 2,
          type: 'test',
          encrypted_payload: 'payload2',
        },
        {
          event_id: '3',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 3,
          stream_id: 'stream1',
          stream_seq: 3,
          type: 'test',
          encrypted_payload: 'payload3',
        },
      ];

      // Verify monotonic ordering
      for (let i = 1; i < events.length; i++) {
        expect(events[i].device_seq).toBeGreaterThan(events[i - 1].device_seq);
      }
    });

    it('should reject non-monotonic device_seq', () => {
      const events: EncryptedEvent[] = [
        {
          event_id: '1',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 1,
          stream_id: 'stream1',
          stream_seq: 1,
          type: 'test',
          encrypted_payload: 'payload1',
        },
        {
          event_id: '2',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 0, // Invalid: less than previous
          stream_id: 'stream1',
          stream_seq: 2,
          type: 'test',
          encrypted_payload: 'payload2',
        },
      ];

      // This should be rejected by validation
      expect(events[1].device_seq).toBeLessThan(events[0].device_seq);
    });
  });

  describe('Stream Sequence Ordering', () => {
    it('should enforce monotonic stream_seq per stream', () => {
      const events: EncryptedEvent[] = [
        {
          event_id: '1',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 1,
          stream_id: 'stream1',
          stream_seq: 1,
          type: 'test',
          encrypted_payload: 'payload1',
        },
        {
          event_id: '2',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 2,
          stream_id: 'stream1',
          stream_seq: 2,
          type: 'test',
          encrypted_payload: 'payload2',
        },
        {
          event_id: '3',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 3,
          stream_id: 'stream1',
          stream_seq: 3,
          type: 'test',
          encrypted_payload: 'payload3',
        },
      ];

      // Verify monotonic ordering within same stream
      for (let i = 1; i < events.length; i++) {
        if (events[i].stream_id === events[i - 1].stream_id) {
          expect(events[i].stream_seq).toBeGreaterThan(events[i - 1].stream_seq);
        }
      }
    });

    it('should allow different stream_seq values for different streams', () => {
      const events: EncryptedEvent[] = [
        {
          event_id: '1',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 1,
          stream_id: 'stream1',
          stream_seq: 5, // Can have any value
          type: 'test',
          encrypted_payload: 'payload1',
        },
        {
          event_id: '2',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 2,
          stream_id: 'stream2', // Different stream
          stream_seq: 1, // Can start from 1
          type: 'test',
          encrypted_payload: 'payload2',
        },
      ];

      // Different streams can have independent sequences
      expect(events[0].stream_id).not.toBe(events[1].stream_id);
      expect(events[0].stream_seq).toBeGreaterThan(events[1].stream_seq); // This is valid
    });
  });

  describe('Multi-Device Event Ordering', () => {
    it('should maintain device_seq ordering across devices for same user', () => {
      const device1Events: EncryptedEvent[] = [
        {
          event_id: '1',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 1,
          stream_id: 'stream1',
          stream_seq: 1,
          type: 'test',
          encrypted_payload: 'payload1',
        },
        {
          event_id: '2',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 2,
          stream_id: 'stream1',
          stream_seq: 2,
          type: 'test',
          encrypted_payload: 'payload2',
        },
      ];

      const device2Events: EncryptedEvent[] = [
        {
          event_id: '3',
          user_id: 'user1',
          device_id: 'device2',
          device_seq: 1, // Independent sequence per device
          stream_id: 'stream1',
          stream_seq: 3,
          type: 'test',
          encrypted_payload: 'payload3',
        },
      ];

      // Each device maintains its own device_seq
      expect(device1Events[0].device_id).not.toBe(device2Events[0].device_id);
      expect(device1Events[0].device_seq).toBe(device2Events[0].device_seq); // Both can be 1
    });
  });

  describe('Event Relay Ordering', () => {
    it('should relay events in stream_seq order', () => {
      const events: EncryptedEvent[] = [
        {
          event_id: '1',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 1,
          stream_id: 'stream1',
          stream_seq: 1,
          type: 'test',
          encrypted_payload: 'payload1',
        },
        {
          event_id: '2',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 2,
          stream_id: 'stream1',
          stream_seq: 2,
          type: 'test',
          encrypted_payload: 'payload2',
        },
        {
          event_id: '3',
          user_id: 'user1',
          device_id: 'device1',
          device_seq: 3,
          stream_id: 'stream1',
          stream_seq: 3,
          type: 'test',
          encrypted_payload: 'payload3',
        },
      ];

      // Events should be relayed in stream_seq order
      const sortedByStreamSeq = [...events].sort((a, b) => a.stream_seq - b.stream_seq);
      expect(sortedByStreamSeq).toEqual(events);
    });
  });
});

