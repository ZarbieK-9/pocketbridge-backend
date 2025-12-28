/**
 * Rate Limiting Tests
 * 
 * Comprehensive tests for rate limiting functionality
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { RateLimiter, connectionRateLimiter, handshakeRateLimiter, rateLimitUserEvent, trackUserDevice, untrackUserDevice, getConcurrentDeviceCount } from '../src/middleware/rate-limit.js';

describe('RateLimiter', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter({
      windowMs: 1000, // 1 second
      maxRequests: 5,
    });
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('check', () => {
    it('should allow requests within limit', () => {
      const result1 = limiter.check('user1');
      expect(result1.allowed).toBe(true);
      expect(result1.remaining).toBe(4);

      const result2 = limiter.check('user1');
      expect(result2.allowed).toBe(true);
      expect(result2.remaining).toBe(3);
    });

    it('should reject requests exceeding limit', () => {
      // Make 5 requests (the limit)
      for (let i = 0; i < 5; i++) {
        limiter.check('user1');
      }

      const result = limiter.check('user1');
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });

    it('should reset window after time expires', () => {
      // Exhaust limit
      for (let i = 0; i < 5; i++) {
        limiter.check('user1');
      }

      // Advance time past window
      vi.advanceTimersByTime(1001);

      const result = limiter.check('user1');
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4);
    });

    it('should track different identifiers separately', () => {
      limiter.check('user1');
      limiter.check('user2');

      const result1 = limiter.check('user1');
      const result2 = limiter.check('user2');

      expect(result1.remaining).toBe(3);
      expect(result2.remaining).toBe(3);
    });

    it('should return correct resetAt timestamp', () => {
      const startTime = Date.now();
      const result = limiter.check('user1');

      expect(result.resetAt).toBeGreaterThanOrEqual(startTime + 1000);
      expect(result.resetAt).toBeLessThanOrEqual(startTime + 1000 + 10); // Allow small margin
    });
  });

  describe('cleanup', () => {
    it('should remove expired entries', () => {
      limiter.check('user1');
      limiter.check('user2');

      // Advance time past window
      vi.advanceTimersByTime(1001);

      // Trigger cleanup (happens automatically via setInterval, but we can test the logic)
      // The cleanup happens in the constructor's setInterval, so we need to wait
      vi.advanceTimersByTime(60000); // Wait for cleanup interval

      // New request should start fresh window
      const result = limiter.check('user1');
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4);
    });
  });
});

describe('Connection Rate Limiter', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should have correct default configuration', () => {
    const result = connectionRateLimiter.check('192.168.1.1');
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(59); // 60 - 1
  });
});

describe('Handshake Rate Limiter', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should have correct default configuration', () => {
    const result = handshakeRateLimiter.check('192.168.1.1');
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(29); // 30 - 1
  });
});

describe('User Device Tracking', () => {
  beforeEach(() => {
    // Clear tracking state by importing and clearing the internal state
    // Note: This requires access to the internal userDevices object
    // For now, we'll test that tracking works, but state may persist between tests
    vi.clearAllMocks();
  });

  it('should track user device', () => {
    // Use unique user ID to avoid state conflicts
    const userId = 'test1'.padEnd(64, '0');
    const deviceId = '550e8400-e29b-41d4-a716-446655440000';

    trackUserDevice(userId, deviceId);
    expect(getConcurrentDeviceCount(userId)).toBe(1);
  });

  it('should track multiple devices for same user', () => {
    // Use unique user ID to avoid state conflicts
    const userId = 'test2'.padEnd(64, '0');
    const deviceId1 = '550e8400-e29b-41d4-a716-446655440000';
    const deviceId2 = '550e8400-e29b-41d4-a716-446655440001';

    trackUserDevice(userId, deviceId1);
    trackUserDevice(userId, deviceId2);
    expect(getConcurrentDeviceCount(userId)).toBe(2);
  });

  it('should not duplicate same device', () => {
    // Use unique user ID to avoid state conflicts
    const userId = 'test3'.padEnd(64, '0');
    const deviceId = '550e8400-e29b-41d4-a716-446655440000';

    trackUserDevice(userId, deviceId);
    trackUserDevice(userId, deviceId);
    expect(getConcurrentDeviceCount(userId)).toBe(1);
  });

  it('should untrack user device', () => {
    // Use unique user ID to avoid state conflicts
    const userId = 'test4'.padEnd(64, '0');
    const deviceId = '550e8400-e29b-41d4-a716-446655440000';

    trackUserDevice(userId, deviceId);
    untrackUserDevice(userId, deviceId);
    expect(getConcurrentDeviceCount(userId)).toBe(0);
  });

  it('should handle untracking non-existent device', () => {
    // Use unique user ID to avoid state conflicts
    const userId = 'test5'.padEnd(64, '0');
    const deviceId = '550e8400-e29b-41d4-a716-446655440000';

    untrackUserDevice(userId, deviceId);
    expect(getConcurrentDeviceCount(userId)).toBe(0);
  });

  it('should track devices for different users separately', () => {
    // Use unique user IDs to avoid state conflicts
    const userId1 = 'test6a'.padEnd(64, '0');
    const userId2 = 'test6b'.padEnd(64, '0');
    const deviceId = '550e8400-e29b-41d4-a716-446655440000';

    trackUserDevice(userId1, deviceId);
    trackUserDevice(userId2, deviceId);
    expect(getConcurrentDeviceCount(userId1)).toBe(1);
    expect(getConcurrentDeviceCount(userId2)).toBe(1);
  });
});

describe('User Event Rate Limiting', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should allow events within limit', () => {
    const userId = 'a'.repeat(64);
    const result1 = rateLimitUserEvent(userId);
    expect(result1.allowed).toBe(true);
    expect(result1.error).toBeUndefined();
  });

  it('should reject events exceeding limit', () => {
    const userId = 'a'.repeat(64);
    
    // Make 1000 requests (the limit per minute)
    for (let i = 0; i < 1000; i++) {
      rateLimitUserEvent(userId);
    }

    const result = rateLimitUserEvent(userId);
    expect(result.allowed).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error).toContain('too many events');
  });

  it('should reset limit after time window', () => {
    const userId = 'a'.repeat(64);
    
    // Exhaust limit
    for (let i = 0; i < 1000; i++) {
      rateLimitUserEvent(userId);
    }

    // Advance time past window (1 minute)
    vi.advanceTimersByTime(60001);

    const result = rateLimitUserEvent(userId);
    expect(result.allowed).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('should track different users separately', () => {
    const userId1 = 'a'.repeat(64);
    const userId2 = 'b'.repeat(64);

    // Exhaust limit for user1
    for (let i = 0; i < 1000; i++) {
      rateLimitUserEvent(userId1);
    }

    // User2 should still be allowed
    const result = rateLimitUserEvent(userId2);
    expect(result.allowed).toBe(true);
  });
});

