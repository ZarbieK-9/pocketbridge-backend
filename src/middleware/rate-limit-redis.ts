/**
 * Distributed Rate Limiting with Redis
 *
 * Provides rate limiting that works across multiple backend instances
 * Falls back to in-memory rate limiting if Redis is unavailable
 */

import type { RedisConnection } from '../db/redis.js';
import { logger } from '../utils/logger.js';
import { RateLimiter, connectionRateLimiter, handshakeRateLimiter } from './rate-limit.js';

interface DistributedRateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  error?: string;
}

/**
 * Distributed rate limiter using Redis
 */
export class DistributedRateLimiter {
  private redis: RedisConnection | null;
  private fallbackLimiter: RateLimiter;

  constructor(redis: RedisConnection | null, fallbackLimiter: RateLimiter) {
    this.redis = redis;
    this.fallbackLimiter = fallbackLimiter;
  }

  /**
   * Check rate limit using Redis (distributed) or fallback to in-memory
   */
  async check(
    identifier: string,
    windowMs: number,
    maxRequests: number
  ): Promise<DistributedRateLimitResult> {
    // If Redis is not available, use fallback
    if (!this.redis) {
      return this.fallbackLimiter.check(identifier);
    }

    try {
      const key = `ratelimit:${identifier}`;
      const now = Date.now();
      const windowStart = now - windowMs;

      // Use Redis sorted set to track requests
      // Score = timestamp, value = request ID
      const pipeline = this.redis.client.multi();

      // Remove old entries (outside window)
      pipeline.zRemRangeByScore(key, 0, windowStart);

      // Count current entries
      pipeline.zCard(key);

      // Add current request
      pipeline.zAdd(key, { score: now, value: `${now}-${Math.random()}` });

      // Set expiration
      pipeline.expire(key, Math.ceil(windowMs / 1000) + 1);

      const results = await pipeline.exec();

      if (!results || results.length < 2) {
        throw new Error('Redis pipeline execution failed');
      }

      const count = results[1] as number;
      const remaining = Math.max(0, maxRequests - count - 1);
      const resetAt = now + windowMs;

      if (count >= maxRequests) {
        return {
          allowed: false,
          remaining: 0,
          resetAt,
          error: 'Rate limit exceeded',
        };
      }

      return {
        allowed: true,
        remaining,
        resetAt,
      };
    } catch (error) {
      // Fallback to in-memory rate limiting on Redis error
      logger.warn('Redis rate limiting failed, falling back to in-memory', {
        error: error instanceof Error ? error.message : String(error),
      });
      return this.fallbackLimiter.check(identifier);
    }
  }
}

/**
 * Create distributed rate limiters (if Redis is available)
 */
export function createDistributedRateLimiters(redis: RedisConnection | null) {
  return {
    connection: new DistributedRateLimiter(redis, connectionRateLimiter),
    handshake: new DistributedRateLimiter(redis, handshakeRateLimiter),
  };
}
