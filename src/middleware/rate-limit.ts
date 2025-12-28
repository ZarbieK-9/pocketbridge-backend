/**
 * Rate Limiting Middleware
 *
 * Protects against:
 * - DoS attacks
 * - Event flooding
 * - Resource exhaustion
 *
 * Tracks by:
 * - IP: Connection/handshake attempts (prevent brute force)
 * - User ID: Concurrent devices, event rate (prevent abuse per user)
 */

import { logger } from '../utils/logger.js';

interface RateLimitConfig {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Max requests per window
}

interface RateLimitStore {
  [key: string]: {
    count: number;
    resetAt: number;
  };
}

export class RateLimiter {
  private store: RateLimitStore = {};
  private config: RateLimitConfig;

  constructor(config: RateLimitConfig) {
    this.config = config;
    // Cleanup expired entries every minute
    setInterval(() => this.cleanup(), 60000);
  }

  /**
   * Check if request should be allowed
   */
  check(identifier: string): { allowed: boolean; remaining: number; resetAt: number } {
    const now = Date.now();
    const entry = this.store[identifier];

    if (!entry || now > entry.resetAt) {
      // New window or expired, reset
      this.store[identifier] = {
        count: 1,
        resetAt: now + this.config.windowMs,
      };
      return {
        allowed: true,
        remaining: this.config.maxRequests - 1,
        resetAt: now + this.config.windowMs,
      };
    }

    if (entry.count >= this.config.maxRequests) {
      // Rate limit exceeded
      return {
        allowed: false,
        remaining: 0,
        resetAt: entry.resetAt,
      };
    }

    // Increment count
    entry.count++;
    return {
      allowed: true,
      remaining: this.config.maxRequests - entry.count,
      resetAt: entry.resetAt,
    };
  }

  /**
   * Cleanup expired entries
   */
  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of Object.entries(this.store)) {
      if (now > entry.resetAt) {
        delete this.store[key];
      }
    }
  }
}

// Per-user concurrent device tracking
interface UserDeviceTracker {
  [userId: string]: Set<string>; // user_id -> Set of device_ids
}

const userDevices: UserDeviceTracker = {};

// Rate limiters for different resources
export const connectionRateLimiter = new RateLimiter({
  windowMs: 60000, // 1 minute
  maxRequests: 60, // 60 connections per minute per IP (increased for reconnection scenarios)
});

export const eventRateLimiter = new RateLimiter({
  windowMs: 1000, // 1 second
  maxRequests: 100, // 100 events per second per device
});

export const handshakeRateLimiter = new RateLimiter({
  windowMs: 60000, // 1 minute
  maxRequests: 30, // 30 handshakes per minute per IP (increased for reconnection scenarios)
});

// Per-user event rate limiter (1000 events per minute per user, all devices combined)
export const userEventRateLimiter = new RateLimiter({
  windowMs: 60000, // 1 minute
  maxRequests: 1000, // 1000 events per minute per user (all devices combined)
});

/**
 * Get client identifier for rate limiting
 */
export function getClientIdentifier(req: any): string {
  // Use IP address for connection/handshake limiting
  const forwarded = req.headers['x-forwarded-for'];
  const ip = forwarded ? forwarded.split(',')[0].trim() : req.socket.remoteAddress;
  return ip || 'unknown';
}

/**
 * Rate limit WebSocket connection
 */
export function rateLimitConnection(identifier: string): { allowed: boolean; error?: string } {
  const result = connectionRateLimiter.check(identifier);

  if (!result.allowed) {
    logger.warn('Connection rate limit exceeded', { identifier });
    return {
      allowed: false,
      error: 'Too many connection attempts. Please try again later.',
    };
  }

  return { allowed: true };
}

/**
 * Rate limit event publishing
 */
export function rateLimitEvent(deviceId: string): { allowed: boolean; error?: string } {
  const result = eventRateLimiter.check(deviceId);

  if (!result.allowed) {
    logger.warn('Event rate limit exceeded', { deviceId });
    return {
      allowed: false,
      error: 'Event rate limit exceeded. Please slow down.',
    };
  }

  return { allowed: true };
}

/**
 * Rate limit handshake
 */
export function rateLimitHandshake(identifier: string): { allowed: boolean; error?: string } {
  const result = handshakeRateLimiter.check(identifier);

  if (!result.allowed) {
    logger.warn('Handshake rate limit exceeded', { identifier });
    return {
      allowed: false,
      error: 'Too many handshake attempts. Please try again later.',
    };
  }

  return { allowed: true };
}

/**
 * Track device connection for a user (per-user concurrency tracking)
 */
export function trackUserDevice(userId: string, deviceId: string): void {
  if (!userDevices[userId]) {
    userDevices[userId] = new Set();
  }
  userDevices[userId].add(deviceId);
}

/**
 * Untrack device for a user (per-user concurrency tracking)
 */
export function untrackUserDevice(userId: string, deviceId: string): void {
  if (userDevices[userId]) {
    userDevices[userId].delete(deviceId);
    if (userDevices[userId].size === 0) {
      delete userDevices[userId];
    }
  }
}

/**
 * Check concurrent device limit per user (max 5 devices per user)
 */
export function checkConcurrentDeviceLimit(
  userId: string,
  maxDevices: number = 5
): { allowed: boolean; error?: string } {
  const deviceCount = userDevices[userId]?.size || 0;

  if (deviceCount >= maxDevices) {
    logger.warn('User concurrent device limit exceeded', {
      userId: userId.substring(0, 16) + '...',
      deviceCount,
      maxDevices,
    });
    return {
      allowed: false,
      error: `Too many devices connected (max ${maxDevices}). Please disconnect another device.`,
    };
  }

  return { allowed: true };
}

/**
 * Get concurrent device count for user
 */
export function getConcurrentDeviceCount(userId: string): number {
  return userDevices[userId]?.size || 0;
}

/**
 * Rate limit events per user (1000 events per minute per user, all devices combined)
 */
export function rateLimitUserEvent(userId: string): { allowed: boolean; error?: string } {
  const result = userEventRateLimiter.check(userId);

  if (!result.allowed) {
    logger.warn('User event rate limit exceeded', { userId: userId.substring(0, 16) + '...' });
    return {
      allowed: false,
      error: 'Your account is sending too many events. Please slow down.',
    };
  }

  return { allowed: true };
}
