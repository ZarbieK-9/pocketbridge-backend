/**
 * Redis Connection with Production Features
 * 
 * Uses Redis ONLY for:
 * - Pub/Sub routing (fan-out events to devices)
 * - Presence tracking (device online/offline)
 * - Rate limiting (optional)
 * 
 * NEVER stores:
 * - Payloads
 * - Plaintext
 * - Files
 */

import { createClient, RedisClientType } from 'redis';
import { config } from '../config.js';
import { logger } from '../utils/logger.js';

export interface RedisConnection {
  client: RedisClientType;
  quit: () => Promise<void>;
  healthCheck: () => Promise<boolean>;
}

/**
 * Initialize Redis connection with retry logic
 */
export async function initRedis(): Promise<RedisConnection> {
  // Use REDIS_URL if provided, otherwise use individual config
  const clientConfig = config.redisUrl
    ? {
        url: config.redisUrl,
        socket: {
          reconnectStrategy: (retries: number) => {
            if (retries > 10) {
              logger.error('Redis reconnection failed after 10 retries');
              return new Error('Redis connection failed');
            }
            const delay = Math.min(retries * 100, 3000);
            logger.warn(`Redis reconnecting in ${delay}ms (attempt ${retries})`);
            return delay;
          },
        },
      }
    : {
        socket: {
          host: config.redis.host,
          port: config.redis.port,
          reconnectStrategy: (retries: number) => {
            if (retries > 10) {
              logger.error('Redis reconnection failed after 10 retries');
              return new Error('Redis connection failed');
            }
            const delay = Math.min(retries * 100, 3000);
            logger.warn(`Redis reconnecting in ${delay}ms (attempt ${retries})`);
            return delay;
          },
        },
        password: config.redis.password,
      };

  const client = createClient(clientConfig) as RedisClientType;

  // Error handling
  client.on('error', (err) => {
    logger.error('Redis client error', {}, err);
  });

  client.on('connect', () => {
    logger.info('Redis connecting...');
  });

  client.on('ready', () => {
    logger.info('Redis connection ready');
  });

  client.on('reconnecting', () => {
    logger.warn('Redis reconnecting...');
  });

  // Retry connection with exponential backoff
  let retries = 5;
  let delay = 1000;

  while (retries > 0) {
    try {
      await client.connect();
      logger.info('Redis connection established');
      break;
    } catch (error) {
      retries--;
      if (retries === 0) {
        logger.error('Failed to connect to Redis after retries', {}, error instanceof Error ? error : new Error(String(error)));
        throw error;
      }
      logger.warn(`Redis connection failed, retrying in ${delay}ms... (${retries} retries left)`);
      await new Promise(resolve => setTimeout(resolve, delay));
      delay *= 2; // Exponential backoff
    }
  }

  return {
    client,
    quit: async () => {
      await client.quit();
      logger.info('Redis connection closed');
    },
    healthCheck: async () => {
      try {
        await client.ping();
        return true;
      } catch {
        return false;
      }
    },
  };
}

/**
 * Get Redis channel name for a user's device
 */
export function getUserDeviceChannel(userId: string, deviceId: string): string {
  return `user:${userId}:device:${deviceId}`;
}

/**
 * Get Redis channel name for a user (all devices)
 */
export function getUserChannel(userId: string): string {
  return `user:${userId}:*`;
}

/**
 * Get presence key for a device
 */
export function getPresenceKey(deviceId: string): string {
  return `presence:${deviceId}`;
}
