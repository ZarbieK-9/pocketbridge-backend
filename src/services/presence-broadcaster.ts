/**
 * Device Presence Broadcaster
 * 
 * Broadcasts device online/offline status via Redis pub/sub
 * Allows clients to be notified when other devices come online/offline
 * 
 * Redis channels:
 * - user:{user_id}:devices - Device list for user (published when device online/offline)
 * - user:{user_id}:device:online - Device came online
 * - user:{user_id}:device:offline - Device came offline
 */

import type { RedisClientType } from 'redis';
import type { DeviceInfo } from '../types/index.js';
import { logger } from '../utils/logger.js';

export class PresenceBroadcaster {
  constructor(private redisClient: RedisClientType) {}

  /**
   * Publish device online event
   */
  async publishDeviceOnline(
    userId: string,
    device: DeviceInfo
  ): Promise<void> {
    try {
      const channel = `user:${userId}:device:online`;
      const message = JSON.stringify(device);

      await this.redisClient.publish(channel, message);

      logger.info('Device online published', {
        userId: userId.substring(0, 16) + '...',
        deviceId: device.device_id,
        channel,
      });
    } catch (error) {
      logger.error('Failed to publish device online', {}, error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Publish device offline event
   */
  async publishDeviceOffline(
    userId: string,
    deviceId: string
  ): Promise<void> {
    try {
      const channel = `user:${userId}:device:offline`;
      const message = JSON.stringify({ device_id: deviceId });

      await this.redisClient.publish(channel, message);

      logger.info('Device offline published', {
        userId: userId.substring(0, 16) + '...',
        deviceId,
        channel,
      });
    } catch (error) {
      logger.error('Failed to publish device offline', {}, error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Publish full device list (presence) for user
   */
  async publishDeviceList(
    userId: string,
    devices: DeviceInfo[]
  ): Promise<void> {
    try {
      const channel = `user:${userId}:devices`;
      const message = JSON.stringify({
        user_id: userId,
        devices,
        timestamp: Date.now(),
        online_count: devices.filter(d => d.is_online).length,
      });

      await this.redisClient.publish(channel, message);

      logger.info('Device list published', {
        userId: userId.substring(0, 16) + '...',
        deviceCount: devices.length,
        channel,
      });
    } catch (error) {
      logger.error('Failed to publish device list', {}, error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Store device online status in Redis for quick lookups
   */
  async cacheDeviceStatus(
    userId: string,
    deviceId: string,
    isOnline: boolean,
    ttl: number = 86400 // 24 hours
  ): Promise<void> {
    try {
      const key = `device:${userId}:${deviceId}:online`;
      if (isOnline) {
        await this.redisClient.setEx(key, ttl, '1');
      } else {
        await this.redisClient.del(key);
      }
    } catch (error) {
      logger.error('Failed to cache device status', {}, error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Get device online status from cache
   */
  async getDeviceStatus(userId: string, deviceId: string): Promise<boolean> {
    try {
      const key = `device:${userId}:${deviceId}:online`;
      const status = await this.redisClient.get(key);
      return status === '1';
    } catch (error) {
      logger.error('Failed to get device status', {}, error instanceof Error ? error : new Error(String(error)));
      return false;
    }
  }

  /**
   * Publish a broadcast message to all user's devices
   */
  async broadcastToUser(
    userId: string,
    eventType: string,
    payload: any
  ): Promise<void> {
    try {
      const channel = `user:${userId}:broadcast`;
      const message = JSON.stringify({
        type: eventType,
        payload,
        timestamp: Date.now(),
      });

      await this.redisClient.publish(channel, message);

      logger.info('Broadcast sent to user', {
        userId: userId.substring(0, 16) + '...',
        eventType,
      });
    } catch (error) {
      logger.error('Failed to broadcast to user', {}, error instanceof Error ? error : new Error(String(error)));
    }
  }
}

export default PresenceBroadcaster;
