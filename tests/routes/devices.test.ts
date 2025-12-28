/**
 * Devices Route Tests
 * 
 * Tests for /api/devices endpoints
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import express from 'express';
import devicesRouter from '../../src/routes/devices.js';
import type { Database } from '../../src/db/postgres.js';
import DeviceRelay from '../../src/services/device-relay.js';

describe('Devices Routes', () => {
  let app: express.Application;
  let mockDb: Partial<Database>;
  let mockDeviceRelay: Partial<DeviceRelay>;
  const userId = 'a'.repeat(64);

  beforeEach(async () => {
    app = express();
    app.use(express.json());
    // Bypass JWT middleware for tests by setting userId directly
    app.use('/api/devices', (req, res, next) => {
      const userId = req.headers['x-user-id'] as string;
      if (userId) {
        (req as any).userId = userId;
      }
      next();
    });
    app.use('/api', devicesRouter);

    mockDb = {
      pool: {
        query: vi.fn(),
      } as any,
    };

    mockDeviceRelay = {
      getUserDevices: vi.fn(),
    };

    // Set up route dependencies
    const devicesModule = await import('../../src/routes/devices.js');
    devicesModule.setDatabase(mockDb as Database);
    devicesModule.setSessionsMap(new Map());
    // Note: setDeviceRelay doesn't exist in devices.ts, it uses database directly
  });

  describe('GET /api/devices', () => {
    it('should return devices for authenticated user', async () => {
      const mockDevices = [
        {
          device_id: '550e8400-e29b-41d4-a716-446655440000',
          device_name: 'Device 1',
          device_type: 'desktop',
          device_os: 'windows',
          is_online: true,
          last_seen: Date.now(),
        },
        {
          device_id: '660e8400-e29b-41d4-a716-446655440001',
          device_name: 'Device 2',
          device_type: 'mobile',
          device_os: 'ios',
          is_online: false,
          last_seen: Date.now() - 86400000,
        },
      ];

      (mockDb.pool!.query as any).mockResolvedValue({
        rows: mockDevices.map(d => ({
          device_id: d.device_id,
          device_name: d.device_name,
          device_type: d.device_type,
          device_os: d.device_os,
          last_seen: new Date(d.last_seen),
          registered_at: new Date(),
          ip_address: null,
        })),
      });

      const response = await request(app)
        .get('/api/devices')
        .set('X-User-ID', userId)
        .expect(200);

      expect(response.body).toHaveProperty('devices');
      expect(response.body).toHaveProperty('count');
      expect(response.body.devices).toHaveLength(2);
      expect(response.body.count).toBe(2);
    });

    it('should require authentication', async () => {
      await request(app)
        .get('/api/devices')
        .expect(401);
    });

    it('should validate user ID format', async () => {
      await request(app)
        .get('/api/devices')
        .set('X-User-ID', 'invalid-user-id')
        .expect(400);
    });

    it('should handle database errors', async () => {
      (mockDb.pool!.query as any).mockRejectedValue(new Error('Database error'));

      await request(app)
        .get('/api/devices')
        .set('X-User-ID', userId)
        .expect(500);
    });
  });
});

