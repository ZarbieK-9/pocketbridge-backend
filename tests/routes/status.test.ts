/**
 * Status Route Tests
 * 
 * Tests for /api/status endpoint
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import express from 'express';
import statusRouter from '../../src/routes/status.js';

describe('Status Routes', () => {
  let app: express.Application;
  let mockSessions: Map<string, any>;

  beforeEach(async () => {
    app = express();
    app.use(express.json());
    app.use('/api', statusRouter);

    mockSessions = new Map();
    const statusModule = await import('../../src/routes/status.js');
    statusModule.setSessionsMap(mockSessions);
  });

  describe('GET /api/connection-status', () => {
    it('should return connection status for device', async () => {
      const deviceId = 'device1';
      const userId = 'a'.repeat(64);
      
      mockSessions.set(deviceId, {
        userId,
        deviceId,
        sessionKeys: { clientKey: Buffer.from('key'), serverKey: Buffer.from('key') },
        lastAckDeviceSeq: 0,
        createdAt: Date.now(),
      });

      const response = await request(app)
        .get('/api/connection-status')
        .query({ deviceId })
        .expect(200);

      expect(response.body).toHaveProperty('connected', true);
      expect(response.body.deviceId).toBe(deviceId);
    });

    it('should return disconnected for non-existent device', async () => {
      const response = await request(app)
        .get('/api/connection-status')
        .query({ deviceId: 'nonexistent' })
        .expect(200);

      expect(response.body).toHaveProperty('connected', false);
    });
  });
});

