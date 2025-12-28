/**
 * Pairing Route Tests
 * 
 * Tests for /api/pairing endpoints
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import express from 'express';
import pairingRouter from '../../src/routes/pairing.js';
import type { Database } from '../../src/db/postgres.js';

describe('Pairing Routes', () => {
  let app: express.Application;
  let mockDb: Partial<Database>;
  const userId = 'a'.repeat(64);
  const deviceId = '550e8400-e29b-41d4-a716-446655440000';

  beforeEach(async () => {
    app = express();
    app.use(express.json());
    app.use('/api/pairing', pairingRouter);

    mockDb = {
      pool: {
        query: vi.fn(),
      } as any,
    };

    const pairingModule = await import('../../src/routes/pairing.js');
    pairingModule.setDatabase(mockDb as Database);
  });

  describe('POST /api/pairing/store', () => {
    it('should store pairing code', async () => {
      const pairingCode = 'ABC123';
      const pairingData = {
        code: pairingCode,
        data: {
          wsUrl: 'ws://localhost:3001/ws',
          userId,
          deviceId,
          deviceName: 'Test Device',
          publicKeyHex: 'b'.repeat(64),
          privateKeyHex: 'c'.repeat(64),
        },
      };

      (mockDb.pool!.query as any)
        .mockResolvedValueOnce({ rows: [] }) // Delete existing
        .mockResolvedValueOnce({ rows: [] }); // Insert new

      const response = await request(app)
        .post('/api/pairing/store')
        .send(pairingData)
        .expect(200);

      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('expiresAt');
      expect(response.body).toHaveProperty('expiresIn');
    });

    it('should require code and data', async () => {
      await request(app)
        .post('/api/pairing/store')
        .send({ code: 'ABC123' })
        .expect(400);
    });

    it('should require all data fields', async () => {
      await request(app)
        .post('/api/pairing/store')
        .send({
          code: 'ABC123',
          data: {
            wsUrl: 'ws://localhost:3001/ws',
            // Missing other fields
          },
        })
        .expect(400);
    });
  });

  describe('GET /api/pairing/lookup/:code', () => {
    it('should retrieve pairing code data', async () => {
      const pairingCode = '123456'; // Must be 6 digits
      const mockData = {
        ws_url: 'ws://localhost:3001/ws',
        user_id: userId,
        device_id: deviceId,
        device_name: 'Test Device',
        public_key_hex: 'b'.repeat(64),
        private_key_hex: 'c'.repeat(64),
        expires_at: new Date(Date.now() + 10 * 60 * 1000),
      };

      (mockDb.pool!.query as any).mockResolvedValue({
        rows: [mockData],
      });

      const response = await request(app)
        .get(`/api/pairing/lookup/${pairingCode}`)
        .expect(200);

      expect(response.body).toHaveProperty('data');
      expect(response.body.data.wsUrl).toBe(mockData.ws_url);
      expect(response.body.data.userId).toBe(userId);
    });

    it('should return 404 for non-existent code', async () => {
      (mockDb.pool!.query as any).mockResolvedValue({
        rows: [],
      });

      await request(app)
        .get('/api/pairing/lookup/123456')
        .expect(404);
    });

    it('should return 400 for invalid code format', async () => {
      await request(app)
        .get('/api/pairing/lookup/INVALID')
        .expect(400);
    });

    it('should return 404 for expired code', async () => {
      const expiredData = {
        ws_url: 'ws://localhost:3001/ws',
        user_id: userId,
        device_id: deviceId,
        expires_at: new Date(Date.now() - 1000), // Expired
      };

      (mockDb.pool!.query as any).mockResolvedValue({
        rows: [], // Expired codes are filtered by SQL
      });

      await request(app)
        .get('/api/pairing/lookup/654321')
        .expect(404);
    });
  });
});

