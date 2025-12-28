/**
 * Device Revocation Tests
 * 
 * Comprehensive tests for device revocation functionality
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Database } from '../src/db/postgres.js';
import { isDeviceRevoked, revokeDevice } from '../src/services/device-revocation.js';

describe('Device Revocation', () => {
  let mockDb: Partial<Database>;

  beforeEach(() => {
    mockDb = {
      pool: {
        query: vi.fn(),
      } as any,
    };
    vi.clearAllMocks();
  });

  describe('isDeviceRevoked', () => {
    it('should return false for non-revoked device', async () => {
      (mockDb.pool!.query as any).mockResolvedValueOnce({
        rows: [],
      });

      const result = await isDeviceRevoked(mockDb as Database, '550e8400-e29b-41d4-a716-446655440000');
      expect(result).toBe(false);
    });

    it('should return true for revoked device', async () => {
      (mockDb.pool!.query as any).mockResolvedValueOnce({
        rows: [{ device_id: '550e8400-e29b-41d4-a716-446655440000' }],
      });

      const result = await isDeviceRevoked(mockDb as Database, '550e8400-e29b-41d4-a716-446655440000');
      expect(result).toBe(true);
    });

    it('should handle database errors gracefully (fail-open)', async () => {
      (mockDb.pool!.query as any).mockRejectedValueOnce(new Error('Database error'));

      // isDeviceRevoked catches errors and returns false (fail-open)
      const result = await isDeviceRevoked(mockDb as Database, '550e8400-e29b-41d4-a716-446655440000');
      expect(result).toBe(false);
    });
  });

  describe('revokeDevice', () => {
    it('should revoke a device', async () => {
      (mockDb.pool!.query as any).mockResolvedValueOnce({
        rows: [],
      });

      await revokeDevice(
        mockDb as Database,
        '550e8400-e29b-41d4-a716-446655440000',
        'a'.repeat(64),
        'Test revocation'
      );

      expect(mockDb.pool!.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO revoked_devices'),
        expect.arrayContaining([
          '550e8400-e29b-41d4-a716-446655440000',
          'a'.repeat(64),
          'Test revocation',
        ])
      );
    });

    it('should revoke device without reason', async () => {
      (mockDb.pool!.query as any).mockResolvedValueOnce({
        rows: [],
      });

      await revokeDevice(
        mockDb as Database,
        '550e8400-e29b-41d4-a716-446655440000',
        'a'.repeat(64)
      );

      expect(mockDb.pool!.query).toHaveBeenCalled();
    });

    it('should handle database errors', async () => {
      (mockDb.pool!.query as any).mockRejectedValueOnce(new Error('Database error'));

      await expect(
        revokeDevice(
          mockDb as Database,
          '550e8400-e29b-41d4-a716-446655440000',
          'a'.repeat(64)
        )
      ).rejects.toThrow('Database error');
    });
  });
});

