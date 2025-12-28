/**
 * User Activity Tracking Tests
 * 
 * Comprehensive tests for user activity tracking
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Database } from '../src/db/postgres.js';
import { updateUserActivity } from '../src/utils/user-activity.js';

describe('User Activity Tracking', () => {
  let mockDb: Partial<Database>;

  beforeEach(() => {
    mockDb = {
      pool: {
        query: vi.fn(),
      } as any,
    };
    vi.clearAllMocks();
  });

  describe('updateUserActivity', () => {
    it('should update user activity timestamp', async () => {
      (mockDb.pool!.query as any).mockResolvedValueOnce({
        rows: [],
      });

      const userId = 'a'.repeat(64);
      await updateUserActivity(mockDb as Database, userId);

      expect(mockDb.pool!.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE users SET last_activity = NOW()'),
        [userId]
      );
    });

    it('should handle database errors gracefully', async () => {
      (mockDb.pool!.query as any).mockRejectedValueOnce(new Error('Database error'));

      // Should not throw (errors are caught internally)
      await expect(
        updateUserActivity(mockDb as Database, 'a'.repeat(64))
      ).resolves.not.toThrow();
    });

    it('should update activity for different users', async () => {
      (mockDb.pool!.query as any)
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [] });

      const userId1 = 'a'.repeat(64);
      const userId2 = 'b'.repeat(64);

      await updateUserActivity(mockDb as Database, userId1);
      await updateUserActivity(mockDb as Database, userId2);

      expect(mockDb.pool!.query).toHaveBeenCalledTimes(2);
    });
  });
});

