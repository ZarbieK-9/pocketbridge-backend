/**
 * Events API Routes
 *
 * APIs for querying events:
 * - Get file transfer history (file:metadata events)
 * - Get events by type
 */

import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger.js';
import type { Database } from '../db/postgres.js';

// Store reference to database
let database: Database | null = null;

export function setDatabase(db: Database): void {
  database = db;
}

const router = Router();

/**
 * Get file transfer history
 * GET /api/events/files
 *
 * Returns file:metadata events for the authenticated user
 * The encrypted_payload contains file metadata that the client decrypts
 *
 * Query params:
 * - limit: number of events to return (default 50, max 100)
 * - offset: pagination offset (default 0)
 */
router.get('/events/files', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId as string | undefined;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
    const offset = parseInt(req.query.offset as string) || 0;

    // Query file:metadata events for this user
    const result = await database.pool.query(
      `SELECT
        event_id,
        device_id,
        stream_id,
        stream_seq,
        type,
        encrypted_payload,
        payload_size,
        created_at
      FROM events
      WHERE user_id = $1 AND type = 'file:metadata'
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );

    // Get total count for pagination
    const countResult = await database.pool.query(
      `SELECT COUNT(*) as count FROM events WHERE user_id = $1 AND type = 'file:metadata'`,
      [userId]
    );
    const total = parseInt(countResult.rows[0].count, 10);

    logger.debug('File history query', {
      userId: userId.substring(0, 16) + '...',
      count: result.rows.length,
      total,
    });

    res.json({
      events: result.rows,
      pagination: {
        limit,
        offset,
        total,
        hasMore: offset + result.rows.length < total,
      },
    });
  } catch (error) {
    logger.error(
      'Failed to get file history',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to get file history' });
  }
});

export default router;
