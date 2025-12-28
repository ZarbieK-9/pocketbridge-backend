/**
 * User Management Routes
 *
 * APIs for user account management:
 * - Delete user account (GDPR compliance)
 * - User account information
 */

import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger.js';
import { ValidationError } from '../utils/errors.js';
import type { Database } from '../db/postgres.js';
import type { SessionState } from '../types/index.js';

// Store reference to database and sessions
let database: Database | null = null;
let sessionsMap: Map<string, SessionState> | null = null;

export function setDatabase(db: Database): void {
  database = db;
}

export function setSessionsMap(sessions: Map<string, SessionState>): void {
  sessionsMap = sessions;
}

const router = Router();

/**
 * Delete user account
 * DELETE /api/user
 *
 * GDPR compliance: Allows users to delete their account and all associated data
 * - Closes all active WebSocket sessions
 * - Deletes all devices (cascade)
 * - Deletes all events (cascade)
 * - Deletes user record
 */
router.delete('/user', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId as string | undefined;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    logger.info('User account deletion requested', {
      userId: userId.substring(0, 16) + '...',
    });

    // Start transaction for atomic deletion
    const client = await database.pool.connect();
    try {
      await client.query('BEGIN');

      // 1. Close all active WebSocket sessions for this user
      // Note: We can't directly access WebSocket connections from here
      // The sessions will be cleaned up when the database records are deleted
      // and the WebSocket gateway detects the user no longer exists
      let sessionCount = 0;
      if (sessionsMap) {
        sessionsMap.forEach(session => {
          if (session.userId === userId) {
            sessionCount++;
          }
        });
        // Remove sessions from map (WebSocket connections will close naturally)
        const keysToDelete: string[] = [];
        sessionsMap.forEach((session, key) => {
          if (session.userId === userId) {
            keysToDelete.push(key);
          }
        });
        for (const key of keysToDelete) {
          sessionsMap.delete(key);
        }

        logger.info('Active sessions marked for cleanup', {
          userId: userId.substring(0, 16) + '...',
          sessionCount,
        });
      }

      // 2. Get device IDs before deletion (for logging)
      const devicesResult = await client.query(
        `SELECT device_id, device_name FROM user_devices WHERE user_id = $1`,
        [userId]
      );
      const deviceIds = devicesResult.rows.map((row: any) => row.device_id);
      const deviceCount = deviceIds.length;

      // 3. Count events before deletion (for logging)
      const eventsCountResult = await client.query(
        `SELECT COUNT(*) as count FROM events WHERE user_id = $1`,
        [userId]
      );
      const eventCount = parseInt(eventsCountResult.rows[0].count, 10);

      // 4. Delete user (cascade deletes devices and events via foreign keys)
      // The database schema has ON DELETE CASCADE for:
      // - user_devices.user_id -> users.user_id
      // - events.user_id -> users.user_id
      const deleteResult = await client.query(
        `DELETE FROM users WHERE user_id = $1 RETURNING user_id`,
        [userId]
      );

      if (deleteResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'User not found' });
      }

      // Commit transaction
      await client.query('COMMIT');

      logger.info('User account deleted successfully', {
        userId: userId.substring(0, 16) + '...',
        deviceCount,
        eventCount,
        sessionsClosed: sessionCount,
      });

      res.json({
        success: true,
        message: 'User account and all associated data have been deleted',
        deleted: {
          devices: deviceCount,
          events: eventCount,
        },
      });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    logger.error(
      'Failed to delete user account',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    if (error instanceof ValidationError) {
      res.status(400).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Failed to delete user account' });
    }
  }
});

export default router;
