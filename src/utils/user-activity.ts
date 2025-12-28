/**
 * User Activity Tracking Utilities
 *
 * Updates user last_activity timestamp for engagement tracking
 */

import type { Database } from '../db/postgres.js';
import { logger } from './logger.js';

/**
 * Update user activity timestamp
 *
 * This should be called on each API request and event processing
 * to track user engagement.
 *
 * @param db - Database connection
 * @param userId - User ID (Ed25519 public key hex)
 */
export async function updateUserActivity(db: Database, userId: string): Promise<void> {
  try {
    await db.pool.query(`UPDATE users SET last_activity = NOW() WHERE user_id = $1`, [userId]);
  } catch (error) {
    // Log but don't throw - activity tracking is not critical
    logger.debug(
      'Failed to update user activity',
      {
        userId: userId.substring(0, 16) + '...',
      },
      error instanceof Error ? error : new Error(String(error))
    );
  }
}
