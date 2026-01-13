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
 * This is non-blocking - errors are logged but don't interrupt event processing
 * Implemented as fire-and-forget to avoid blocking the caller
 *
 * @param db - Database connection
 * @param userId - User ID (Ed25519 public key hex)
 */
export function updateUserActivity(db: Database, userId: string): void {
  // Fire and forget - don't await to avoid blocking event processing
  db.pool.query(`UPDATE users SET last_activity = NOW() WHERE user_id = $1`, [userId])
    .catch(error => {
      // Only log errors at debug level to avoid log spam
      logger.debug(
        'Failed to update user activity (non-blocking)',
        {
          userId: userId.substring(0, 16) + '...',
        },
        error instanceof Error ? error : new Error(String(error))
      );
    });
}
