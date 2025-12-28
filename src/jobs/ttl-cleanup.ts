/**
 * TTL Cleanup Job
 *
 * Periodically removes expired events from database
 * Runs every hour
 */

import type { Database } from '../db/postgres.js';
import { logger } from '../utils/logger.js';

/**
 * Cleanup expired events
 */
export async function cleanupExpiredEvents(db: Database): Promise<void> {
  try {
    const result = await db.pool.query(
      `DELETE FROM events 
       WHERE ttl IS NOT NULL 
       AND ttl < NOW() 
       RETURNING event_id`
    );

    if (result.rows.length > 0) {
      logger.info('Cleaned up expired events', { count: result.rows.length });
    }
  } catch (error) {
    logger.error(
      'Failed to cleanup expired events',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
  }
}

/**
 * Start TTL cleanup job
 */
export function startTTLCleanupJob(db: Database, intervalMs: number = 3600000): void {
  logger.info('Starting TTL cleanup job', { intervalMs });

  // Run immediately on start (handle promise to avoid unhandled rejection)
  cleanupExpiredEvents(db).catch(error => {
    logger.error(
      'TTL cleanup job error on startup',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
  });

  // Then run periodically
  setInterval(() => {
    cleanupExpiredEvents(db).catch(error => {
      logger.error(
        'TTL cleanup job error',
        {},
        error instanceof Error ? error : new Error(String(error))
      );
    });
  }, intervalMs);
}
