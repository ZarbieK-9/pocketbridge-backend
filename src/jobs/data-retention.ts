/**
 * Data Retention Job
 *
 * Implements data retention policy:
 * - Events older than retention period are archived or deleted
 * - Inactive devices are cleaned up
 * - Old sessions are cleaned up
 */

import type { Database } from '../db/postgres.js';
import { logger } from '../utils/logger.js';
import { incrementCounter } from '../services/metrics.js';

interface RetentionConfig {
  eventRetentionDays: number; // Default: 90 days
  deviceInactiveDays: number; // Default: 365 days
  sessionRetentionDays: number; // Default: 30 days
}

const DEFAULT_CONFIG: RetentionConfig = {
  eventRetentionDays: parseInt(process.env.EVENT_RETENTION_DAYS || '90', 10),
  deviceInactiveDays: parseInt(process.env.DEVICE_INACTIVE_DAYS || '365', 10),
  sessionRetentionDays: parseInt(process.env.SESSION_RETENTION_DAYS || '30', 10),
};

/**
 * Clean up old events based on retention policy
 */
export async function cleanupOldEvents(
  db: Database,
  retentionDays: number = DEFAULT_CONFIG.eventRetentionDays
): Promise<number> {
  const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
  try {

    const result = await db.pool.query(
      `DELETE FROM events 
       WHERE created_at < $1 
       AND (ttl IS NULL OR ttl < $1)
       RETURNING event_id`,
      [cutoffDate]
    );

    const deletedCount = result.rows.length;

    if (deletedCount > 0) {
      logger.info('Cleaned up old events', {
        count: deletedCount,
        retentionDays,
        cutoffDate: cutoffDate.toISOString(),
      });
      incrementCounter('data_retention_events_deleted_total', {
        retentionDays: retentionDays.toString(),
      });
    }

    return deletedCount;
  } catch (error) {
    const errorContext = {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      retentionDays,
      cutoffDate: cutoffDate.toISOString(),
    };
    logger.error(errorContext, 'Failed to cleanup old events');
    console.error('[ERROR] Failed to cleanup old events:', {
      ...errorContext,
      fullError: error,
    });
    // Don't throw - event cleanup failure shouldn't stop other cleanup tasks
    return 0;
  }
}

/**
 * Clean up inactive devices
 */
export async function cleanupInactiveDevices(
  db: Database,
  inactiveDays: number = DEFAULT_CONFIG.deviceInactiveDays
): Promise<number> {
  const cutoffDate = new Date(Date.now() - inactiveDays * 24 * 60 * 60 * 1000);
  try {

    // Only clean up devices that are:
    // 1. Not online
    // 2. Haven't been seen in the retention period
    // 3. Have no recent events
    const result = await db.pool.query(
      `DELETE FROM user_devices
       WHERE is_online = FALSE
       AND last_seen < $1
       AND NOT EXISTS (
         SELECT 1 FROM events 
         WHERE events.device_id = user_devices.device_id
         AND events.created_at > $1
       )
       RETURNING device_id`,
      [cutoffDate]
    );

    const deletedCount = result.rows.length;

    if (deletedCount > 0) {
      logger.info('Cleaned up inactive devices', {
        count: deletedCount,
        inactiveDays,
        cutoffDate: cutoffDate.toISOString(),
      });
      incrementCounter('data_retention_devices_deleted_total', {
        inactiveDays: inactiveDays.toString(),
      });
    }

    return deletedCount;
  } catch (error) {
    const errorContext = {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      inactiveDays,
      cutoffDate: cutoffDate.toISOString(),
    };
    logger.error(errorContext, 'Failed to cleanup inactive devices');
    console.error('[ERROR] Failed to cleanup inactive devices:', {
      ...errorContext,
      fullError: error,
    });
    // Don't throw - device cleanup failure shouldn't stop other cleanup tasks
    return 0;
  }
}

/**
 * Clean up old sessions
 */
export async function cleanupOldSessions(
  db: Database,
  retentionDays: number = DEFAULT_CONFIG.sessionRetentionDays
): Promise<number> {
  const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
  try {

    const result = await db.pool.query(
      `DELETE FROM user_sessions
       WHERE expires_at < $1
       AND is_active = FALSE
       RETURNING session_id`,
      [cutoffDate]
    );

    const deletedCount = result.rows.length;

    if (deletedCount > 0) {
      logger.info('Cleaned up old sessions', {
        count: deletedCount,
        retentionDays,
        cutoffDate: cutoffDate.toISOString(),
      });
      incrementCounter('data_retention_sessions_deleted_total', {
        retentionDays: retentionDays.toString(),
      });
    }

    return deletedCount;
  } catch (error) {
    const errorContext = {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      retentionDays,
      cutoffDate: cutoffDate.toISOString(),
    };
    logger.error(errorContext, 'Failed to cleanup old sessions');
    console.error('[ERROR] Failed to cleanup old sessions:', {
      ...errorContext,
      fullError: error,
    });
    // Don't throw - session cleanup is not critical, continue with other cleanup tasks
    return 0;
  }
}

/**
 * Run all data retention cleanup tasks
 */
export async function runDataRetentionCleanup(
  db: Database,
  config: RetentionConfig = DEFAULT_CONFIG
): Promise<{
  eventsDeleted: number;
  devicesDeleted: number;
  sessionsDeleted: number;
}> {
  logger.info('Starting data retention cleanup', {
    eventRetentionDays: config.eventRetentionDays,
    deviceInactiveDays: config.deviceInactiveDays,
    sessionRetentionDays: config.sessionRetentionDays,
  });

  const [eventsDeleted, devicesDeleted, sessionsDeleted] = await Promise.all([
    cleanupOldEvents(db, config.eventRetentionDays),
    cleanupInactiveDevices(db, config.deviceInactiveDays),
    cleanupOldSessions(db, config.sessionRetentionDays),
  ]);

  logger.info('Data retention cleanup completed', {
    eventsDeleted,
    devicesDeleted,
    sessionsDeleted,
  });

  return {
    eventsDeleted,
    devicesDeleted,
    sessionsDeleted,
  };
}

/**
 * Start data retention job
 * Runs daily at specified time
 */
export function startDataRetentionJob(
  db: Database,
  intervalMs: number = 24 * 60 * 60 * 1000
): void {
  logger.info('Starting data retention job', { intervalMs });

  // Run immediately on start
  runDataRetentionCleanup(db).catch(error => {
    const errorContext = {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    };
    logger.error(errorContext, 'Data retention job error on startup');
    console.error('[ERROR] Data retention job error on startup:', {
      ...errorContext,
      fullError: error,
    });
  });

  // Then run periodically
  setInterval(() => {
    runDataRetentionCleanup(db).catch(error => {
      const errorContext = {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      };
      logger.error(errorContext, 'Data retention job error');
      console.error('[ERROR] Data retention job error:', {
        ...errorContext,
        fullError: error,
      });
    });
  }, intervalMs);
}
