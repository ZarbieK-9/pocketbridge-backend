/**
 * Event Handler
 *
 * Processes incoming encrypted events:
 * - Validates metadata
 * - Stores in PostgreSQL (replay index)
 * - Routes via Redis Pub/Sub
 * - Never decrypts payloads
 */

import type { Database } from '../db/postgres.js';
import type { RedisConnection } from '../db/redis.js';
import type { SessionState, EncryptedEvent } from '../types/index.js';
import { getUserDeviceChannel } from '../db/redis.js';
import {
  validateEventId,
  validateUserId,
  validateDeviceId,
  validateStreamId,
  validateEventType,
  validateEncryptedPayload,
  validateDeviceSeq,
  validateTTL,
} from '../utils/validation.js';
import { rateLimitEvent, rateLimitUserEvent } from '../middleware/rate-limit.js';
import { withTimeout, TIMEOUTS } from '../utils/timeouts.js';
import { ValidationError } from '../utils/errors.js';
import { logger } from '../utils/logger.js';
import { auditLog, AuditEventType } from '../utils/audit-log.js';
import type DeviceRelay from '../services/device-relay.js';
import { incrementCounter, recordHistogram } from '../services/metrics.js';
import { databaseCircuitBreaker, redisCircuitBreaker } from '../services/circuit-breaker.js';
import { isDeviceRevoked } from '../services/device-revocation.js';

/**
 * Handle incoming encrypted event
 *
 * This is the core relay function - it receives events from one device
 * and automatically relays them to all other devices of the same user.
 */
export async function handleEvent(
  event: unknown,
  sessionState: SessionState,
  db: Database,
  redis: RedisConnection,
  deviceRelay?: DeviceRelay
): Promise<void> {
  // Check if device is revoked (security: prevent revoked devices from sending events)
  const revoked = await isDeviceRevoked(db, sessionState.deviceId);
  if (revoked) {
    auditLog(AuditEventType.DEVICE_REVOKED, {
      userId: sessionState.userId,
      deviceId: sessionState.deviceId,
      details: { reason: 'Revoked device attempted to send event' },
    });
    throw new ValidationError('Device has been revoked');
  }

  // Check if device still exists (race condition: device deleted during event processing)
  const deviceCheck = await db.pool.query(
    `SELECT device_id FROM user_devices WHERE device_id = $1::uuid AND user_id = $2`,
    [sessionState.deviceId, sessionState.userId]
  );
  if (deviceCheck.rows.length === 0) {
    logger.warn('Device not found during event processing (may have been deleted)', {
      deviceId: sessionState.deviceId,
      userId: sessionState.userId.substring(0, 16) + '...',
    });
    throw new ValidationError('Device not found or has been deleted');
  }

  // Rate limit: Per-user event rate (1000 events/min per user, all devices combined)
  const userRateLimit = rateLimitUserEvent(sessionState.userId);
  if (!userRateLimit.allowed) {
    throw new ValidationError(userRateLimit.error || 'Event rate limit exceeded');
  }

  // Validate event structure
  if (!isValidEncryptedEvent(event)) {
    throw new ValidationError('Invalid event structure');
  }

  const encryptedEvent = event as EncryptedEvent;

  // If user_id is missing or empty, use sessionState.userId (fallback for compatibility)
  if (!encryptedEvent.user_id || encryptedEvent.user_id.trim() === '') {
    encryptedEvent.user_id = sessionState.userId;
  }

  // Validate all input fields
  try {
    validateEventId(encryptedEvent.event_id);
    validateUserId(encryptedEvent.user_id);
    validateDeviceId(encryptedEvent.device_id);
    validateStreamId(encryptedEvent.stream_id);
    validateEventType(encryptedEvent.type);
    validateEncryptedPayload(encryptedEvent.encrypted_payload);
    validateDeviceSeq(encryptedEvent.device_seq);

    // Validate TTL with clock skew tolerance (±5 minutes)
    if (encryptedEvent.ttl !== undefined && !validateTTL(encryptedEvent.ttl)) {
      throw new ValidationError('Event TTL has expired (considering clock skew tolerance)');
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const isValidationError = error instanceof ValidationError;

    // Audit log for security monitoring
    auditLog(AuditEventType.INVALID_INPUT, {
      userId: encryptedEvent.user_id,
      deviceId: encryptedEvent.device_id,
      details: { eventId: encryptedEvent.event_id, error: errorMessage },
    });

    // Log validation failure with context
    // Use debug level for expected validation errors (user input issues)
    // Use warn level for unexpected validation failures
    if (isValidationError) {
      logger.debug('Event validation failed (invalid user input)', {
        eventId: encryptedEvent.event_id,
        deviceId: encryptedEvent.device_id,
        validationError: errorMessage,
        field: errorMessage.includes('device_seq')
          ? 'device_seq'
          : errorMessage.includes('event_id')
            ? 'event_id'
            : errorMessage.includes('user_id')
              ? 'user_id'
              : errorMessage.includes('device_id')
                ? 'device_id'
                : errorMessage.includes('stream_id')
                  ? 'stream_id'
                  : errorMessage.includes('type')
                    ? 'type'
                    : errorMessage.includes('payload')
                      ? 'encrypted_payload'
                      : 'unknown',
      });
    } else {
      logger.warn('Event validation failed (unexpected error)', {
        eventId: encryptedEvent.event_id,
        deviceId: encryptedEvent.device_id,
        error: errorMessage,
      });
    }

    throw error;
  }

  // Validate event belongs to session
  if (encryptedEvent.user_id !== sessionState.userId) {
    throw new ValidationError('Event user_id mismatch');
  }

  if (encryptedEvent.device_id !== sessionState.deviceId) {
    throw new ValidationError('Event device_id mismatch');
  }

  // Validate device_seq is monotonic
  if (encryptedEvent.device_seq <= sessionState.lastAckDeviceSeq) {
    throw new ValidationError('Device sequence not monotonic');
  }

  // Assign stream_seq (get next sequence for this stream) with timeout and circuit breaker
  const streamSeqStart = Date.now();
  const streamSeq = await withTimeout(
    databaseCircuitBreaker.execute(
      async () => getNextStreamSeq(db, encryptedEvent.stream_id),
      'database'
    ),
    TIMEOUTS.DATABASE_QUERY,
    'Stream sequence assignment timed out'
  );
  recordHistogram('database_query_duration_ms', Date.now() - streamSeqStart, {
    operation: 'get_stream_seq',
  });
  incrementCounter('database_queries_total', { operation: 'get_stream_seq', status: 'success' });

  // Calculate payload size
  const payloadSize = Buffer.from(encryptedEvent.encrypted_payload, 'base64').length;

  // Check for conflicts: same stream_id + stream_seq from different devices
  // This implements "last write wins" conflict resolution
  const conflictCheck = await db.pool.query(
    `SELECT device_id, created_at FROM events 
     WHERE stream_id = $1 AND stream_seq = $2 AND device_id != $3
     ORDER BY created_at DESC LIMIT 1`,
    [encryptedEvent.stream_id, streamSeq, encryptedEvent.device_id]
  );

  if (conflictCheck.rows.length > 0) {
    const existingEvent = conflictCheck.rows[0];
    const existingTimestamp = new Date(existingEvent.created_at).getTime();
    const currentTimestamp = Date.now();

    logger.warn('Conflict detected: same stream_seq from different devices', {
      streamId: encryptedEvent.stream_id,
      streamSeq,
      existingDeviceId: existingEvent.device_id,
      currentDeviceId: encryptedEvent.device_id,
      existingTimestamp,
      currentTimestamp,
      winner: currentTimestamp > existingTimestamp ? 'current' : 'existing',
    });

    // Log conflict for audit trail
    await db.pool.query(
      `INSERT INTO conflict_log (
        stream_id, stream_seq, device_id_1, device_id_2, 
        timestamp_1, timestamp_2, resolution, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
      [
        encryptedEvent.stream_id,
        streamSeq,
        existingEvent.device_id,
        encryptedEvent.device_id,
        new Date(existingTimestamp),
        new Date(currentTimestamp),
        currentTimestamp > existingTimestamp ? 'current_wins' : 'existing_wins',
      ]
    );
  }

  // Store event metadata in PostgreSQL with timeout and circuit breaker
  // Also update user activity timestamp in the same transaction
  const storeStart = Date.now();
  try {
    await withTimeout(
      databaseCircuitBreaker.execute(async () => {
        const client = await db.pool.connect();
        try {
          await client.query('BEGIN');

          // Update user last_activity timestamp
          await client.query(`UPDATE users SET last_activity = NOW() WHERE user_id = $1`, [
            sessionState.userId,
          ]);

          // Store event
          await client.query(
            `INSERT INTO events (
                event_id, user_id, device_id, device_seq, stream_id, stream_seq,
                type, encrypted_payload, payload_size, ttl, created_at
              ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
              ON CONFLICT (event_id) DO NOTHING`,
            [
              encryptedEvent.event_id,
              encryptedEvent.user_id,
              encryptedEvent.device_id,
              encryptedEvent.device_seq,
              encryptedEvent.stream_id,
              streamSeq,
              encryptedEvent.type,
              encryptedEvent.encrypted_payload,
              payloadSize,
              encryptedEvent.ttl ? new Date(encryptedEvent.ttl) : null,
            ]
          );

          await client.query('COMMIT');
        } catch (error) {
          await client.query('ROLLBACK');
          throw error;
        } finally {
          client.release();
        }
      }, 'database'),
      TIMEOUTS.DATABASE_QUERY,
      'Event storage timed out'
    );
    recordHistogram('database_query_duration_ms', Date.now() - storeStart, {
      operation: 'store_event',
    });
    incrementCounter('database_queries_total', { operation: 'store_event', status: 'success' });
  } catch (error) {
    incrementCounter('database_queries_total', { operation: 'store_event', status: 'error' });
    throw error;
  }

  // Create event with server-assigned stream_seq
  const routedEvent: EncryptedEvent = {
    ...encryptedEvent,
    stream_seq: streamSeq,
    created_at: Date.now(),
  };

  // RELAY: Automatically route event to all other devices of the same user
  // This is the core relay functionality - connects devices together
  // Optimized: Parallel WebSocket sends for better performance with multiple devices
  const relayStart = Date.now();
  if (deviceRelay) {
    const relayResult = await deviceRelay.relayEventToUserDevices(
      routedEvent,
      sessionState.deviceId,
      sessionState.userId
    );

    recordHistogram('event_relay_duration_ms', Date.now() - relayStart);
    incrementCounter('events_relayed_total', {
      eventType: routedEvent.type,
      status: relayResult.relayed > 0 ? 'success' : 'no_targets',
    });

    if (relayResult.failed > 0) {
      incrementCounter('events_relay_failed_total', { eventType: routedEvent.type });
    }

    logger.info('Event relayed to user devices', {
      userId: sessionState.userId.substring(0, 16) + '...',
      senderDeviceId: sessionState.deviceId,
      relayed: relayResult.relayed,
      failed: relayResult.failed,
      targetDevices: relayResult.targetDevices,
      eventType: routedEvent.type,
      relayDurationMs: Date.now() - relayStart,
    });
  }

  // Also publish to Redis for horizontal scaling and persistence
  const redisStart = Date.now();
  try {
    const channel = `user:${sessionState.userId}:broadcast`;
    await withTimeout(
      redisCircuitBreaker.execute(async () => {
        await redis.client.publish(channel, JSON.stringify(routedEvent));
      }, 'redis'),
      TIMEOUTS.REDIS_OPERATION,
      'Redis publish timed out'
    );
    recordHistogram('redis_operation_duration_ms', Date.now() - redisStart, {
      operation: 'publish',
    });
    incrementCounter('redis_operations_total', { operation: 'publish', status: 'success' });

    // Also publish to specific device channels for direct routing
    const deviceChannel = getUserDeviceChannel(sessionState.userId, encryptedEvent.device_id);
    await withTimeout(
      redisCircuitBreaker.execute(async () => {
        await redis.client.publish(deviceChannel, JSON.stringify(routedEvent));
      }, 'redis'),
      TIMEOUTS.REDIS_OPERATION,
      'Redis publish timed out'
    );
    incrementCounter('redis_operations_total', { operation: 'publish', status: 'success' });
  } catch (error) {
    incrementCounter('redis_operations_total', { operation: 'publish', status: 'error' });
    // Don't throw - Redis failure shouldn't block event processing
    logger.warn(
      'Redis publish failed, continuing without Redis',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
  }

  // Track event processing
  incrementCounter('events_processed_total', { eventType: routedEvent.type, status: 'success' });
  recordHistogram('event_payload_size_bytes', payloadSize, { eventType: routedEvent.type });
}

/**
 * Get next stream sequence number
 */
async function getNextStreamSeq(db: Database, streamId: string): Promise<number> {
  // Use PostgreSQL atomic increment with timeout
  const result = await withTimeout(
    db.pool.query(
      `INSERT INTO stream_sequences (stream_id, last_stream_seq) 
     VALUES ($1, 1)
     ON CONFLICT (stream_id) 
     DO UPDATE SET last_stream_seq = stream_sequences.last_stream_seq + 1
     RETURNING last_stream_seq`,
      [streamId]
    ),
    TIMEOUTS.DATABASE_QUERY,
    'Stream sequence query timed out'
  );

  if (result.rows.length === 0) {
    throw new Error('Failed to get stream sequence');
  }

  return parseInt(result.rows[0].last_stream_seq, 10);
}

/**
 * Validate encrypted event structure
 */
function isValidEncryptedEvent(event: unknown): event is EncryptedEvent {
  if (typeof event !== 'object' || event === null) {
    return false;
  }

  const e = event as Record<string, unknown>;

  return (
    typeof e.event_id === 'string' &&
    typeof e.user_id === 'string' &&
    typeof e.device_id === 'string' &&
    typeof e.device_seq === 'number' &&
    typeof e.stream_id === 'string' &&
    typeof e.type === 'string' &&
    typeof e.encrypted_payload === 'string' &&
    (e.ttl === undefined || typeof e.ttl === 'number')
  );
}
