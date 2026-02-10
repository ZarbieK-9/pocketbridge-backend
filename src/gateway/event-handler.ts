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

  // Validate device_seq hasn't been processed yet
  // Use a sliding window to track recent processed sequences
  // This prevents unbounded memory growth while detecting duplicates within a reasonable window
  const DEDUP_WINDOW_SIZE = 1000; // Keep track of last 1000 sequences

  // Initialize the dedup window if it doesn't exist
  if (!sessionState.processedDeviceSeqs) {
    sessionState.processedDeviceSeqs = new Set<number>();
  }

  // If sequence is older than our window (lastAckDeviceSeq - DEDUP_WINDOW_SIZE),
  // we assume it's already been processed
  const windowStart = Math.max(1, sessionState.lastAckDeviceSeq - DEDUP_WINDOW_SIZE);
  if (encryptedEvent.device_seq < windowStart) {
    logger.debug('Device sequence older than dedup window, treating as duplicate', {
      eventDeviceSeq: encryptedEvent.device_seq,
      windowStart,
      sessionLastAckDeviceSeq: sessionState.lastAckDeviceSeq,
      deviceId: sessionState.deviceId,
      eventId: encryptedEvent.event_id,
    });
    return;
  }

  // Check if this sequence was already processed (duplicate)
  if (sessionState.processedDeviceSeqs.has(encryptedEvent.device_seq)) {
    logger.debug('Device sequence already processed (duplicate event, ignoring)', {
      eventDeviceSeq: encryptedEvent.device_seq,
      sessionLastAckDeviceSeq: sessionState.lastAckDeviceSeq,
      processedSeqsSize: sessionState.processedDeviceSeqs.size,
      deviceId: sessionState.deviceId,
      userId: sessionState.userId?.substring(0, 16) + '...',
      eventId: encryptedEvent.event_id,
    });
    return;
  }

  // Mark this sequence as processed
  sessionState.processedDeviceSeqs.add(encryptedEvent.device_seq);

  // Clean up sequences outside the window (bounded cleanup)
  if (sessionState.processedDeviceSeqs.size > DEDUP_WINDOW_SIZE * 1.5) {
    // Remove all sequences older than windowStart
    for (const seq of sessionState.processedDeviceSeqs) {
      if (seq < windowStart) {
        sessionState.processedDeviceSeqs.delete(seq);
      }
    }
  }

  // GAP DETECTION: Check if device_seq indicates a gap in the sequence
  // If current device_seq > lastAckDeviceSeq + 1, we're missing events
  // NON-BLOCKING: Log the gap and request missing events, but still process
  // the current event immediately. Clients use Yjs CRDT which handles
  // out-of-order events, so strict ordering is not required for correctness.
  if (encryptedEvent.device_seq > sessionState.lastAckDeviceSeq + 1) {
    const gap = encryptedEvent.device_seq - sessionState.lastAckDeviceSeq - 1;
    const startSeq = sessionState.lastAckDeviceSeq + 1;
    const endSeq = encryptedEvent.device_seq - 1;

    logger.warn('Sequence gap detected (non-blocking)', {
      deviceId: sessionState.deviceId,
      userId: sessionState.userId.substring(0, 16) + '...',
      lastAckDeviceSeq: sessionState.lastAckDeviceSeq,
      receivedDeviceSeq: encryptedEvent.device_seq,
      gap,
      missingRange: `${startSeq}-${endSeq}`,
      eventId: encryptedEvent.event_id,
    });

    // Request missing events from client (best-effort, don't block)
    sendMissingEventsRequest(
      sessionState,
      deviceRelay,
      startSeq,
      endSeq
    ).catch(err => logger.warn('Failed to request missing events', { error: String(err) }));

    // Increment gap detection metric
    incrementCounter('sequence_gaps_detected_total', {
      deviceId: sessionState.deviceId,
    });

    // Continue processing — don't block event relay
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
  // IMPORTANT: Device existence check is done INSIDE the transaction to prevent race conditions
  // where the device is deleted between validation and storage
  const storeStart = Date.now();
  try {
    await withTimeout(
      databaseCircuitBreaker.execute(async () => {
        const client = await db.pool.connect();
        try {
          await client.query('BEGIN');

          // Re-verify device exists INSIDE transaction (prevents race condition with device deletion)
          // Use FOR SHARE to allow concurrent reads but prevent deletion during this transaction
          const deviceCheckInTx = await client.query(
            `SELECT device_id FROM user_devices
             WHERE device_id = $1::uuid AND user_id = $2
             FOR SHARE`,
            [sessionState.deviceId, sessionState.userId]
          );
          if (deviceCheckInTx.rows.length === 0) {
            throw new ValidationError('Device was deleted during event processing');
          }

          // Update user last_activity timestamp
          await client.query(`UPDATE users SET last_activity = NOW() WHERE user_id = $1`, [
            sessionState.userId,
          ]);

          // Store event
          // Use sessionState.deviceId to ensure we have the correct UUID format
          // encryptedEvent.device_id should match, but we use sessionState for safety
          await client.query(
            `INSERT INTO events (
                event_id, user_id, device_id, device_seq, stream_id, stream_seq,
                type, encrypted_payload, payload_size, ttl, created_at
              ) VALUES ($1, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10, NOW())
              ON CONFLICT (event_id) DO NOTHING`,
            [
              encryptedEvent.event_id,
              encryptedEvent.user_id,
              sessionState.deviceId, // Use sessionState.deviceId (guaranteed to be UUID)
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

  // CRITICAL: Update lastAckDeviceSeq in session state after successful storage
  // Use Math.max to handle out-of-order event processing (events may arrive in different order)
  // Must happen BEFORE relaying to prevent race conditions
  sessionState.lastAckDeviceSeq = Math.max(sessionState.lastAckDeviceSeq, encryptedEvent.device_seq);

  // Also persist to DB so it's loaded correctly on reconnect
  // Use GREATEST to prevent regression in case of concurrent updates
  try {
    await db.pool.query(
      `UPDATE user_devices
       SET last_ack_device_seq = GREATEST(last_ack_device_seq, $1)
       WHERE device_id = $2::uuid`,
      [encryptedEvent.device_seq, sessionState.deviceId]
    );
  } catch (dbError) {
    // Log but don't fail the event - in-memory state is already updated
    logger.warn('Failed to persist last_ack_device_seq to DB', {
      deviceId: sessionState.deviceId,
      deviceSeq: encryptedEvent.device_seq,
      error: dbError instanceof Error ? dbError.message : String(dbError),
    });
  }

  // GAP FILL: Check if this event fills a gap and process buffered events
  if (sessionState.bufferedEvents && sessionState.bufferedEvents.size > 0) {
    await processBufferedEvents(
      sessionState,
      db,
      redis,
      deviceRelay
    );
  }

  // Create event with server-assigned stream_seq
  const routedEvent: EncryptedEvent = {
    ...encryptedEvent,
    stream_seq: streamSeq,
    created_at: Date.now(),
  };

  // FILE EVENT TRACING: Log file events for debugging file transfer issues
  if (routedEvent.type.startsWith('file:')) {
    logger.info('FILE EVENT RECEIVED', {
      eventType: routedEvent.type,
      eventId: routedEvent.event_id,
      streamId: routedEvent.stream_id,
      senderDeviceId: sessionState.deviceId,
      userId: sessionState.userId.substring(0, 16) + '...',
      payloadSize: payloadSize,
    });
  }

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

  // ACTIVITY EVENTS: Emit system message for activity tracking (e.g., file synced)
  // This allows the dashboard to show real-time activity without polling
  if (routedEvent.type === 'file:metadata' && deviceRelay) {
    try {
      await deviceRelay.broadcastSystemMessage(
        sessionState.userId,
        {
          type: 'activity:event',
          payload: {
            event_id: routedEvent.event_id,
            device_id: routedEvent.device_id,
            type: 'file:metadata',
            created_at: Date.now(),
            payload_size: payloadSize,
          },
        },
        sessionState.deviceId // Exclude sender device
      );
      logger.debug('Activity event broadcast for file:metadata', {
        eventId: routedEvent.event_id,
        userId: sessionState.userId.substring(0, 16) + '...',
      });
    } catch (error) {
      // Log but don't fail - activity tracking shouldn't block event processing
      logger.warn(
        'Failed to broadcast activity:event system message',
        { eventId: routedEvent.event_id },
        error instanceof Error ? error : new Error(String(error))
      );
    }
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

/**
 * Request missing events from client to fill sequence gap
 */
async function sendMissingEventsRequest(
  sessionState: SessionState,
  deviceRelay: DeviceRelay | undefined,
  startSeq: number,
  endSeq: number
): Promise<void> {
  if (!deviceRelay) {
    logger.error('Cannot request missing events: deviceRelay not available');
    return;
  }

  try {
    const message = {
      type: 'missing_events_request',
      payload: {
        startSeq,
        endSeq,
      },
    };

    // Send request directly to the device that has the gap
    const sent = deviceRelay.sendToDevice(
      sessionState.userId,
      sessionState.deviceId,
      message
    );

    if (!sent) {
      throw new Error('Failed to send missing events request: device not connected');
    }

    logger.info('Sent missing events request to client', {
      deviceId: sessionState.deviceId,
      userId: sessionState.userId.substring(0, 16) + '...',
      startSeq,
      endSeq,
      gap: endSeq - startSeq + 1,
    });

    // Increment metric
    incrementCounter('missing_events_requests_sent_total', {
      deviceId: sessionState.deviceId,
    });
  } catch (error) {
    logger.error('Failed to send missing events request', {
      deviceId: sessionState.deviceId,
      startSeq,
      endSeq,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

/**
 * Process buffered out-of-order events after gap is filled
 */
async function processBufferedEvents(
  sessionState: SessionState,
  db: Database,
  redis: RedisConnection,
  deviceRelay?: DeviceRelay
): Promise<void> {
  if (!sessionState.bufferedEvents) return;

  // Sort buffered events by device_seq
  const buffered = Array.from(sessionState.bufferedEvents.entries())
    .sort((a, b) => a[0] - b[0]);

  let processed = 0;
  let failed = 0;

  for (const [seq, event] of buffered) {
    // Check if we can now process this event
    // Event can be processed if it's the next expected sequence
    if (seq === sessionState.lastAckDeviceSeq + 1) {
      try {
        // Process the buffered event (recursive call to handleEvent)
        await handleEvent(event, sessionState, db, redis, deviceRelay);

        // Remove from buffer
        sessionState.bufferedEvents.delete(seq);
        processed++;

        logger.info('Processed buffered event after gap fill', {
          deviceSeq: seq,
          eventId: event.event_id,
          deviceId: sessionState.deviceId,
        });
      } catch (error) {
        failed++;
        logger.error('Failed to process buffered event', {
          deviceSeq: seq,
          eventId: event.event_id,
          error: error instanceof Error ? error.message : String(error),
        });
        // Keep in buffer for retry
      }
    } else if (seq < sessionState.lastAckDeviceSeq) {
      // Event is now obsolete (gap was filled by resent event)
      sessionState.bufferedEvents.delete(seq);
      logger.debug('Removed obsolete buffered event', {
        deviceSeq: seq,
        lastAckDeviceSeq: sessionState.lastAckDeviceSeq,
      });
    }
  }

  if (processed > 0 || failed > 0) {
    logger.info('Buffered events processing complete', {
      processed,
      failed,
      remaining: sessionState.bufferedEvents.size,
      deviceId: sessionState.deviceId,
    });

    // Increment metrics
    incrementCounter('buffered_events_processed_total', {
      status: 'success',
      count: String(processed),
    });
    if (failed > 0) {
      incrementCounter('buffered_events_processed_total', {
        status: 'failed',
        count: String(failed),
      });
    }
  }

  // Clean up buffer if it gets too large (prevent memory leak)
  const MAX_BUFFER_SIZE = 100;
  if (sessionState.bufferedEvents.size > MAX_BUFFER_SIZE) {
    logger.warn('Buffer size exceeded limit, clearing old events', {
      bufferSize: sessionState.bufferedEvents.size,
      maxSize: MAX_BUFFER_SIZE,
      deviceId: sessionState.deviceId,
    });

    // Keep only the most recent events
    const sorted = Array.from(sessionState.bufferedEvents.keys()).sort((a, b) => b - a);
    sorted.slice(MAX_BUFFER_SIZE).forEach(seq => {
      sessionState.bufferedEvents!.delete(seq);
    });

    incrementCounter('buffer_overflow_events_discarded_total', {
      discarded: String(sorted.length - MAX_BUFFER_SIZE),
    });
  }
}
