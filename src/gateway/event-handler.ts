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
} from '../utils/validation.js';
import { rateLimitEvent, rateLimitUserEvent } from '../middleware/rate-limit.js';
import { withTimeout, TIMEOUTS } from '../utils/timeouts.js';
import { ValidationError } from '../utils/errors.js';
import { logger } from '../utils/logger.js';
import { auditLog, AuditEventType } from '../utils/audit-log.js';

/**
 * Handle incoming encrypted event
 */
export async function handleEvent(
  event: unknown,
  sessionState: SessionState,
  db: Database,
  redis: RedisConnection
): Promise<void> {
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
  } catch (error) {
    auditLog(AuditEventType.INVALID_INPUT, {
      userId: encryptedEvent.user_id,
      deviceId: encryptedEvent.device_id,
      details: { eventId: encryptedEvent.event_id, error: error instanceof Error ? error.message : String(error) },
    });
    logger.warn('Event validation failed', { 
      eventId: encryptedEvent.event_id,
      deviceId: encryptedEvent.device_id 
    });
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

  // Assign stream_seq (get next sequence for this stream) with timeout
  const streamSeq = await withTimeout(
    getNextStreamSeq(db, encryptedEvent.stream_id),
    TIMEOUTS.DATABASE_QUERY,
    'Stream sequence assignment timed out'
  );

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

  // Store event metadata in PostgreSQL with timeout
  await withTimeout(
    db.pool.query(
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
    ),
    TIMEOUTS.DATABASE_QUERY,
    'Event storage timed out'
  );

  // Create event with server-assigned stream_seq
  const routedEvent: EncryptedEvent = {
    ...encryptedEvent,
    stream_seq: streamSeq,
    created_at: Date.now(),
  };

  // Route to all user's devices via Redis with timeout
  const channel = `user:${sessionState.userId}:broadcast`;
  await withTimeout(
    redis.client.publish(channel, JSON.stringify(routedEvent)),
    TIMEOUTS.REDIS_OPERATION,
    'Redis publish timed out'
  );

  // Also publish to specific device channels for direct routing
  const deviceChannel = getUserDeviceChannel(sessionState.userId, encryptedEvent.device_id);
  await withTimeout(
    redis.client.publish(deviceChannel, JSON.stringify(routedEvent)),
    TIMEOUTS.REDIS_OPERATION,
    'Redis publish timed out'
  );
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

