/**
 * Input Validation Utilities
 *
 * Validates all user inputs to prevent:
 * - Injection attacks
 * - DoS via large inputs
 * - Invalid data formats
 */

import { ValidationError } from './errors.js';

// Constants
export const MAX_PAYLOAD_SIZE = 15 * 1024 * 1024; // 15MB per event (5MB chunks + encryption + double base64 overhead)
export const MAX_STREAM_ID_LENGTH = 256;
export const MAX_EVENT_TYPE_LENGTH = 64;
export const MAX_DEVICE_ID_LENGTH = 36; // UUIDv4
export const MAX_USER_ID_LENGTH = 64; // Ed25519 hex (32 bytes = 64 hex chars)
export const MAX_EVENT_ID_LENGTH = 36; // UUIDv7
export const MAX_REPLAY_EVENTS = 1000;

/**
 * Validate UUIDv4 format
 */
export function validateUUIDv4(id: string): boolean {
  const uuidv4Regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidv4Regex.test(id);
}

/**
 * Validate UUIDv7 format (simplified - checks structure)
 */
export function validateUUIDv7(id: string): boolean {
  // UUIDv7: xxxxxxxx-xxxx-7xxx-xxxx-xxxxxxxxxxxx
  const uuidv7Regex = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidv7Regex.test(id);
}

/**
 * Validate generic UUID format (v4 or v7)
 */
export function validateUUID(id: string): boolean {
  return validateUUIDv4(id) || validateUUIDv7(id);
}

/**
 * Validate Ed25519 public key (hex format, 64 chars)
 */
export function validateEd25519PublicKey(key: string): boolean {
  // Ed25519 public key is 32 bytes = 64 hex characters
  const hexRegex = /^[0-9a-f]{64}$/i;
  return hexRegex.test(key);
}

/**
 * Validate device ID
 */
export function validateDeviceId(deviceId: string): void {
  if (!deviceId || typeof deviceId !== 'string') {
    throw new ValidationError('Device ID is required');
  }
  if (deviceId.length > MAX_DEVICE_ID_LENGTH) {
    throw new ValidationError('Device ID too long');
  }
  if (!validateUUIDv4(deviceId)) {
    throw new ValidationError('Invalid device ID format (must be UUIDv4)');
  }
}

/**
 * Validate user ID (Ed25519 public key)
 */
export function validateUserId(userId: string): void {
  if (!userId || typeof userId !== 'string') {
    throw new ValidationError('User ID is required');
  }
  if (userId.length > MAX_USER_ID_LENGTH) {
    throw new ValidationError('User ID too long');
  }
  if (!validateEd25519PublicKey(userId)) {
    throw new ValidationError('Invalid user ID format (must be Ed25519 public key hex)');
  }
}

/**
 * Validate event ID
 */
export function validateEventId(eventId: string): void {
  if (!eventId || typeof eventId !== 'string') {
    throw new ValidationError('Event ID is required');
  }
  if (eventId.length > MAX_EVENT_ID_LENGTH) {
    throw new ValidationError('Event ID too long');
  }
  if (!validateUUIDv7(eventId)) {
    throw new ValidationError('Invalid event ID format (must be UUIDv7)');
  }
}

/**
 * Validate stream ID
 */
export function validateStreamId(streamId: string): void {
  if (!streamId || typeof streamId !== 'string') {
    throw new ValidationError('Stream ID is required');
  }
  if (streamId.length > MAX_STREAM_ID_LENGTH) {
    throw new ValidationError('Stream ID too long');
  }
  // Stream ID should be alphanumeric with :, -, _ allowed
  const streamIdRegex = /^[a-zA-Z0-9:_-]+$/;
  if (!streamIdRegex.test(streamId)) {
    throw new ValidationError('Invalid stream ID format');
  }
}

/**
 * Validate event type
 */
export function validateEventType(type: string): void {
  if (!type || typeof type !== 'string') {
    throw new ValidationError('Event type is required');
  }
  if (type.length > MAX_EVENT_TYPE_LENGTH) {
    throw new ValidationError('Event type too long');
  }
  // Event type should be alphanumeric with :, -, _ allowed
  const eventTypeRegex = /^[a-zA-Z0-9:_-]+$/;
  if (!eventTypeRegex.test(type)) {
    throw new ValidationError('Invalid event type format');
  }
}

/**
 * Validate encrypted payload
 */
export function validateEncryptedPayload(payload: string): void {
  if (!payload || typeof payload !== 'string') {
    throw new ValidationError('Encrypted payload is required');
  }

  // Decode base64 to check size
  try {
    const decoded = Buffer.from(payload, 'base64');
    if (decoded.length > MAX_PAYLOAD_SIZE) {
      throw new ValidationError(`Payload too large (max ${MAX_PAYLOAD_SIZE / 1024 / 1024}MB)`);
    }
    if (decoded.length === 0) {
      throw new ValidationError('Payload cannot be empty');
    }
  } catch (error) {
    if (error instanceof ValidationError) {
      throw error;
    }
    throw new ValidationError('Invalid base64 payload format');
  }
}

/**
 * Validate device sequence
 */
export function validateDeviceSeq(deviceSeq: number): void {
  if (typeof deviceSeq !== 'number' || !Number.isInteger(deviceSeq)) {
    throw new ValidationError('Device sequence must be an integer');
  }
  if (deviceSeq < 1) {
    throw new ValidationError('Device sequence must be >= 1');
  }
  if (deviceSeq > Number.MAX_SAFE_INTEGER) {
    throw new ValidationError('Device sequence too large');
  }
}

/**
 * Validate replay request
 */
export function validateReplayRequest(lastAckDeviceSeq: number): void {
  validateDeviceSeq(lastAckDeviceSeq);
  // Additional validation: ensure reasonable range
  if (lastAckDeviceSeq > 1000000) {
    throw new ValidationError('Replay request out of range');
  }
}

/**
 * Validate nonce format
 */
export function validateNonceFormat(nonce: string): boolean {
  // Nonce should be 32 bytes = 64 hex characters
  const hexRegex = /^[0-9a-f]{64}$/i;
  return hexRegex.test(nonce);
}

/**
 * Sanitize device name to ensure valid UTF-8 encoding
 * Removes invalid UTF-8 sequences and truncates to max length
 *
 * @param name - Device name to sanitize
 * @param maxLength - Maximum length (default: 50)
 * @returns Sanitized device name
 */
export function sanitizeDeviceName(name: string, maxLength: number = 50): string {
  if (typeof name !== 'string') {
    return '';
  }

  try {
    // Try to decode and re-encode as UTF-8 to remove invalid sequences
    const sanitized = Buffer.from(name, 'utf8').toString('utf8');
    // Truncate to max length
    return sanitized.slice(0, maxLength);
  } catch {
    // If UTF-8 encoding fails, fall back to ASCII-only
    // Remove non-printable characters and keep only ASCII printable range (32-126)
    const asciiOnly = name
      .split('')
      .filter(char => {
        const code = char.charCodeAt(0);
        return code >= 32 && code <= 126; // Printable ASCII range
      })
      .join('');
    return asciiOnly.slice(0, maxLength);
  }
}

/**
 * Validate TTL with clock skew tolerance
 *
 * Allows ±5 minutes tolerance for clock differences between devices
 *
 * @param ttl - TTL timestamp (Unix timestamp in milliseconds)
 * @param toleranceMs - Clock skew tolerance in milliseconds (default: 5 minutes)
 * @returns true if TTL is valid (not expired considering tolerance), false otherwise
 */
export function validateTTL(ttl: number | undefined, toleranceMs: number = 5 * 60 * 1000): boolean {
  if (ttl === undefined || ttl === null) {
    return true; // No TTL means no expiration
  }

  if (typeof ttl !== 'number') {
    throw new ValidationError('TTL must be a number');
  }

  const now = Date.now();
  // Consider TTL valid if it's within tolerance (allows for clock skew)
  // TTL is valid if: ttl >= (now - tolerance)
  // This means events are considered expired only if ttl < (now - tolerance)
  return ttl >= now - toleranceMs;
}
