/**
 * Audit Logging
 * 
 * Logs security-relevant events for audit trail
 */

import { logger } from './logger.js';

export enum AuditEventType {
  AUTHENTICATION_SUCCESS = 'auth_success',
  AUTHENTICATION_FAILURE = 'auth_failure',
  RATE_LIMIT_HIT = 'rate_limit_hit',
  CONNECTION_LIMIT_EXCEEDED = 'connection_limit_exceeded',
  INVALID_INPUT = 'invalid_input',
  SESSION_EXPIRED = 'session_expired',
  HANDSHAKE_TIMEOUT = 'handshake_timeout',
  DEVICE_REVOKED = 'device_revoked',
}

interface AuditLogEntry {
  timestamp: number;
  type: AuditEventType;
  userId?: string;
  deviceId?: string;
  clientId?: string;
  details?: Record<string, unknown>;
}

/**
 * Log audit event
 */
export function auditLog(
  type: AuditEventType,
  context: {
    userId?: string;
    deviceId?: string;
    clientId?: string;
    details?: Record<string, unknown>;
  }
): void {
  const entry: AuditLogEntry = {
    timestamp: Date.now(),
    type,
    ...context,
  };

  // Log with special prefix for easy filtering
  logger.warn(`[AUDIT] ${type}`, {
    audit: true,
    ...entry,
  });
}















