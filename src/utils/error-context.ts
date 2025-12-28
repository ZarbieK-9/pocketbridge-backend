/**
 * Error Context Utilities
 *
 * Enhances errors with context for better debugging and logging
 */

import { Request } from 'express';
import type { SessionState } from '../types/index.js';

export interface ErrorContext {
  requestId?: string;
  userId?: string;
  deviceId?: string;
  apiVersion?: string;
  path?: string;
  method?: string;
  ip?: string;
  timestamp: number;
}

/**
 * Create error context from request
 */
export function createErrorContext(req: Request): ErrorContext {
  return {
    requestId: (req as any).requestId,
    userId: (req as any).userId,
    apiVersion: (req as any).apiVersion,
    path: req.path,
    method: req.method,
    ip: req.ip || req.socket.remoteAddress,
    timestamp: Date.now(),
  };
}

/**
 * Create error context from session state
 */
export function createErrorContextFromSession(sessionState: SessionState): ErrorContext {
  return {
    userId: sessionState.userId,
    deviceId: sessionState.deviceId,
    timestamp: Date.now(),
  };
}

/**
 * Enhance error with context
 */
export function enhanceError(
  error: Error,
  context: ErrorContext
): Error & { context: ErrorContext } {
  (error as any).context = context;
  return error as Error & { context: ErrorContext };
}
