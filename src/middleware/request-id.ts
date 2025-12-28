/**
 * Request ID Middleware
 *
 * Adds unique request ID to all requests for correlation tracking
 * - Generates UUID for each request
 * - Adds to response headers
 * - Includes in logs for tracing
 */

import { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';

/**
 * Add request ID to request and response
 */
export function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Generate or use existing request ID
  const requestId = (req.headers['x-request-id'] as string) || randomUUID();

  // Attach to request for use in handlers
  (req as any).requestId = requestId;

  // Add to response headers
  res.setHeader('X-Request-ID', requestId);

  // Add to logger context (if using structured logging)
  if ((req as any).logger) {
    (req as any).logger = (req as any).logger.child({ requestId });
  }

  next();
}

/**
 * Get request ID from request
 */
export function getRequestId(req: Request): string | undefined {
  return (req as any).requestId;
}
