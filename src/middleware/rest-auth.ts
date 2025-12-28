/**
 * REST API Authentication Middleware
 *
 * Verifies user identity for REST API endpoints
 * Currently uses X-User-ID header (should be replaced with JWT in production)
 */

import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger.js';
import { validateEd25519PublicKey } from '../utils/validation.js';
import { AuthenticationError } from '../utils/errors.js';

/**
 * Verify user identity for REST API
 *
 * In production, this should:
 * 1. Extract JWT token from Authorization header
 * 2. Verify JWT signature
 * 3. Extract user_id from token claims
 * 4. Attach to request object
 *
 * For now, validates X-User-ID header format
 */
export function restAuthMiddleware(req: Request, res: Response, next: NextFunction): void {
  const userId = req.headers['x-user-id'] as string | undefined;

  // For health and metrics endpoints, allow without auth
  if (req.path === '/health' || req.path === '/metrics') {
    return next();
  }

  if (!userId) {
    logger.warn('REST API request without user ID', {
      requestId: (req as any).requestId,
      path: req.path,
      ip: req.ip,
    });
    res.status(401).json({
      error: 'Unauthorized',
      code: 'USER_ID_REQUIRED',
      message: 'X-User-ID header is required',
    });
    return;
  }

  // Validate user ID format (Ed25519 public key hex)
  if (!validateEd25519PublicKey(userId)) {
    logger.warn('Invalid user ID format in REST API request', {
      requestId: (req as any).requestId,
      path: req.path,
      userId: userId.substring(0, 16) + '...',
    });
    res.status(400).json({
      error: 'Invalid user ID format',
      code: 'INVALID_USER_ID',
      message: 'User ID must be a valid Ed25519 public key (64 hex characters)',
    });
    return;
  }

  // Attach to request
  (req as any).userId = userId;
  next();
}
