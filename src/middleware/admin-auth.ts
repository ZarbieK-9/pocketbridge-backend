/**
 * Admin Authentication Middleware
 *
 * Protects admin routes with basic authentication
 * In production, replace with proper JWT/OAuth authentication
 */

import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger.js';
import { config } from '../config.js';
import { AuthenticationError } from '../utils/errors.js';

/**
 * Admin authentication middleware
 *
 * Uses ADMIN_API_KEY environment variable for basic auth
 * In production, replace with proper JWT/OAuth
 */
export function adminAuthMiddleware(req: Request, res: Response, next: NextFunction): void {
  const adminApiKey = process.env.ADMIN_API_KEY;

  // If no admin key is set, allow in development but warn
  if (!adminApiKey) {
    if (config.nodeEnv === 'production') {
      logger.error('ADMIN_API_KEY not set in production! Admin routes are unprotected.');
      res.status(500).json({
        error: 'Server configuration error: Admin authentication not configured',
      });
      return;
    } else {
      logger.warn('ADMIN_API_KEY not set. Admin routes are unprotected in development.');
      next(); // Allow in development
      return;
    }
  }

  // Check for API key in header
  const providedKey =
    req.headers['x-admin-api-key'] || req.headers['authorization']?.replace('Bearer ', '');

  if (!providedKey || providedKey !== adminApiKey) {
    logger.warn('Admin authentication failed', {
      requestId: (req as any).requestId,
      path: req.path,
      ip: req.ip,
    });
    res.status(401).json({
      error: 'Unauthorized',
      code: 'ADMIN_AUTH_REQUIRED',
    });
    return;
  }

  // Authentication successful
  (req as any).isAdmin = true;
  next();
}
