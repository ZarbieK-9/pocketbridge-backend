/**
 * API Versioning Middleware
 *
 * Handles API versioning via URL path or header
 * Supports: /api/v1/... or X-API-Version header
 */

import { Request, Response, NextFunction } from 'express';

const SUPPORTED_VERSIONS = ['v1'];
const DEFAULT_VERSION = 'v1';

/**
 * Extract API version from request
 */
export function getApiVersion(req: Request): string {
  // Check URL path first: /api/v1/...
  const pathMatch = req.path.match(/^\/api\/(v\d+)\//);
  if (pathMatch) {
    return pathMatch[1];
  }

  // Check header
  const headerVersion = req.headers['x-api-version'] as string;
  if (headerVersion && SUPPORTED_VERSIONS.includes(headerVersion)) {
    return headerVersion;
  }

  // Default to v1
  return DEFAULT_VERSION;
}

/**
 * API versioning middleware
 * Adds version to request object
 */
export function apiVersionMiddleware(req: Request, res: Response, next: NextFunction): void {
  const version = getApiVersion(req);
  (req as any).apiVersion = version;

  // Add version to response headers
  res.setHeader('X-API-Version', version);

  // Validate version
  if (!SUPPORTED_VERSIONS.includes(version)) {
    res.status(400).json({
      error: 'Unsupported API version',
      supportedVersions: SUPPORTED_VERSIONS,
      requestedVersion: version,
    });
    return;
  }

  next();
}
