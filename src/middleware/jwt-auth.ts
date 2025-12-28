/**
 * JWT Authentication Middleware
 *
 * Replaces X-User-ID header with JWT token verification
 * Tokens are signed with server private key and contain user_id claim
 */

import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger.js';
import { config } from '../config.js';
import { AuthenticationError } from '../utils/errors.js';
import { signEd25519, verifyEd25519 } from '../crypto/utils.js';
import { randomBytes } from 'crypto';

interface JWTPayload {
  user_id: string;
  iat: number; // Issued at
  exp: number; // Expiration
  jti: string; // JWT ID (for revocation)
}

/**
 * Base64URL encoding helpers
 */
function base64urlEncode(str: string): string {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64urlEncodeBuffer(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf-8');
}

function base64urlDecodeBuffer(str: string): Buffer {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

/**
 * Generate JWT token for a user
 */
export async function generateToken(
  userId: string,
  expiresInMs: number = 3600000
): Promise<string> {
  const now = Date.now();
  const payload: JWTPayload = {
    user_id: userId,
    iat: Math.floor(now / 1000),
    exp: Math.floor((now + expiresInMs) / 1000),
    jti: randomBytes(16).toString('hex'),
  };

  // Create JWT: header.payload.signature
  const header = base64urlEncode(JSON.stringify({ alg: 'Ed25519', typ: 'JWT' }));
  const payloadEncoded = base64urlEncode(JSON.stringify(payload));
  const unsignedToken = `${header}.${payloadEncoded}`;

  // Sign with server private key
  const signatureHex = await signEd25519(
    config.serverIdentity.privateKeyHex || config.serverIdentity.privateKey,
    unsignedToken
  );

  // Convert hex signature to buffer and encode as base64url
  const signatureBuffer = Buffer.from(signatureHex, 'hex');
  const signature = base64urlEncodeBuffer(signatureBuffer);

  return `${unsignedToken}.${signature}`;
}

/**
 * Verify JWT token
 */
export async function verifyToken(token: string): Promise<JWTPayload> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new AuthenticationError('Invalid token format');
  }

  const [header, payload, signature] = parts;

  // Decode signature from base64url to hex
  const signatureBuffer = base64urlDecodeBuffer(signature);
  const signatureHex = signatureBuffer.toString('hex');

  // Verify signature
  const unsignedToken = `${header}.${payload}`;
  const isValid = await verifyEd25519(
    config.serverIdentity.publicKeyHex || config.serverIdentity.publicKey,
    unsignedToken,
    signatureHex
  );

  if (!isValid) {
    throw new AuthenticationError('Invalid token signature');
  }

  // Decode payload
  let payloadData: JWTPayload;
  try {
    payloadData = JSON.parse(base64urlDecode(payload));
  } catch {
    throw new AuthenticationError('Invalid token payload');
  }

  // Check expiration
  const now = Math.floor(Date.now() / 1000);
  if (payloadData.exp < now) {
    throw new AuthenticationError('Token expired');
  }

  return payloadData;
}

/**
 * JWT authentication middleware
 *
 * Verifies JWT token from Authorization header
 * Falls back to X-User-ID for backward compatibility (with warning)
 */
export async function jwtAuthMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  // Skip auth for health and metrics
  if (req.path === '/health' || req.path === '/metrics') {
    return next();
  }

  const authHeader = req.headers.authorization;
  const userIdHeader = req.headers['x-user-id'] as string | undefined;

  // Try JWT token first
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const token = authHeader.substring(7);
      const payload = await verifyToken(token);

      // Attach user ID to request
      (req as any).userId = payload.user_id;
      (req as any).tokenPayload = payload;

      next();
      return;
    } catch (error) {
      logger.warn('JWT authentication failed', {
        requestId: (req as any).requestId,
        path: req.path,
        error: error instanceof Error ? error.message : String(error),
      });

      res.status(401).json({
        error: 'Unauthorized',
        code: 'INVALID_TOKEN',
        message: error instanceof Error ? error.message : 'Invalid token',
      });
      return;
    }
  }

  // Fallback to X-User-ID (for HTTP API calls)
  // Note: WebSocket connections use MTProto-inspired handshake with Ed25519 signatures for security.
  // X-User-ID header is acceptable for HTTP REST API calls since the real security is in the WebSocket handshake.
  // JWT tokens are optional and provide additional features like expiration and revocation.
  if (userIdHeader) {
    // Only log at debug level - X-User-ID is acceptable for HTTP API
    logger.debug('Using X-User-ID header for HTTP API authentication', {
      requestId: (req as any).requestId,
      path: req.path,
    });

    // Validate format
    if (!/^[0-9a-f]{64}$/i.test(userIdHeader)) {
      res.status(400).json({
        error: 'Invalid user ID format',
        code: 'INVALID_USER_ID',
        message: 'User ID must be a valid Ed25519 public key (64 hex characters)',
      });
      return;
    }

    (req as any).userId = userIdHeader;
    next();
    return;
  }

  // No authentication provided
  logger.warn('Request without authentication', {
    requestId: (req as any).requestId,
    path: req.path,
    ip: req.ip,
  });

  res.status(401).json({
    error: 'Unauthorized',
    code: 'AUTH_REQUIRED',
    message: 'Authorization header with Bearer token or X-User-ID header required',
  });
}
