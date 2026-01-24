/**
 * Secure Pairing Code Generator
 * 
 * Generates cryptographically secure 6-digit pairing codes
 * with collision detection and retry logic
 */

import { randomBytes } from 'crypto';
import type { Database } from '../db/postgres.js';
import { logger } from './logger.js';

/**
 * Generate a cryptographically secure 6-digit pairing code
 */
export function generateSecurePairingCode(): string {
  // Use crypto.randomBytes for cryptographically secure random
  const buffer = randomBytes(4);
  const number = buffer.readUInt32BE(0) % 900000 + 100000;
  return number.toString();
}

/**
 * Generate a unique pairing code with database verification
 * Retries on collision (UNIQUE constraint violation)
 */
export async function generateUniquePairingCode(
  db: Database,
  userId: string,
  deviceId: string,
  wsUrl: string,
  deviceName: string,
  publicKeyHex: string,
  privateKeyHex: string,
  maxRetries: number = 5
): Promise<{ code: string; expiresAt: Date }> {
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const code = generateSecurePairingCode();

    try {
      // Delete any existing pairing codes for this user/device
      await db.pool.query(
        'DELETE FROM pairing_codes WHERE user_id = $1 AND device_id = $2',
        [userId, deviceId]
      );

      // Try to insert the new code
      await db.pool.query(
        `INSERT INTO pairing_codes 
         (code, ws_url, user_id, device_id, device_name, public_key_hex, private_key_hex, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [code, wsUrl, userId, deviceId, deviceName, publicKeyHex, privateKeyHex, expiresAt]
      );

      logger.info('Generated unique pairing code', {
        code,
        userId: userId.substring(0, 16) + '...',
        deviceId: deviceId.substring(0, 8) + '...',
        attempt: attempt + 1,
      });

      return { code, expiresAt };
    } catch (error: any) {
      // Check for unique constraint violation (code collision)
      if (error.code === '23505' && error.constraint === 'idx_pairing_codes_code_unique') {
        logger.warn('Pairing code collision detected, retrying', {
          code,
          attempt: attempt + 1,
          maxRetries,
        });
        continue; // Retry with a new code
      }

      // Other errors should be thrown
      throw error;
    }
  }

  // If we've exhausted all retries
  throw new Error(
    `Failed to generate unique pairing code after ${maxRetries} attempts. This is extremely rare.`
  );
}

/**
 * Lookup pairing code with validation
 */
export async function lookupPairingCode(
  db: Database,
  code: string
): Promise<{
  wsUrl: string;
  userId: string;
  deviceId: string;
  deviceName: string;
  publicKeyHex: string;
  privateKeyHex: string;
  expiresAt: Date;
} | null> {
  // Validate code format
  if (!/^\d{6}$/.test(code)) {
    return null;
  }

  const result = await db.pool.query(
    `SELECT ws_url, user_id, device_id, device_name, public_key_hex, private_key_hex, expires_at
     FROM pairing_codes
     WHERE code = $1 AND expires_at > NOW()`,
    [code]
  );

  if (result.rows.length === 0) {
    return null;
  }

  const row = result.rows[0];
  return {
    wsUrl: row.ws_url,
    userId: row.user_id,
    deviceId: row.device_id,
    deviceName: row.device_name,
    publicKeyHex: row.public_key_hex,
    privateKeyHex: row.private_key_hex,
    expiresAt: row.expires_at,
  };
}

/**
 * Delete pairing code after use (one-time use pattern)
 */
export async function deletePairingCode(db: Database, code: string): Promise<boolean> {
  const result = await db.pool.query('DELETE FROM pairing_codes WHERE code = $1', [code]);
  return result.rowCount !== null && result.rowCount > 0;
}
