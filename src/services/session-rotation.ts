/**
 * Session Key Rotation Service
 *
 * Implements periodic session key rotation for enhanced security
 */

import type { SessionState } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { generateECDHKeypair, computeECDHSecret, deriveSessionKeys } from '../crypto/utils.js';

/**
 * Rotate session keys for an existing session
 * Generates new ephemeral keys and derives new session keys
 */
export async function rotateSessionKeys(
  sessionState: SessionState,
  clientEphemeralPub: string
): Promise<{ clientKey: Buffer; serverKey: Buffer }> {
  // Generate new server ephemeral keypair
  const serverEphemeralKeypair = generateECDHKeypair();

  // Compute new shared secret
  const sharedSecret = computeECDHSecret(clientEphemeralPub, serverEphemeralKeypair.privateKey);

  // Derive new session keys
  const newKeys = deriveSessionKeys(
    sharedSecret,
    clientEphemeralPub,
    serverEphemeralKeypair.publicKey
  );

  logger.info('Session keys rotated', {
    deviceId: sessionState.deviceId,
  });

  return {
    clientKey: newKeys.clientKey,
    serverKey: newKeys.serverKey,
  };
}

/**
 * Check if session keys should be rotated
 * Rotate every 24 hours or after 1000 events
 */
export function shouldRotateKeys(sessionState: SessionState, eventCount: number = 0): boolean {
  const SESSION_KEY_LIFETIME = 24 * 60 * 60 * 1000; // 24 hours
  const MAX_EVENTS_PER_KEY = 1000;

  const age = Date.now() - sessionState.createdAt;
  return age > SESSION_KEY_LIFETIME || eventCount > MAX_EVENTS_PER_KEY;
}
