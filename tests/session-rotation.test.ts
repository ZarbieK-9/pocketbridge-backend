/**
 * Session Rotation Tests
 * 
 * Comprehensive tests for session key rotation
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { shouldRotateKeys, rotateSessionKeys } from '../src/services/session-rotation.js';
import type { SessionState } from '../src/types/index.js';
import { generateECDHKeypair } from '../src/crypto/utils.js';

describe('Session Rotation', () => {
  function createSessionState(age: number, eventCount: number = 0): SessionState {
    return {
      userId: 'a'.repeat(64),
      deviceId: '550e8400-e29b-41d4-a716-446655440000',
      sessionKeys: {
        clientKey: Buffer.from('client-key'),
        serverKey: Buffer.from('server-key'),
      },
      lastAckDeviceSeq: 0,
      createdAt: Date.now() - age,
    };
  }

  describe('shouldRotateKeys', () => {
    it('should return false for new session', () => {
      const session = createSessionState(1000); // 1 second old
      expect(shouldRotateKeys(session)).toBe(false);
    });

    it('should return true for old session (24 hours)', () => {
      const session = createSessionState(24 * 60 * 60 * 1000 + 1000); // 24 hours + 1 second
      expect(shouldRotateKeys(session)).toBe(true);
    });

    it('should return false for session just under 24 hours', () => {
      const session = createSessionState(24 * 60 * 60 * 1000 - 1000); // 24 hours - 1 second
      expect(shouldRotateKeys(session)).toBe(false);
    });

    it('should return true for session with many events', () => {
      const session = createSessionState(1000); // 1 second old
      expect(shouldRotateKeys(session, 1001)).toBe(true); // Over 1000 events
    });

    it('should return false for session with few events', () => {
      const session = createSessionState(1000); // 1 second old
      expect(shouldRotateKeys(session, 500)).toBe(false); // Under 1000 events
    });
  });

  describe('rotateSessionKeys', () => {
    it('should generate new session keys', async () => {
      const session = createSessionState(1000);
      const clientEphemeralKeypair = generateECDHKeypair();

      const newKeys = await rotateSessionKeys(
        session,
        clientEphemeralKeypair.publicKey
      );

      expect(newKeys.clientKey).toBeDefined();
      expect(newKeys.serverKey).toBeDefined();
      expect(newKeys.clientKey).toBeInstanceOf(Buffer);
      expect(newKeys.serverKey).toBeInstanceOf(Buffer);
    });

    it('should generate different keys for different ephemeral keys', async () => {
      const session = createSessionState(1000);
      const keypair1 = generateECDHKeypair();
      const keypair2 = generateECDHKeypair();

      const keys1 = await rotateSessionKeys(session, keypair1.publicKey);
      const keys2 = await rotateSessionKeys(session, keypair2.publicKey);

      expect(keys1.clientKey).not.toEqual(keys2.clientKey);
      expect(keys1.serverKey).not.toEqual(keys2.serverKey);
    });
  });
});

