/**
 * Validation Functions Tests
 * 
 * Tests for input validation and sanitization
 */

import { describe, it, expect } from 'vitest';
import {
  validateUUID,
  validateUUIDv4,
  validateUUIDv7,
  validateEd25519PublicKey,
  validateNonceFormat,
  validateDeviceId,
  validateUserId,
  validateEventId,
  validateStreamId,
  validateEventType,
  validateEncryptedPayload,
  validateDeviceSeq,
} from '../src/utils/validation.js';
import type { EncryptedEvent } from '../src/types/index.js';

describe('Validation Functions', () => {
  describe('UUID Validation', () => {
    it('should validate UUIDv4', () => {
      const validUUIDv4 = '550e8400-e29b-41d4-a716-446655440000';
      expect(validateUUIDv4(validUUIDv4)).toBe(true);
      expect(validateUUID(validUUIDv4)).toBe(true);
    });

    it('should reject invalid UUIDv4', () => {
      expect(validateUUIDv4('not-a-uuid')).toBe(false);
      expect(validateUUIDv4('550e8400-e29b-41d4-a716')).toBe(false);
      expect(validateUUIDv4('')).toBe(false);
    });

    it('should validate UUIDv7', () => {
      const validUUIDv7 = '01234567-89ab-7def-0123-456789abcdef';
      expect(validateUUIDv7(validUUIDv7)).toBe(true);
      expect(validateUUID(validUUIDv7)).toBe(true);
    });

    it('should reject invalid UUIDv7', () => {
      expect(validateUUIDv7('01234567-89ab-4def-0123-456789abcdef')).toBe(false); // Wrong version
      expect(validateUUIDv7('not-a-uuid')).toBe(false);
      expect(validateUUIDv7('')).toBe(false);
    });

    it('should validate generic UUID', () => {
      expect(validateUUID('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
      expect(validateUUID('01234567-89ab-7def-0123-456789abcdef')).toBe(true);
      expect(validateUUID('invalid')).toBe(false);
    });
  });

  describe('Ed25519 Key Validation', () => {
    it('should validate Ed25519 public key (64 hex chars)', () => {
      const validKey = 'a'.repeat(64);
      expect(validateEd25519PublicKey(validKey)).toBe(true);
    });

    it('should reject invalid Ed25519 public keys', () => {
      expect(validateEd25519PublicKey('a'.repeat(63))).toBe(false); // Too short
      expect(validateEd25519PublicKey('a'.repeat(65))).toBe(false); // Too long
      expect(validateEd25519PublicKey('g'.repeat(64))).toBe(false); // Invalid hex
      expect(validateEd25519PublicKey('')).toBe(false);
    });

    it('should validate nonce format', () => {
      const validNonce = 'a'.repeat(64);
      expect(validateNonceFormat(validNonce)).toBe(true);
      expect(validateNonceFormat('invalid')).toBe(false);
    });
  });

  describe('Individual Field Validation', () => {
    it('should validate event ID', () => {
      expect(() => validateEventId('01234567-89ab-7def-0123-456789abcdef')).not.toThrow();
      expect(() => validateEventId('invalid')).toThrow();
      expect(() => validateEventId('')).toThrow();
    });

    it('should validate user ID', () => {
      expect(() => validateUserId('a'.repeat(64))).not.toThrow();
      expect(() => validateUserId('invalid')).toThrow();
      expect(() => validateUserId('')).toThrow();
    });

    it('should validate device ID', () => {
      expect(() => validateDeviceId('550e8400-e29b-41d4-a716-446655440000')).not.toThrow();
      expect(() => validateDeviceId('invalid')).toThrow();
      expect(() => validateDeviceId('')).toThrow();
    });

    it('should validate stream ID', () => {
      expect(() => validateStreamId('stream-123')).not.toThrow();
      expect(() => validateStreamId('stream:test')).not.toThrow();
      expect(() => validateStreamId('stream with spaces')).toThrow();
      expect(() => validateStreamId('')).toThrow();
    });

    it('should validate event type', () => {
      expect(() => validateEventType('clipboard')).not.toThrow();
      expect(() => validateEventType('event:type')).not.toThrow();
      expect(() => validateEventType('event with spaces')).toThrow();
      expect(() => validateEventType('')).toThrow();
    });

    it('should validate encrypted payload', () => {
      const validPayload = Buffer.from('test').toString('base64');
      expect(() => validateEncryptedPayload(validPayload)).not.toThrow();
      // Invalid base64 - Buffer.from with 'base64' doesn't throw, it just returns empty buffer
      // So we test with empty string which should throw
      expect(() => validateEncryptedPayload('')).toThrow();
      // Test with payload that's too large
      const largePayload = Buffer.alloc(11 * 1024 * 1024).toString('base64');
      expect(() => validateEncryptedPayload(largePayload)).toThrow();
    });

    it('should validate device sequence', () => {
      expect(() => validateDeviceSeq(1)).not.toThrow();
      expect(() => validateDeviceSeq(100)).not.toThrow();
      expect(() => validateDeviceSeq(0)).toThrow();
      expect(() => validateDeviceSeq(-1)).toThrow();
      expect(() => validateDeviceSeq(1.5)).toThrow();
    });
  });
});

