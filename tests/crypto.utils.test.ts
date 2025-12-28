/**
 * Crypto Utilities Tests
 * 
 * Tests for cryptographic functions used in handshake and authentication
 */

import { describe, it, expect } from 'vitest';
import {
  generateECDHKeypair,
  computeECDHSecret,
  deriveSessionKeys,
  generateNonce,
  validateNonce,
  hashForSignature,
  signEd25519,
  verifyEd25519,
} from '../src/crypto/utils.js';

describe('Crypto Utils', () => {
  describe('Nonce Generation', () => {
    it('should generate valid nonces', () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      
      expect(nonce1).toBeDefined();
      expect(nonce2).toBeDefined();
      expect(nonce1).not.toBe(nonce2); // Should be unique
      expect(validateNonce(nonce1)).toBe(true);
      expect(validateNonce(nonce2)).toBe(true);
    });
    
    it('should validate nonce format', () => {
      const validNonce = generateNonce();
      expect(validateNonce(validNonce)).toBe(true);
      
      // Invalid formats
      expect(validateNonce('')).toBe(false);
      expect(validateNonce('abc')).toBe(false);
      expect(validateNonce('123')).toBe(false);
      expect(validateNonce(validNonce.substring(0, 32))).toBe(false); // Too short
    });
  });
  
  describe('ECDH Key Exchange', () => {
    it('should generate keypairs', () => {
      const keypair = generateECDHKeypair();
      
      expect(keypair.privateKey).toBeDefined();
      expect(keypair.publicKey).toBeDefined();
      expect(keypair.privateKey.length).toBeGreaterThan(0);
      expect(keypair.publicKey.length).toBeGreaterThan(0);
    });
    
    it('should compute shared secret', () => {
      const keypair1 = generateECDHKeypair();
      const keypair2 = generateECDHKeypair();
      
      // ECDH keys are 130 hex chars (65 bytes uncompressed)
      expect(keypair1.publicKey.length).toBe(130);
      expect(keypair2.publicKey.length).toBe(130);
      
      const secret1 = computeECDHSecret(keypair1.publicKey, keypair2.privateKey);
      const secret2 = computeECDHSecret(keypair2.publicKey, keypair1.privateKey);
      
      expect(secret1).toBeDefined();
      expect(secret2).toBeDefined();
      expect(Buffer.from(secret1).toString('hex')).toBe(Buffer.from(secret2).toString('hex'));
    });
    
    it('should derive session keys', () => {
      const keypair1 = generateECDHKeypair();
      const keypair2 = generateECDHKeypair();
      const sharedSecret = computeECDHSecret(keypair1.publicKey, keypair2.privateKey);
      
      const sessionKeys = deriveSessionKeys(
        sharedSecret,
        keypair1.publicKey, // clientEphemeralPub (string)
        keypair2.publicKey  // serverEphemeralPub (string)
      );
      
      expect(sessionKeys.clientKey).toBeDefined();
      expect(sessionKeys.serverKey).toBeDefined();
      expect(sessionKeys.clientKey.length).toBe(32); // 256 bits
      expect(sessionKeys.serverKey.length).toBe(32);
    });
  });
  
  describe('Hash for Signature', () => {
    it('should hash signature data consistently', () => {
      const userId = 'a'.repeat(64);
      const deviceId = 'b'.repeat(36);
      const nonceC = 'c'.repeat(64);
      const nonceS = 'd'.repeat(64);
      const serverEphemeralPub = 'e'.repeat(130);
      
      const hash1 = hashForSignature(userId, deviceId, nonceC, nonceS, serverEphemeralPub);
      const hash2 = hashForSignature(userId, deviceId, nonceC, nonceS, serverEphemeralPub);
      
      expect(hash1).toBeDefined();
      expect(Buffer.from(hash1).toString('hex')).toBe(Buffer.from(hash2).toString('hex'));
    });
    
    it('should produce different hashes for different inputs', () => {
      const base = {
        userId: 'a'.repeat(64),
        deviceId: 'b'.repeat(36),
        nonceC: 'c'.repeat(64),
        nonceS: 'd'.repeat(64),
        serverEphemeralPub: 'e'.repeat(130),
      };
      
      const hash1 = hashForSignature(
        base.userId,
        base.deviceId,
        base.nonceC,
        base.nonceS,
        base.serverEphemeralPub
      );
      
      const hash2 = hashForSignature(
        base.userId + 'x',
        base.deviceId,
        base.nonceC,
        base.nonceS,
        base.serverEphemeralPub
      );
      
      expect(Buffer.from(hash1).toString('hex')).not.toBe(Buffer.from(hash2).toString('hex'));
    });
  });
  
  describe('Ed25519 Signing', () => {
    it('should sign and verify data', async () => {
      // Generate a test keypair (using tweetnacl)
      const nacl = await import('tweetnacl');
      const keypair = nacl.sign.keyPair();
      // Ed25519 private key: use first 32 bytes (64 hex chars) for signing
      const privateKeyHex = Buffer.from(keypair.secretKey.slice(0, 32)).toString('hex');
      const publicKeyHex = Buffer.from(keypair.publicKey).toString('hex');
      
      const message = 'test message';
      const signature = await signEd25519(privateKeyHex, message);
      
      expect(signature).toBeDefined();
      expect(signature.length).toBe(128); // 64 bytes = 128 hex chars
      
      const isValid = await verifyEd25519(publicKeyHex, message, signature);
      expect(isValid).toBe(true);
    });
    
    it('should reject invalid signatures', async () => {
      const nacl = await import('tweetnacl');
      const keypair = nacl.sign.keyPair();
      const publicKeyHex = Buffer.from(keypair.publicKey).toString('hex');
      
      const message = 'test message';
      const invalidSignature = '0'.repeat(128);
      
      const isValid = await verifyEd25519(publicKeyHex, message, invalidSignature);
      expect(isValid).toBe(false);
    });
  });
});

