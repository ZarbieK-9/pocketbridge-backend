/**
 * JWT Authentication Tests
 * 
 * Tests for JWT token generation, verification, and middleware
 */

import { describe, it, expect, vi } from 'vitest';
import * as nacl from 'tweetnacl';

// Generate test keys
const testKeypair = nacl.sign.keyPair();
const testPublicKeyHex = Buffer.from(testKeypair.publicKey).toString('hex');
// Ed25519 private key from tweetnacl is 64 bytes, but we need the first 32 bytes for signing
const testPrivateKeyHex = Buffer.from(testKeypair.secretKey.slice(0, 32)).toString('hex');

// Mock config before importing
vi.mock('../src/config.js', () => {
  const nacl = require('tweetnacl');
  const keypair = nacl.sign.keyPair();
  const publicKeyHex = Buffer.from(keypair.publicKey).toString('hex');
  const privateKeyHex = Buffer.from(keypair.secretKey.slice(0, 32)).toString('hex');
  
  return {
    config: {
      serverIdentity: {
        publicKeyHex,
        privateKeyHex,
        publicKey: publicKeyHex,
        privateKey: privateKeyHex,
      },
    },
  };
});

// Import after mocking
import { generateToken, verifyToken } from '../src/middleware/jwt-auth.js';

describe('JWT Authentication', () => {

  describe('Token Generation', () => {
    it('should generate a valid JWT token', async () => {
      const userId = 'a'.repeat(64);
      const token = await generateToken(userId, 3600000);
      
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      
      // JWT format: header.payload.signature
      const parts = token.split('.');
      expect(parts.length).toBe(3);
    });

    it('should generate different tokens for different users', async () => {
      const userId1 = 'a'.repeat(64);
      const userId2 = 'b'.repeat(64);
      
      const token1 = await generateToken(userId1);
      const token2 = await generateToken(userId2);
      
      expect(token1).not.toBe(token2);
    });

    it('should generate different tokens on each call', async () => {
      const userId = 'a'.repeat(64);
      const token1 = await generateToken(userId);
      const token2 = await generateToken(userId);
      
      // Should be different due to jti (JWT ID)
      expect(token1).not.toBe(token2);
    });
  });

  describe('Token Verification', () => {
    it('should verify a valid token', async () => {
      const userId = 'a'.repeat(64);
      const token = await generateToken(userId, 3600000);
      
      const payload = await verifyToken(token);
      
      expect(payload).toBeDefined();
      expect(payload.user_id).toBe(userId);
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeDefined();
      expect(payload.jti).toBeDefined();
    });

    it('should reject token with invalid format', async () => {
      await expect(verifyToken('invalid.token')).rejects.toThrow();
      await expect(verifyToken('invalid')).rejects.toThrow();
      await expect(verifyToken('')).rejects.toThrow();
    });

    it('should reject token with invalid signature', async () => {
      const userId = 'a'.repeat(64);
      const token = await generateToken(userId);
      
      // Tamper with signature
      const parts = token.split('.');
      parts[2] = 'invalid_signature';
      const tamperedToken = parts.join('.');
      
      await expect(verifyToken(tamperedToken)).rejects.toThrow();
    });

    it('should reject expired token', async () => {
      const userId = 'a'.repeat(64);
      // Generate token with expiration in the past
      // Manually create an expired token
      const nowSeconds = Math.floor(Date.now() / 1000);
      const expiredPayload = {
        user_id: userId,
        iat: nowSeconds - 10,
        exp: nowSeconds - 5, // Expired 5 seconds ago
        jti: 'test-jti-expired',
      };
      
      // Create expired token manually
      const header = Buffer.from(JSON.stringify({ alg: 'Ed25519', typ: 'JWT' })).toString('base64url');
      const payloadEncoded = Buffer.from(JSON.stringify(expiredPayload)).toString('base64url');
      const unsignedToken = `${header}.${payloadEncoded}`;
      
      // Sign with server private key
      const { signEd25519 } = await import('../src/crypto/utils.js');
      const { config } = await import('../src/config.js');
      const signatureHex = await signEd25519(
        config.serverIdentity.privateKeyHex || config.serverIdentity.privateKey,
        unsignedToken
      );
      const signature = Buffer.from(signatureHex, 'hex').toString('base64url');
      const expiredToken = `${unsignedToken}.${signature}`;
      
      await expect(verifyToken(expiredToken)).rejects.toThrow('Token expired');
    });

    it('should accept non-expired token', async () => {
      const userId = 'a'.repeat(64);
      const token = await generateToken(userId, 3600000); // 1 hour
      
      const payload = await verifyToken(token);
      expect(payload.user_id).toBe(userId);
    });
  });

  describe('Token Payload', () => {
    it('should include correct claims', async () => {
      const userId = 'a'.repeat(64);
      const token = await generateToken(userId, 3600000);
      const payload = await verifyToken(token);
      
      expect(payload.user_id).toBe(userId);
      expect(typeof payload.iat).toBe('number');
      expect(typeof payload.exp).toBe('number');
      expect(typeof payload.jti).toBe('string');
      expect(payload.exp).toBeGreaterThan(payload.iat);
    });

    it('should have correct expiration time', async () => {
      const userId = 'a'.repeat(64);
      const expiresInMs = 7200000; // 2 hours
      const token = await generateToken(userId, expiresInMs);
      const payload = await verifyToken(token);
      
      const expectedExp = Math.floor((Date.now() + expiresInMs) / 1000);
      const tolerance = 5; // 5 seconds tolerance
      
      expect(Math.abs(payload.exp - expectedExp)).toBeLessThan(tolerance);
    });
  });
});

