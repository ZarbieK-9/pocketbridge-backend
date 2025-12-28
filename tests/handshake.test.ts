/**
 * Handshake Logic Tests
 * 
 * Tests for WebSocket handshake protocol (MTProto-inspired)
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Database } from '../src/db/postgres.js';
import type { ServerIdentityKeypair } from '../src/crypto/utils.js';
import {
  generateECDHKeypair,
  generateNonce,
  signEd25519,
  verifyEd25519,
  hashForSignature,
} from '../src/crypto/utils.js';
import * as nacl from 'tweetnacl';

// Mock config
vi.mock('../src/config.js', () => ({
  config: {
    serverIdentity: {} as ServerIdentityKeypair,
    websocket: {
      sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
    },
  },
}));

// Mock WebSocket
class MockWebSocket {
  send = vi.fn();
  close = vi.fn();
  readyState = 1; // OPEN
  on = vi.fn();
  addEventListener = vi.fn();
  removeEventListener = vi.fn();
}

describe('Handshake Logic', () => {
  let mockDb: Partial<Database>;
  let serverIdentity: ServerIdentityKeypair;
  let mockWs: MockWebSocket;

  beforeEach(async () => {
    // Generate server identity keys
    // Ed25519 private key from tweetnacl is 64 bytes, but we need the first 32 bytes (seed) for signing
    const seed = nacl.randomBytes(32);
    const keypair = nacl.sign.keyPair.fromSeed(seed);
    const publicKeyHex = Buffer.from(keypair.publicKey).toString('hex');
    const privateKeyHex = Buffer.from(seed).toString('hex');
    
    serverIdentity = {
      publicKey: publicKeyHex,
      privateKey: privateKeyHex,
      publicKeyHex: publicKeyHex,
      privateKeyHex: privateKeyHex,
    };

    // Update mocked config
    const { config } = await import('../src/config.js');
    config.serverIdentity = serverIdentity;

    mockDb = {
      pool: {
        query: vi.fn(),
      } as any,
    };

    mockWs = new MockWebSocket();
  });

  describe('Handshake Flow', () => {
    it('should process valid client hello through handleHandshake', async () => {
      const { handleHandshake } = await import('../src/gateway/handshake.js');

      const clientHello = {
        type: 'client_hello',
        client_ephemeral_pub: generateECDHKeypair().publicKey,
        nonce_c: generateNonce(),
      };

      const result = await handleHandshake(
        clientHello,
        mockWs as any,
        mockDb as Database,
        serverIdentity
      );

      expect(result.success).toBe(true);
      expect(result.response).toBeDefined();
      const response = result.response as any;
      expect(response.type).toBe('server_hello');
      expect(response.payload.server_ephemeral_pub).toBeDefined();
      expect(response.payload.nonce_s).toBeDefined();
      expect(response.payload.server_signature).toBeDefined();
    });

    it('should generate unique nonces for each handshake', async () => {
      const { handleHandshake } = await import('../src/gateway/handshake.js');

      const mockWs1 = new MockWebSocket();
      const mockWs2 = new MockWebSocket();

      const clientHello1 = {
        type: 'client_hello',
        client_ephemeral_pub: generateECDHKeypair().publicKey,
        nonce_c: generateNonce(),
      };

      const clientHello2 = {
        type: 'client_hello',
        client_ephemeral_pub: generateECDHKeypair().publicKey,
        nonce_c: generateNonce(),
      };

      const result1 = await handleHandshake(
        clientHello1,
        mockWs1 as any,
        mockDb as Database,
        serverIdentity
      );

      const result2 = await handleHandshake(
        clientHello2,
        mockWs2 as any,
        mockDb as Database,
        serverIdentity
      );

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      const response1 = result1.response as any;
      const response2 = result2.response as any;
      expect(response1.payload.nonce_s).not.toBe(response2.payload.nonce_s);
    });

    it('should generate server ephemeral keypair', async () => {
      const { handleHandshake } = await import('../src/gateway/handshake.js');

      const clientHello = {
        type: 'client_hello',
        client_ephemeral_pub: generateECDHKeypair().publicKey,
        nonce_c: generateNonce(),
      };

      const result = await handleHandshake(
        clientHello,
        mockWs as any,
        mockDb as Database,
        serverIdentity
      );

      const response = result.response as any;
      expect(response.payload.server_ephemeral_pub).toBeDefined();
      expect(response.payload.server_ephemeral_pub.length).toBeGreaterThan(0);
    });
  });

  describe('Server Hello Signature', () => {
    it('should sign server hello correctly', async () => {
      const { handleHandshake } = await import('../src/gateway/handshake.js');

      const clientEphemeralPub = generateECDHKeypair().publicKey;
      const nonceC = generateNonce();

      const clientHello = {
        type: 'client_hello',
        client_ephemeral_pub: clientEphemeralPub,
        nonce_c: nonceC,
      };

      const result = await handleHandshake(
        clientHello,
        mockWs as any,
        mockDb as Database,
        serverIdentity
      );

      const response = result.response as any;
      const serverHello = response.payload;
      expect(serverHello.server_signature).toBeDefined();

      // Verify signature
      const signatureData = hashForSignature(
        serverIdentity.publicKeyHex,
        serverHello.server_ephemeral_pub,
        nonceC,
        serverHello.nonce_s
      );

      const isValid = await verifyEd25519(
        serverIdentity.publicKeyHex,
        signatureData,
        serverHello.server_signature
      );

      expect(isValid).toBe(true);
    });
  });

  describe('Client Auth Verification', () => {
    it('should process client auth through handleHandshake', async () => {
      const { handleHandshake } = await import('../src/gateway/handshake.js');

      // Step 1: Client Hello
      const clientEphemeralKeypair = generateECDHKeypair();
      const nonceC = generateNonce();

      const clientHello = {
        type: 'client_hello',
        client_ephemeral_pub: clientEphemeralKeypair.publicKey,
        nonce_c: nonceC,
      };

      const helloResult = await handleHandshake(
        clientHello,
        mockWs as any,
        mockDb as Database,
        serverIdentity
      );

      expect(helloResult.success).toBe(true);
      const serverHello = (helloResult.response as any).payload;

      // Step 2: Client Auth
      // Create client keypair - userId is the public key
      // Ed25519 private key from tweetnacl is 64 bytes, but we need the first 32 bytes (seed) for signing
      const clientSeed = nacl.randomBytes(32);
      const clientKeypair = nacl.sign.keyPair.fromSeed(clientSeed);
      const userId = Buffer.from(clientKeypair.publicKey).toString('hex');
      const deviceId = '550e8400-e29b-41d4-a716-446655440000';
      const nonceC2 = generateNonce();

      // Generate client signature
      const signatureData = hashForSignature(
        userId,
        deviceId,
        nonceC,
        serverHello.nonce_s,
        serverHello.server_ephemeral_pub
      );

      const clientSignature = await signEd25519(
        Buffer.from(clientSeed).toString('hex'),
        signatureData
      );

      // Mock database responses
      // First mock isDeviceRevoked check (returns empty = not revoked)
      (mockDb.pool!.query as any)
        .mockResolvedValueOnce({ rows: [] }) // isDeviceRevoked check
        .mockResolvedValueOnce({ rows: [] }) // User insert
        .mockResolvedValueOnce({ rows: [{ last_ack_device_seq: 0 }] }); // Device insert

      const clientAuth = {
        type: 'client_auth',
        user_id: userId,
        device_id: deviceId,
        nonce_c2: nonceC2,
        client_signature: clientSignature,
      };

      const result = await handleHandshake(
        clientAuth,
        mockWs as any,
        mockDb as Database,
        serverIdentity
      );

      // This should succeed because we're using the correct keypair
      expect(result.success).toBe(true);
      expect(result.sessionState).toBeDefined();
    });

    it('should reject client auth with invalid signature', async () => {
      const { handleHandshake } = await import('../src/gateway/handshake.js');

      // First do client hello
      const helloResult = await handleHandshake(
        {
          type: 'client_hello',
          client_ephemeral_pub: generateECDHKeypair().publicKey,
          nonce_c: generateNonce(),
        },
        mockWs as any,
        mockDb as Database,
        serverIdentity
      );

      expect(helloResult.success).toBe(true);

      const clientAuth = {
        type: 'client_auth',
        user_id: 'a'.repeat(64),
        device_id: '550e8400-e29b-41d4-a716-446655440000',
        nonce_c2: generateNonce(),
        client_signature: '0'.repeat(128), // Invalid signature
      };

      const result = await handleHandshake(
        clientAuth,
        mockWs as any,
        mockDb as Database,
        serverIdentity
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('signature');
    });
  });

  describe('Nonce Validation', () => {
    it('should validate nonce format', async () => {
      const { handleHandshake } = await import('../src/gateway/handshake.js');

      const invalidClientHello = {
        type: 'client_hello',
        client_ephemeral_pub: generateECDHKeypair().publicKey,
        nonce_c: 'invalid-nonce', // Invalid format
      };

      const result = await handleHandshake(
        invalidClientHello,
        mockWs as any,
        mockDb as Database,
        serverIdentity
      );

      expect(result.success).toBe(false);
    });
  });

  describe('State Management', () => {
    it('should maintain handshake state between steps', async () => {
      const { handleHandshake } = await import('../src/gateway/handshake.js');

      const clientEphemeralPub = generateECDHKeypair().publicKey;
      const nonceC = generateNonce();

      const result = await handleHandshake(
        {
          type: 'client_hello',
          client_ephemeral_pub: clientEphemeralPub,
          nonce_c: nonceC,
        },
        mockWs as any,
        mockDb as Database,
        serverIdentity
      );

      expect(result.success).toBe(true);
      // State is maintained internally in handshakeStates WeakMap
      expect(result.response).toBeDefined();
    });
  });
});

