/**
 * End-to-End Full Flow Tests
 * 
 * Tests complete user journeys:
 * - Full handshake flow
 * - Event relay between devices
 * - Multi-device scenarios
 * - Error handling
 * - Device revocation
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll, vi } from 'vitest';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import WebSocket from 'ws';
import express from 'express';
import type { Database } from '../../src/db/postgres.js';
import type { RedisConnection } from '../../src/db/redis.js';
import { createWebSocketGateway } from '../../src/gateway/websocket.js';
import { initDatabase } from '../../src/db/postgres.js';
import { initRedis } from '../../src/db/redis.js';
import * as nacl from 'tweetnacl';
import {
  generateECDHKeypair,
  computeECDHSecret,
  deriveSessionKeys,
  signEd25519,
  hashForSignature,
  generateNonce,
} from '../../src/crypto/utils.js';
import type { ServerIdentityKeypair } from '../../src/crypto/utils.js';
import { config } from '../../src/config.js';
import { revokeDevice } from '../../src/services/device-revocation.js';
import type { EncryptedEvent } from '../../src/types/index.js';
import { randomUUID } from 'crypto';
import { uuidv7 } from 'uuidv7';

// Test server setup
let testServer: ReturnType<typeof createServer>;
let testWss: WebSocketServer;
let testApp: express.Application;
let testDb: Database | null = null;
let testRedis: RedisConnection | null = null;
let TEST_PORT = 0; // Use 0 to get random available port
// Track revoked devices across tests (shared state)
const revokedDevices = new Set<string>();

// Helper to generate client identity
function generateClientIdentity() {
  const seed = nacl.randomBytes(32);
  const keypair = nacl.sign.keyPair.fromSeed(seed);
  const publicKeyHex = Buffer.from(keypair.publicKey).toString('hex');
  const privateKeyHex = Buffer.from(seed).toString('hex');
  
  return {
    publicKey: keypair.publicKey,
    privateKey: seed,
    publicKeyHex,
    privateKeyHex,
  };
}

// Helper to perform full handshake
async function performHandshake(
  ws: WebSocket,
  userId: string,
  deviceId: string,
  clientIdentity: ReturnType<typeof generateClientIdentity>
): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Handshake timeout'));
    }, 10000);

    let clientEphemeralKeypair: ReturnType<typeof generateECDHKeypair> | null = null;
    let nonceC: string | null = null;
    let messageHandlerAttached = false;

    const attachMessageHandler = () => {
      if (messageHandlerAttached) return;
      messageHandlerAttached = true;

      ws.on('message', async (data: Buffer) => {
        const message = JSON.parse(data.toString('utf8'));

        if (message.type === 'server_hello') {
          const serverHello = message.payload;
          
          // Verify server signature (simplified - just check it exists)
          expect(serverHello.server_signature).toBeDefined();
          expect(serverHello.server_ephemeral_pub).toBeDefined();
          expect(serverHello.nonce_s).toBeDefined();

          if (!clientEphemeralKeypair || !nonceC) {
            clearTimeout(timeout);
            reject(new Error('Client ephemeral keypair or nonce not set'));
            return;
          }

          try {
            // Sign client auth
            const signatureData = hashForSignature(
              userId,
              deviceId,
              nonceC,
              serverHello.nonce_s,
              serverHello.server_ephemeral_pub
            );

            const clientSignature = await signEd25519(clientIdentity.privateKeyHex, signatureData);
            // signEd25519 already returns hex string, don't double-encode
            const nonceC2 = generateNonce();

            // Send client auth
            ws.send(JSON.stringify({
              type: 'client_auth',
              payload: {
                type: 'client_auth',
                user_id: userId,
                device_id: deviceId,
                client_signature: clientSignature,
                nonce_c2: nonceC2,
              },
            }));
          } catch (error) {
            clearTimeout(timeout);
            reject(error);
          }
        } else if (message.type === 'session_established') {
          clearTimeout(timeout);
          const sessionEstablished = message.payload;
          expect(sessionEstablished.device_id).toBe(deviceId);
          expect(sessionEstablished.last_ack_device_seq).toBeDefined();
          resolve();
        } else if (message.type === 'error') {
          clearTimeout(timeout);
          reject(new Error(`Handshake error: ${JSON.stringify(message.payload)}`));
        }
      });
    };

    const sendClientHello = () => {
      console.log('[TEST] sendClientHello called', { readyState: ws.readyState });
      
      if (ws.readyState !== WebSocket.OPEN) {
        console.log('[TEST] Connection not open, waiting...', { readyState: ws.readyState });
        // Connection not open, wait a bit and retry
        setTimeout(() => {
          console.log('[TEST] Retry check', { readyState: ws.readyState });
          if (ws.readyState === WebSocket.OPEN) {
            sendClientHello();
          } else {
            clearTimeout(timeout);
            reject(new Error(`Connection closed before sending client_hello. ReadyState: ${ws.readyState}`));
          }
        }, 50);
        return;
      }

      // Generate keys and send immediately
      clientEphemeralKeypair = generateECDHKeypair();
      nonceC = generateNonce();
      
      // Attach message handler before sending
      attachMessageHandler();
      
      const clientHelloMessage = {
        type: 'client_hello',
        payload: {
          type: 'client_hello',
          client_ephemeral_pub: clientEphemeralKeypair.publicKey,
          nonce_c: nonceC,
        },
      };
      
      console.log('[TEST] Sending client_hello', { readyState: ws.readyState, messageType: clientHelloMessage.type });
      
      try {
        ws.send(JSON.stringify(clientHelloMessage));
        console.log('[TEST] client_hello sent successfully');
      } catch (error) {
        console.log('[TEST] Error sending client_hello', { error: error instanceof Error ? error.message : String(error) });
        clearTimeout(timeout);
        reject(error);
      }
    };

    // Wait for connection to be open before sending
    if (ws.readyState === WebSocket.OPEN) {
      // Connection already open, send immediately
      console.log('[TEST] Connection already open, sending immediately');
      sendClientHello();
    } else {
      // Wait for open event
      ws.once('open', () => {
        console.log('[TEST] Open event received, sending client_hello');
        // Small delay to ensure server is ready to receive messages
        setTimeout(() => {
          sendClientHello();
        }, 10);
      });
    }
    
    // Also listen for close event to debug
    ws.on('close', (code, reason) => {
      console.log('[TEST] WebSocket closed in performHandshake', { code, reason: reason.toString(), readyState: ws.readyState });
      if (!messageHandlerAttached || !clientEphemeralKeypair) {
        clearTimeout(timeout);
        reject(new Error(`Connection closed before handshake could complete. Code: ${code}, Reason: ${reason.toString()}`));
      }
    });
  });
}

// Mock config before imports
vi.mock('../../src/config.js', async () => {
  const nacl = await import('tweetnacl');
  const seed = nacl.randomBytes(32);
  const keypair = nacl.sign.keyPair.fromSeed(seed);
  const publicKeyHex = Buffer.from(keypair.publicKey).toString('hex');
  const privateKeyHex = Buffer.from(seed).toString('hex');
  
  const mockServerIdentity = {
    publicKey: publicKeyHex,
    privateKey: privateKeyHex,
    publicKeyHex,
    privateKeyHex,
  };
  
  return {
    config: {
      serverIdentity: mockServerIdentity,
      websocket: {
        sessionTimeout: 24 * 60 * 60 * 1000,
      },
    },
  };
});

describe('E2E Full Flow Tests', () => {

  beforeEach(async () => {
    // Create Express app
    testApp = express();
    testServer = createServer(testApp);
    testWss = new WebSocketServer({ server: testServer, path: '/ws' });

    // Initialize test database (use test DB if available, otherwise mock)
    try {
      // Try to use test database if TEST_DATABASE_URL is set
      if (process.env.TEST_DATABASE_URL) {
        testDb = await initDatabase();
      } else {
        // Mock database
        testDb = {
          pool: {
            query: vi.fn().mockResolvedValue({ rows: [] }),
          } as any,
          end: vi.fn(),
          healthCheck: vi.fn().mockResolvedValue(true),
        } as Database;
      }
    } catch (error) {
      // Fallback to mock
      testDb = {
        pool: {
          query: vi.fn().mockResolvedValue({ rows: [] }),
        } as any,
        end: vi.fn(),
        healthCheck: vi.fn().mockResolvedValue(true),
      } as Database;
    }

    // Initialize test Redis (mock if not available)
    try {
      if (process.env.TEST_REDIS_URL) {
        testRedis = await initRedis();
      } else {
        const mockSubscriber = {
          subscribe: vi.fn().mockResolvedValue(undefined),
          quit: vi.fn().mockResolvedValue(undefined),
          on: vi.fn(),
          connect: vi.fn().mockResolvedValue(undefined),
        };
        testRedis = {
          client: {
            publish: vi.fn().mockResolvedValue(1),
            duplicate: vi.fn().mockReturnValue(mockSubscriber),
            ping: vi.fn().mockResolvedValue('PONG'),
            setEx: vi.fn().mockResolvedValue('OK'),
            del: vi.fn().mockResolvedValue(1),
          } as any,
          quit: vi.fn(),
          healthCheck: vi.fn().mockResolvedValue(true),
        } as RedisConnection;
      }
    } catch (error) {
      // Fallback to mock
      const mockSubscriber = {
        subscribe: vi.fn(),
        quit: vi.fn(),
        on: vi.fn(),
      };
      testRedis = {
        client: {
          publish: vi.fn().mockResolvedValue(1),
          duplicate: vi.fn().mockReturnValue(mockSubscriber),
          ping: vi.fn().mockResolvedValue('PONG'),
        } as any,
        quit: vi.fn(),
        healthCheck: vi.fn().mockResolvedValue(true),
      } as RedisConnection;
    }

    // Clear revoked devices for each test
    revokedDevices.clear();
    
    // Setup database mocks for common queries
    if (testDb && 'pool' in testDb && typeof (testDb.pool as any).query === 'function') {
      const mockQuery = testDb.pool.query as ReturnType<typeof vi.fn>;
      
      // Mock user creation
      mockQuery.mockImplementation(async (query: string, params?: any[]) => {
        if (query.includes('INSERT INTO users')) {
          return { rows: [] };
        }
        if (query.includes('INSERT INTO user_devices')) {
          return { rows: [{ last_ack_device_seq: 0 }] };
        }
        if (query.includes('INSERT INTO revoked_devices')) {
          // Track revoked device
          if (params && params[0]) {
            revokedDevices.add(params[0] as string);
          }
          return { rows: [] };
        }
        if (query.includes('SELECT') && query.includes('revoked_devices') && query.includes('device_id = $1')) {
          // Check if device is revoked
          const deviceId = params?.[0];
          if (deviceId && revokedDevices.has(deviceId as string)) {
            return { rows: [{ device_id: deviceId }] };
          }
          return { rows: [] };
        }
        if (query.includes('SELECT') && query.includes('stream_sequences')) {
          return { rows: [{ last_stream_seq: 1 }] };
        }
        if (query.includes('INSERT INTO stream_sequences')) {
          return { rows: [{ last_stream_seq: 1 }] };
        }
        if (query.includes('INSERT INTO events')) {
          return { rows: [] };
        }
        if (query.includes('UPDATE user_devices') && query.includes('is_online')) {
          return { rows: [] };
        }
        return { rows: [] };
      });
    }

    // Create WebSocket gateway
    createWebSocketGateway(testWss, {
      db: testDb!,
      redis: testRedis!,
    });

    // Start server on random port
    await new Promise<void>((resolve) => {
      testServer.listen(0, '127.0.0.1', () => {
        const address = testServer.address();
        TEST_PORT = typeof address === 'object' && address ? address.port : 30099;
        // Wait for server to be fully ready - check that it's actually listening
        // Use a small delay and verify the server is listening
        setTimeout(() => {
          if (testServer.listening && TEST_PORT > 0) {
            resolve();
          } else {
            // Retry after a bit more time
            setTimeout(() => resolve(), 100);
          }
        }, 150);
      });
    });
    
    // Additional verification that server is ready
    await new Promise(resolve => setTimeout(resolve, 50));
  });

  afterEach(async () => {
    // Close all WebSocket connections
    testWss.clients.forEach((ws) => {
      if (ws.readyState === ws.OPEN || ws.readyState === ws.CONNECTING) {
        ws.close();
      }
    });

    // Wait a bit for connections to close
    await new Promise(resolve => setTimeout(resolve, 100));

    // Close WebSocket server
    await new Promise<void>((resolve) => {
      if (testWss.clients.size === 0) {
        testWss.close(() => {
          testServer.close(() => {
            resolve();
          });
        });
      } else {
        // Force close after timeout
        setTimeout(() => {
          testWss.close(() => {
            testServer.close(() => {
              resolve();
            });
          });
        }, 1000);
      }
    });

    // Cleanup database and Redis
    if (testDb && typeof testDb.end === 'function') {
      try {
        await testDb.end();
      } catch (error) {
        // Ignore cleanup errors
      }
    }
    if (testRedis && typeof testRedis.quit === 'function') {
      try {
        await testRedis.quit();
      } catch (error) {
        // Ignore cleanup errors
      }
    }
  });

  describe('Full Handshake Flow', () => {
    it('should complete full handshake successfully', async () => {
      const clientIdentity = generateClientIdentity();
      const userId = clientIdentity.publicKeyHex;
      const deviceId = '550e8400-e29b-41d4-a716-446655440000';

      // Verify server is listening before connecting
      if (!testServer.listening || TEST_PORT === 0) {
        throw new Error('Test server is not ready');
      }

      // Create WebSocket and attach handlers BEFORE connection attempt
      const ws = new WebSocket(`ws://127.0.0.1:${TEST_PORT}/ws`);

      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          if (ws.readyState !== WebSocket.CLOSED) {
            ws.close();
          }
          reject(new Error(`Connection timeout. ReadyState: ${ws.readyState}`));
        }, 10000);

        let resolved = false;

        const handleOpen = async () => {
          if (resolved) return;
          try {
            await performHandshake(ws, userId, deviceId, clientIdentity);
            resolved = true;
            clearTimeout(timeout);
            resolve();
          } catch (error) {
            resolved = true;
            clearTimeout(timeout);
            reject(error);
          }
        };

        // Attach handlers immediately (before connection completes)
        ws.once('open', () => {
          console.log('[TEST] WebSocket opened, readyState:', ws.readyState);
          handleOpen();
        });
        ws.once('error', (error) => {
          console.log('[TEST] WebSocket error:', error.message);
          if (!resolved) {
            resolved = true;
            clearTimeout(timeout);
            reject(error);
          }
        });
        ws.once('close', (code, reason) => {
          console.log('[TEST] WebSocket closed:', code, reason.toString());
          if (!resolved) {
            resolved = true;
            clearTimeout(timeout);
            reject(new Error(`Connection closed before opening. Code: ${code}, Reason: ${reason.toString()}`));
          }
        });

        // If already open (unlikely but possible), handle immediately
        if (ws.readyState === WebSocket.OPEN) {
          handleOpen();
        } else {
          // Log initial state
          console.log('[TEST] WebSocket initial readyState:', ws.readyState);
        }
      });

      expect(ws.readyState).toBe(WebSocket.OPEN);
      ws.close();
    });

    it('should reject handshake with invalid signature', async () => {
      const clientIdentity = generateClientIdentity();
      const userId = clientIdentity.publicKeyHex;
      const deviceId = '550e8400-e29b-41d4-a716-446655440000';

      const ws = new WebSocket(`ws://localhost:${TEST_PORT}/ws`);

      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Test timeout'));
        }, 5000);

        ws.on('open', () => {
          // Send client hello
          const clientEphemeralKeypair = generateECDHKeypair();
          const nonceC = generateNonce();
          
          ws.send(JSON.stringify({
            type: 'client_hello',
            payload: {
              type: 'client_hello',
              client_ephemeral_pub: clientEphemeralKeypair.publicKey,
              nonce_c: nonceC,
            },
          }));
        });

        ws.on('message', (data: Buffer) => {
          const message = JSON.parse(data.toString('utf8'));
          
          if (message.type === 'server_hello') {
            const serverHello = message.payload;
            
            // Send client auth with INVALID signature
            ws.send(JSON.stringify({
              type: 'client_auth',
              payload: {
                type: 'client_auth',
                user_id: userId,
                device_id: deviceId,
                client_signature: 'invalid_signature_hex',
                nonce_c2: generateNonce(),
              },
            }));
          } else if (message.type === 'error' || ws.readyState === WebSocket.CLOSING) {
            clearTimeout(timeout);
            resolve(); // Expected to fail
          }
        });

        ws.on('close', () => {
          clearTimeout(timeout);
          resolve();
        });

        ws.on('error', () => {
          clearTimeout(timeout);
          resolve(); // Expected to fail
        });
      });

      expect(ws.readyState).toBe(WebSocket.CLOSED);
    });
  });

  describe('Event Relay Between Devices', () => {
    it('should relay event from one device to another', async () => {
      const clientIdentity = generateClientIdentity();
      const userId = clientIdentity.publicKeyHex;
      const deviceId1 = randomUUID();
      const deviceId2 = randomUUID();

      // Connect first device
      const ws1 = new WebSocket(`ws://localhost:${TEST_PORT}/ws`);
      await new Promise<void>((resolve) => {
        ws1.on('open', async () => {
          await performHandshake(ws1, userId, deviceId1, clientIdentity);
          resolve();
        });
      });

      // Connect second device
      const ws2 = new WebSocket(`ws://localhost:${TEST_PORT}/ws`);
      await new Promise<void>((resolve) => {
        ws2.on('open', async () => {
          await performHandshake(ws2, userId, deviceId2, clientIdentity);
          resolve();
        });
      });

      // Wait a bit for both to be connected
      await new Promise(resolve => setTimeout(resolve, 500));

      // Device 1 sends event
      const eventReceived: EncryptedEvent[] = [];
      ws2.on('message', (data: Buffer) => {
        const message = JSON.parse(data.toString('utf8'));
        if (message.type === 'event') {
          eventReceived.push(message.payload);
        }
      });

      const testEvent: EncryptedEvent = {
        event_id: uuidv7(),
        user_id: userId,
        device_id: deviceId1,
        device_seq: 1,
        stream_id: 'test-stream',
        stream_seq: 0, // Will be assigned by server
        type: 'test_event',
        encrypted_payload: Buffer.from('test payload').toString('base64'),
      };

      ws1.send(JSON.stringify({
        type: 'event',
        payload: testEvent,
      }));

      // Wait for relay
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Device 2 should have received the event
      expect(eventReceived.length).toBeGreaterThan(0);
      if (eventReceived.length > 0) {
        expect(eventReceived[0].user_id).toBe(userId);
        expect(eventReceived[0].type).toBe('test_event');
      }

      ws1.close();
      ws2.close();
    });

    it('should not relay event when only one device is connected', async () => {
      const clientIdentity = generateClientIdentity();
      const userId = clientIdentity.publicKeyHex;
      const deviceId = '550e8400-e29b-41d4-a716-446655440000';

      const ws = new WebSocket(`ws://localhost:${TEST_PORT}/ws`);
      await new Promise<void>((resolve) => {
        ws.on('open', async () => {
          await performHandshake(ws, userId, deviceId, clientIdentity);
          resolve();
        });
      });

      // Send event (no other devices to relay to)
      const testEvent: EncryptedEvent = {
        event_id: uuidv7(),
        user_id: userId,
        device_id: deviceId,
        device_seq: 1,
        stream_id: 'test-stream',
        stream_seq: 0,
        type: 'test_event',
        encrypted_payload: Buffer.from('test payload').toString('base64'),
      };

      ws.send(JSON.stringify({
        type: 'event',
        payload: testEvent,
      }));

      // Wait a bit
      await new Promise(resolve => setTimeout(resolve, 500));

      // Should not error (just no relay targets)
      expect(ws.readyState).toBe(WebSocket.OPEN);
      ws.close();
    });
  });

  describe('Device Revocation', () => {
    it('should reject revoked device during handshake', async () => {
      const clientIdentity = generateClientIdentity();
      const userId = clientIdentity.publicKeyHex;
      const deviceId = '550e8400-e29b-41d4-a716-446655440000';

      // Revoke device before handshake
      if (testDb) {
        await revokeDevice(testDb, deviceId, userId, 'Test revocation');
      }

      const ws = new WebSocket(`ws://localhost:${TEST_PORT}/ws`);

      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Test timeout'));
        }, 5000);

        ws.on('open', () => {
          // Send client hello
          const clientEphemeralKeypair = generateECDHKeypair();
          const nonceC = generateNonce();
          
          ws.send(JSON.stringify({
            type: 'client_hello',
            payload: {
              type: 'client_hello',
              client_ephemeral_pub: clientEphemeralKeypair.publicKey,
              nonce_c: nonceC,
            },
          }));
        });

        ws.on('message', async (data: Buffer) => {
          const message = JSON.parse(data.toString('utf8'));
          
          if (message.type === 'server_hello') {
            const serverHello = message.payload;
            
            try {
              // Complete handshake
              const nonceC = generateNonce();
              const signatureData = hashForSignature(
                userId,
                deviceId,
                nonceC,
                serverHello.nonce_s,
                serverHello.server_ephemeral_pub
              );

              const clientSignature = await signEd25519(clientIdentity.privateKeyHex, signatureData);
              // signEd25519 already returns hex string, don't double-encode

              ws.send(JSON.stringify({
                type: 'client_auth',
                payload: {
                  type: 'client_auth',
                  user_id: userId,
                  device_id: deviceId,
                  client_signature: clientSignature,
                  nonce_c2: generateNonce(),
                },
              }));
            } catch (error) {
              clearTimeout(timeout);
              reject(error);
            }
          } else if (message.type === 'error' || ws.readyState === WebSocket.CLOSING) {
            clearTimeout(timeout);
            resolve(); // Expected to fail
          }
        });

        ws.on('close', () => {
          clearTimeout(timeout);
          resolve();
        });

        ws.on('error', () => {
          clearTimeout(timeout);
          resolve();
        });
      });

      // Device should be rejected
      expect(ws.readyState).toBe(WebSocket.CLOSED);
    });

    it('should reject events from revoked device', async () => {
      const clientIdentity = generateClientIdentity();
      const userId = clientIdentity.publicKeyHex;
      const deviceId = '550e8400-e29b-41d4-a716-446655440000';

      // Connect device first
      const ws = new WebSocket(`ws://localhost:${TEST_PORT}/ws`);
      await new Promise<void>((resolve) => {
        ws.on('open', async () => {
          await performHandshake(ws, userId, deviceId, clientIdentity);
          resolve();
        });
      });

      // Revoke device after connection
      if (testDb) {
        await revokeDevice(testDb, deviceId, userId, 'Test revocation');
      }

      // Wait a bit for revocation to be processed
      await new Promise(resolve => setTimeout(resolve, 200));

      // Set up close handler to wait for connection close
      const closePromise = new Promise<void>((resolve) => {
        ws.on('close', () => {
          resolve();
        });
      });

      // Try to send event (this should trigger revocation check)
      const testEvent: EncryptedEvent = {
        event_id: uuidv7(),
        user_id: userId,
        device_id: deviceId,
        device_seq: 1,
        stream_id: 'test-stream',
        stream_seq: 0,
        type: 'test_event',
        encrypted_payload: Buffer.from('test payload').toString('base64'),
      };

      ws.send(JSON.stringify({
        type: 'event',
        payload: testEvent,
      }));

      // Wait for close event or timeout
      await Promise.race([
        closePromise,
        new Promise(resolve => setTimeout(resolve, 2000)),
      ]);

      // Connection should be closed
      expect(ws.readyState).toBe(WebSocket.CLOSED);
    });
  });

  describe('Multi-Device Scenarios', () => {
    it('should handle three devices for same user', async () => {
      const clientIdentity = generateClientIdentity();
      const userId = clientIdentity.publicKeyHex;
      const deviceIds = [randomUUID(), randomUUID(), randomUUID()];

      const connections: WebSocket[] = [];

      // Connect all three devices
      for (const deviceId of deviceIds) {
        const ws = new WebSocket(`ws://localhost:${TEST_PORT}/ws`);
        await new Promise<void>((resolve) => {
          ws.on('open', async () => {
            await performHandshake(ws, userId, deviceId, clientIdentity);
            resolve();
          });
        });
        connections.push(ws);
      }

      // Wait for all to be connected
      await new Promise(resolve => setTimeout(resolve, 500));

      // All should be connected
      connections.forEach(ws => {
        expect(ws.readyState).toBe(WebSocket.OPEN);
      });

      // Cleanup
      connections.forEach(ws => ws.close());
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid message format', async () => {
      const clientIdentity = generateClientIdentity();
      const userId = clientIdentity.publicKeyHex;
      const deviceId = '550e8400-e29b-41d4-a716-446655440000';

      const ws = new WebSocket(`ws://localhost:${TEST_PORT}/ws`);
      await new Promise<void>((resolve) => {
        ws.on('open', async () => {
          await performHandshake(ws, userId, deviceId, clientIdentity);
          resolve();
        });
      });

      // Send invalid message
      ws.send(JSON.stringify({
        type: 'invalid_type',
        payload: { invalid: 'data' },
      }));

      // Wait a bit
      await new Promise(resolve => setTimeout(resolve, 500));

      // Connection should still be open (errors don't always close connection)
      // But invalid messages should be ignored
      ws.close();
    });

    it('should reject invalid device sequence (sequence must be >= 1)', async () => {
      // NOTE: This test validates that device_seq must be >= 1
      // This is about the EVENT SEQUENCE NUMBER (1, 2, 3...), NOT about the number of devices
      // A user with only one device is handled correctly - see "should not relay event when only one device is connected"
      
      const clientIdentity = generateClientIdentity();
      const userId = clientIdentity.publicKeyHex;
      const deviceId = '550e8400-e29b-41d4-a716-446655440000';

      const ws = new WebSocket(`ws://localhost:${TEST_PORT}/ws`);
      await new Promise<void>((resolve) => {
        ws.on('open', async () => {
          await performHandshake(ws, userId, deviceId, clientIdentity);
          resolve();
        });
      });

      // Send event with sequence 1 (valid)
      const event1: EncryptedEvent = {
        event_id: uuidv7(),
        user_id: userId,
        device_id: deviceId,
        device_seq: 1, // Valid: sequences start at 1
        stream_id: 'test-stream',
        stream_seq: 0,
        type: 'test_event',
        encrypted_payload: Buffer.from('test').toString('base64'),
      };

      ws.send(JSON.stringify({
        type: 'event',
        payload: event1,
      }));

      await new Promise(resolve => setTimeout(resolve, 200));

      // Send event with sequence 0 (invalid - should fail validation)
      // device_seq must be >= 1 (this is the event counter, not the number of devices)
      const event2: EncryptedEvent = {
        event_id: uuidv7(),
        user_id: userId,
        device_id: deviceId,
        device_seq: 0, // Invalid: must be >= 1 (event sequences start at 1, not 0)
        stream_id: 'test-stream',
        stream_seq: 0,
        type: 'test_event',
        encrypted_payload: Buffer.from('test').toString('base64'),
      };

      let errorReceived = false;
      let closeCode: number | undefined;
      let closeReason = '';

      ws.on('message', (data: Buffer) => {
        const message = JSON.parse(data.toString('utf8'));
        if (message.type === 'error') {
          errorReceived = true;
          expect(message.payload?.error).toContain('Device sequence');
        }
      });

      ws.on('close', (code, reason) => {
        closeCode = code;
        closeReason = reason.toString();
      });

      ws.send(JSON.stringify({
        type: 'event',
        payload: event2,
      }));

      // Wait for error/close
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Connection should be closed due to validation error
      expect(ws.readyState).toBe(WebSocket.CLOSED);
      expect(closeCode).toBe(1011); // Internal error code for validation failures
      expect(closeReason).toContain('Device sequence');
    });
  });
});

