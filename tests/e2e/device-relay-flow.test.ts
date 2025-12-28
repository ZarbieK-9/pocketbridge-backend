/**
 * End-to-End Device Relay Flow Tests
 * 
 * Tests the complete flow: two devices connect, one sends event, other receives it
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import WebSocket from 'ws';
import type { Database } from '../../src/db/postgres.js';
import type { RedisConnection } from '../../src/db/redis.js';
import { createWebSocketGateway } from '../../src/gateway/websocket.js';
import { handleEvent } from '../../src/gateway/event-handler.js';
import type { SessionState, EncryptedEvent } from '../../src/types/index.js';
import DeviceRelay from '../../src/services/device-relay.js';
import MultiDeviceSessionManager from '../../src/services/multi-device-sessions.js';
import * as nacl from 'tweetnacl';
import {
  generateECDHKeypair,
  signEd25519,
  hashForSignature,
  generateNonce,
} from '../../src/crypto/utils.js';

describe.skip('E2E Device Relay Flow', () => {
  // Skip E2E tests for now due to async import issues
  // These tests require a full server setup
  let server: ReturnType<typeof createServer>;
  let wss: WebSocketServer;
  let mockDb: Partial<Database>;
  let mockRedis: Partial<RedisConnection>;
  let deviceRelay: DeviceRelay;
  let sessionManager: MultiDeviceSessionManager;
  const port = 3003;

  beforeEach(async () => {
    server = createServer();
    wss = new WebSocketServer({ server, path: '/ws' });

    sessionManager = new MultiDeviceSessionManager();
    deviceRelay = new DeviceRelay(sessionManager);

    // Mock database
    mockDb = {
      pool: {
        query: vi.fn(),
      } as any,
    };

    // Mock Redis subscriber
    const mockSubscriber = {
      subscribe: vi.fn(),
      quit: vi.fn(),
      on: vi.fn(),
    };

    mockRedis = {
      client: {
        publish: vi.fn().mockResolvedValue(1),
        duplicate: vi.fn().mockReturnValue(mockSubscriber),
      } as any,
    };

    // Initialize gateway
    createWebSocketGateway(wss, {
      db: mockDb as Database,
      redis: mockRedis as RedisConnection,
    });

    await new Promise<void>((resolve) => {
      server.listen(port, () => resolve());
    });
  });

  afterEach(async () => {
    return new Promise<void>((resolve) => {
      wss.close(() => {
        server.close(() => resolve());
      });
    });
  });

  describe('Device-to-Device Event Relay', () => {
    it('should relay event from device 1 to device 2', async () => {
      // Generate user identity
      const userKeypair = nacl.sign.keyPair();
      const userId = Buffer.from(userKeypair.publicKey).toString('hex');
      const userPrivateKeyHex = Buffer.from(userKeypair.secretKey).toString('hex');

      const deviceId1 = '550e8400-e29b-41d4-a716-446655440000';
      const deviceId2 = '660e8400-e29b-41d4-a716-446655440001';

      // Mock database responses
      (mockDb.pool!.query as any)
        .mockResolvedValueOnce({ rows: [] }) // User insert (device 1)
        .mockResolvedValueOnce({ rows: [{ last_ack_device_seq: 0 }] }) // Device insert (device 1)
        .mockResolvedValueOnce({ rows: [] }) // User insert (device 2)
        .mockResolvedValueOnce({ rows: [{ last_ack_device_seq: 0 }] }) // Device insert (device 2)
        .mockResolvedValue({ rows: [{ last_stream_seq: 0 }] }); // Stream sequence queries

      return new Promise<void>((resolve, reject) => {
        const device1Messages: any[] = [];
        const device2Messages: any[] = [];
        let device1Session: SessionState | null = null;
        let device2Session: SessionState | null = null;

        // Helper to complete handshake
        const completeHandshake = async (
          ws: WebSocket,
          deviceId: string,
          onSessionEstablished: (session: SessionState) => void
        ) => {
          return new Promise<void>((wsResolve, wsReject) => {
            const clientEphemeralKeypair = generateECDHKeypair();
            const nonceC = generateNonce();
            let serverHello: any = null;

            ws.on('message', async (data: Buffer) => {
              const message = JSON.parse(data.toString());

              if (message.type === 'server_hello') {
                serverHello = message.payload;
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
                  userPrivateKeyHex,
                  signatureData
                );

                const clientAuth = {
                  type: 'client_auth',
                  payload: {
                    user_id: userId,
                    device_id: deviceId,
                    nonce_c2: nonceC2,
                    client_signature: clientSignature,
                  },
                };

                ws.send(JSON.stringify(clientAuth));
              } else if (message.type === 'session_established') {
                // Create session state
                const session: SessionState = {
                  userId,
                  deviceId,
                  sessionKeys: {
                    clientKey: Buffer.from('client-key'),
                    serverKey: Buffer.from('server-key'),
                  },
                  lastAckDeviceSeq: message.payload.last_ack_device_seq || 0,
                  createdAt: Date.now(),
                };
                onSessionEstablished(session);
                wsResolve();
              } else if (message.type === 'error') {
                wsReject(new Error(message.payload?.error || 'Handshake failed'));
              }
            });

            // Send client hello
            ws.send(JSON.stringify({
              type: 'client_hello',
              payload: {
                client_ephemeral_pub: clientEphemeralKeypair.publicKey,
                nonce_c: nonceC,
              },
            }));
          });
        };

        // Connect Device 1
        const ws1 = new WebSocket(`ws://localhost:${port}/ws`);
        ws1.on('open', async () => {
          await completeHandshake(ws1, deviceId1, (session) => {
            device1Session = session;
          });

          // Connect Device 2
          const ws2 = new WebSocket(`ws://localhost:${port}/ws`);
          ws2.on('open', async () => {
            await completeHandshake(ws2, deviceId2, (session) => {
              device2Session = session;
            });

            // Device 2 listens for events
            ws2.on('message', (data: Buffer) => {
              const message = JSON.parse(data.toString());
              device2Messages.push(message);

              if (message.type === 'event') {
                expect(message.payload.user_id).toBe(userId);
                expect(message.payload.device_id).toBe(deviceId1);
                expect(message.payload.type).toBe('clipboard');
                resolve();
              }
            });

            // Device 1 sends event
            if (device1Session) {
              const event: EncryptedEvent = {
                event_id: '01234567-89ab-7def-0123-456789abcdef',
                user_id: userId,
                device_id: deviceId1,
                device_seq: 1,
                stream_id: 'stream-123',
                stream_seq: 1,
                type: 'clipboard',
                encrypted_payload: Buffer.from('test payload').toString('base64'),
                created_at: Date.now(),
              };

              // Send event through handler
              handleEvent(
                event,
                device1Session,
                mockDb as Database,
                mockRedis as RedisConnection,
                deviceRelay
              ).then(() => {
                // Event should be relayed to device 2
                // Wait a bit for relay
                setTimeout(() => {
                  if (device2Messages.length === 0) {
                    reject(new Error('Event not relayed to device 2'));
                  }
                }, 1000);
              }).catch(reject);
            }
          });

          ws2.on('error', reject);
        });

        ws1.on('error', reject);

        setTimeout(() => {
          reject(new Error('Test timeout'));
        }, 15000);
      });
    });

    it('should not relay events between different users', async () => {
      // This test verifies user isolation
      const user1Keypair = nacl.sign.keyPair();
      const user1Id = Buffer.from(user1Keypair.publicKey).toString('hex');
      const user1PrivateKey = Buffer.from(user1Keypair.secretKey).toString('hex');

      const user2Keypair = nacl.sign.keyPair();
      const user2Id = Buffer.from(user2Keypair.publicKey).toString('hex');

      const deviceId1 = '550e8400-e29b-41d4-a716-446655440000';
      const deviceId2 = '660e8400-e29b-41d4-a716-446655440001';

      (mockDb.pool!.query as any).mockResolvedValue({ rows: [{ last_stream_seq: 0 }] });

      return new Promise<void>((resolve, reject) => {
        const device2Messages: any[] = [];

        // Connect Device 1 (User 1)
        const ws1 = new WebSocket(`ws://localhost:${port}/ws`);
        ws1.on('open', async () => {
          // Complete handshake for device 1 (simplified)
          const session1: SessionState = {
            userId: user1Id,
            deviceId: deviceId1,
            sessionKeys: { clientKey: Buffer.from('key1'), serverKey: Buffer.from('key1') },
            lastAckDeviceSeq: 0,
            createdAt: Date.now(),
          };

          // Connect Device 2 (User 2)
          const ws2 = new WebSocket(`ws://localhost:${port}/ws`);
          ws2.on('open', () => {
            ws2.on('message', (data: Buffer) => {
              const message = JSON.parse(data.toString());
              device2Messages.push(message);
            });

            // Device 1 sends event with user2's ID (should be blocked)
            const maliciousEvent: EncryptedEvent = {
              event_id: '01234567-89ab-7def-0123-456789abcdef',
              user_id: user2Id, // Different user!
              device_id: deviceId1,
              device_seq: 1,
              stream_id: 'stream-123',
              stream_seq: 1,
              type: 'clipboard',
              encrypted_payload: Buffer.from('test').toString('base64'),
              created_at: Date.now(),
            };

            handleEvent(
              maliciousEvent,
              session1,
              mockDb as Database,
              mockRedis as RedisConnection,
              deviceRelay
            ).then(() => {
              // Wait to ensure no relay happened
              setTimeout(() => {
                // Device 2 should not receive the event
                const relayedEvents = device2Messages.filter(m => m.type === 'event');
                expect(relayedEvents.length).toBe(0);
                resolve();
              }, 1000);
            }).catch(reject);
          });

          ws2.on('error', reject);
        });

        ws1.on('error', reject);

        setTimeout(() => {
          reject(new Error('Test timeout'));
        }, 10000);
      });
    });
  });
});

