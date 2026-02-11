/**
 * WebSocket Gateway
 *
 * Handles:
 * - Session handshake (MTProto-inspired)
 * - Connection lifecycle
 * - Event routing via Redis
 * - Replay on reconnect
 * - Presence tracking
 *
 * Security:
 * - Authenticates clients via Ed25519 signatures
 * - Establishes forward-secret sessions via ECDH
 * - Never decrypts payloads (E2E encryption)
 * - Rate limiting
 * - Input validation
 * - Timeouts
 */

import crypto from 'crypto';
import { WebSocketServer, WebSocket } from 'ws';
import type { Database } from '../db/postgres.js';
import type { RedisConnection } from '../db/redis.js';
import type { ConnectionStatus } from '../types/index.js';
import { config } from '../config.js';
import { handleHandshake } from './handshake.js';
import { handleEvent } from './event-handler.js';
import { logger } from '../utils/logger.js';
import { ValidationError } from '../utils/errors.js';
import { isDeviceRevoked } from '../services/device-revocation.js';
import {
  rateLimitConnection,
  rateLimitHandshake,
  getClientIdentifier,
  trackUserDevice,
  untrackUserDevice,
  checkConcurrentDeviceLimit,
  tryTrackUserDevice,
} from '../middleware/rate-limit.js';
import {
  checkConnectionLimit,
  tryIncrementConnection,
  incrementConnection,
  decrementConnection,
} from '../middleware/connection-limits.js';
import { auditLog, AuditEventType } from '../utils/audit-log.js';
import { storeSession, deleteSession, updateSession } from '../services/session-store.js';
import { shouldRotateKeys } from '../services/session-rotation.js';
import MultiDeviceSessionManager from '../services/multi-device-sessions.js';
import PresenceBroadcaster from '../services/presence-broadcaster.js';
import DeviceRelay from '../services/device-relay.js';
import { incrementCounter, setGauge, recordHistogram } from '../services/metrics.js';
import type { SessionState, ReplayRequest, ReplayResponse } from '../types/index.js';
import {
  initiatePairing,
  completePairing,
} from '../services/device-pairing.js';
import type { ServerIdentityKeypair } from '../crypto/utils.js';

interface GatewayDependencies {
  db: Database;
  redis: RedisConnection;
  serverIdentity?: ServerIdentityKeypair;
}

// Track in-flight replay requests to prevent concurrent duplicate replays
const inFlightReplayRequests = new WeakMap<WebSocket, boolean>();

/**
 * Safely send message to WebSocket with state validation
 * Returns true if sent successfully, false if connection not ready
 */
function safeSend(ws: WebSocket, message: string, context?: { userId?: string; deviceId?: string }): boolean {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    if (context) {
      logger.debug('Skipping send to non-OPEN WebSocket', {
        userId: context.userId?.substring(0, 16) + '...',
        deviceId: context.deviceId,
        readyState: ws?.readyState,
      });
    }
    return false;
  }

  try {
    ws.send(message);
    return true;
  } catch (error) {
    logger.error(
      'Failed to send WebSocket message',
      context || {},
      error instanceof Error ? error : new Error(String(error))
    );
    return false;
  }
}

/**
 * Create WebSocket gateway
 * Returns sessions Map for status API access (flat view via getAllSessionsFlat())
 */
export function createWebSocketGateway(
  wss: WebSocketServer,
  deps: GatewayDependencies
): Map<string, SessionState> {
  const { db, redis } = deps;
  // Get server identity from config (not from deps to avoid type issues)
  const serverIdentity: ServerIdentityKeypair = config.serverIdentity;

  // Create multi-device session manager (grouping by user_id -> device_id)
  const sessionManager = new MultiDeviceSessionManager();

  // Create device relay service - core relay system that connects devices
  const deviceRelay = new DeviceRelay(sessionManager);

  // Create presence broadcaster for Redis pub/sub
  const presenceBroadcaster = new PresenceBroadcaster(redis.client);

  // Store Redis subscribers per connection (for cleanup)
  const subscribers = new WeakMap<WebSocket, any>();

  // Track active subscriber count for metrics
  let activeSubscriberCount = 0;

  // Store handshake timeouts
  const handshakeTimeouts = new Map<WebSocket, NodeJS.Timeout>();

  // Store heartbeat intervals
  const heartbeatIntervals = new Map<WebSocket, NodeJS.Timeout>();

  // Store last pong time per connection
  const lastPongTime = new WeakMap<WebSocket, number>();

  // Store connection status per WebSocket
  const connectionStatuses = new WeakMap<WebSocket, ConnectionStatus>();

  // Track which sessions have received expiration warning (avoid spamming)
  const expirationWarningsent = new WeakMap<WebSocket, boolean>();

  // Track buffered message count per WebSocket (for overflow protection)
  const bufferedMessageCount = new WeakMap<WebSocket, number>();
  const MAX_BUFFERED_MESSAGES = 100; // Maximum messages to buffer before closing connection

  // Store session timeout interval for cleanup
  const sessionTimeoutInterval = setInterval(() => {
    const now = Date.now();
    const warningThresholdMs = 5 * 60 * 1000; // 5 minutes before expiry
    const sessionTimeoutMs = config.websocket.sessionTimeout;

    // Iterate through all active sessions
    wss.clients.forEach((ws: WebSocket) => {
      const status = connectionStatuses.get(ws);
      if (status !== 'connected') return; // Skip non-connected

      // Get session state from WebSocket (if available)
      const wsWithState = ws as any;
      const sessionState = wsWithState._sessionState;
      if (!sessionState) return;

      const ageMs = now - sessionState.createdAt;
      const remainingMs = sessionTimeoutMs - ageMs;

      // Send warning if within 5 min window and not yet sent
      if (remainingMs <= warningThresholdMs && remainingMs > 0) {
        const alreadyWarned = expirationWarningsent.get(ws);
        if (!alreadyWarned) {
          const sent = safeSend(
            ws,
            JSON.stringify({
              type: 'session_expiring_soon',
              payload: {
                type: 'session_expiring_soon',
                expires_in_seconds: Math.ceil(remainingMs / 1000),
                expires_at: now + remainingMs,
              },
            }),
            { userId: sessionState.userId, deviceId: sessionState.deviceId }
          );
          if (sent) {
            expirationWarningsent.set(ws, true);
            logger.info('Session expiration warning sent', {
              deviceId: sessionState.deviceId,
              expiresInSeconds: Math.ceil(remainingMs / 1000),
            });
          }
        }
      }

      // Close connection if expired
      if (remainingMs <= 0) {
        logger.info('Session expired, closing connection', {
          deviceId: sessionState.deviceId,
          ageMs,
          timeoutMs: sessionTimeoutMs,
        });
        ws.close(1008, 'Session expired. Please re-authenticate.');
      }
    });

    // Also clean up in-memory sessions
    const cleaned = sessionManager.cleanup(sessionTimeoutMs);
    if (cleaned > 0) {
      logger.info('Cleaned up expired sessions', { cleaned });
    }
  }, 60000); // Check every minute

  wss.on('connection', (ws: WebSocket, req) => {
    const clientId = getClientIdentifier(req);
    logger.info('New WebSocket connection', { clientId, readyState: ws.readyState });

    // Track connection metrics
    incrementCounter('websocket_connections_total', { status: 'new' });
    setGauge('websocket_connections_active', wss.clients.size);

    // Set initial status to connecting
    connectionStatuses.set(ws, 'connecting');

    // Track if connection was closed
    let connectionClosed = false;
    ws.on('close', (code, reason) => {
      connectionClosed = true;
      // Clean up buffered message count
      bufferedMessageCount.delete(ws);
      logger.debug('WebSocket closed in connection handler', {
        clientId,
        code,
        reason: reason.toString(),
        readyState: ws.readyState,
      });
    });

    // CRITICAL: Set up message handler IMMEDIATELY so messages aren't lost
    // We'll check rate limits inside the handler
    let sessionState: SessionState | null = null;
    let handshakeComplete = false;
    let rateLimitChecked = false;
    let rateLimitAllowed = false;

    // Set handshake timeout (60 seconds - increased for slower connections)
    const handshakeTimeout = setTimeout(() => {
      const currentTimeout = handshakeTimeouts.get(ws);
      const currentSessionState = (ws as any)._sessionState;
      if (
        currentTimeout === handshakeTimeout &&
        !handshakeComplete &&
        !sessionState &&
        !currentSessionState
      ) {
        auditLog(AuditEventType.HANDSHAKE_TIMEOUT, { clientId });
        logger.warn('Handshake timeout', { 
          clientId, 
          readyState: ws.readyState,
          timeoutMs: 60000,
        });
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
          ws.close(1008, 'Handshake timeout');
        }
      }
    }, 60000); // Increased from 30s to 60s for slower connections
    handshakeTimeouts.set(ws, handshakeTimeout);

    logger.debug('Message handler attached, waiting for client_hello', {
      clientId,
      readyState: ws.readyState,
    });

    // Handle incoming messages - set up immediately
    ws.on('message', async (data: Buffer) => {
      // Declare message outside try block so it's accessible in catch
      let message: any = null;
      
      try {
        // Check buffer overflow protection
        const currentBuffered = bufferedMessageCount.get(ws) || 0;
        if (currentBuffered >= MAX_BUFFERED_MESSAGES) {
          logger.warn('WebSocket message buffer overflow, closing connection', {
            clientId,
            bufferedCount: currentBuffered,
            maxBuffered: MAX_BUFFERED_MESSAGES,
            readyState: ws.readyState,
          });
          auditLog(AuditEventType.SECURITY_VIOLATION, {
            clientId,
            details: { reason: 'message_buffer_overflow' },
          });
          if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
            ws.close(1008, 'Message buffer overflow');
          }
          return;
        }

        // Increment buffered message count
        bufferedMessageCount.set(ws, currentBuffered + 1);

        // Check rate limit on first message (non-blocking check)
        if (!rateLimitChecked) {
          rateLimitChecked = true;
          logger.debug('Checking rate limit on first message', {
            clientId,
            readyState: ws.readyState,
          });

          let connectionLimit: { allowed: boolean; error?: string };
          if (redis) {
            try {
              const { createDistributedRateLimiters } =
                await import('../middleware/rate-limit-redis.js');
              const distributedLimiters = createDistributedRateLimiters(redis);
              const result = await distributedLimiters.connection.check(
                clientId,
                60000, // 1 minute
                60 // 60 connections per minute
              );
              connectionLimit = { allowed: result.allowed, error: result.error };
            } catch (error) {
              logger.warn('Distributed rate limiting failed, using in-memory', { error });
              connectionLimit = rateLimitConnection(clientId);
            }
          } else {
            connectionLimit = rateLimitConnection(clientId);
          }

          logger.debug('Rate limit check completed', {
            clientId,
            allowed: connectionLimit.allowed,
            readyState: ws.readyState,
          });

          if (!connectionLimit.allowed) {
            auditLog(AuditEventType.RATE_LIMIT_HIT, { clientId, details: { type: 'connection' } });
            logger.warn('Connection rate limited', { clientId });
            if (ws.readyState === WebSocket.OPEN) {
              ws.close(1008, connectionLimit.error);
            }
            return;
          }

          rateLimitAllowed = true;
          logger.debug('Rate limit passed', { clientId, readyState: ws.readyState });
        } else if (!rateLimitAllowed) {
          // Rate limit was checked and failed, but message still arrived - ignore it
          logger.debug('Ignoring message from rate-limited connection', { clientId });
          return;
        }

        // Validate message size (prevent DoS)
        // 5MB chunks + encryption + double base64 encoding can exceed 10MB
        // Allow up to 15MB to accommodate encrypted 5MB chunks with overhead
        if (data.length > 15 * 1024 * 1024) {
          // 15MB
          throw new Error('Message too large');
        }

        // Parse message (message is declared at function scope for error handling)
        try {
          message = JSON.parse(data.toString('utf8'));
        } catch (parseError) {
          logger.error(
            'Failed to parse WebSocket message',
            {
              clientId,
              dataLength: data.length,
              dataPreview: data.toString('utf8').substring(0, 200),
              error: parseError instanceof Error ? parseError.message : String(parseError),
            },
            parseError instanceof Error ? parseError : new Error(String(parseError))
          );
          ws.close(1008, 'Invalid message format');
          return;
        }

        logger.debug('Received message', {
          clientId,
          dataLength: data.length,
          readyState: ws.readyState,
          handshakeComplete,
          rateLimitChecked,
          rateLimitAllowed,
          messageType: message?.type,
          hasPayload: !!message?.payload,
        });

        if (!handshakeComplete) {
          // Rate limit handshake (enabled with higher limits for production)
          const handshakeLimit = rateLimitHandshake(clientId);
          if (!handshakeLimit.allowed) {
            auditLog(AuditEventType.RATE_LIMIT_HIT, { clientId, details: { type: 'handshake' } });
            ws.close(1008, handshakeLimit.error);
            return;
          }

          // Handle handshake
          // Extract handshake message - check if it's wrapped in payload or direct
          let handshakeMessage: any;
          if (message.type === 'client_hello' || message.type === 'client_auth') {
            // If message has payload and payload has the same type, use payload
            // Otherwise use message directly (for unwrapped messages)
            if (message.payload && (message.payload as any).type === message.type) {
              handshakeMessage = message.payload;
            } else {
              handshakeMessage = message;
            }
          } else {
            handshakeMessage = message.payload || message;
          }
          logger.info('Processing handshake message', {
            messageType: message.type,
            handshakeType: handshakeMessage?.type,
            clientId,
            hasPayload: !!message.payload,
            hasNonceC: !!(handshakeMessage as any)?.nonce_c,
            nonceCLength: (handshakeMessage as any)?.nonce_c?.length,
            wsReadyState: ws.readyState,
            rawMessage: JSON.stringify(message).substring(0, 200),
            extractedMessage: JSON.stringify(handshakeMessage).substring(0, 200),
          });

          // Validate server identity is configured
          if (!serverIdentity || !serverIdentity.publicKeyHex || !serverIdentity.privateKey) {
            logger.error('Server identity not configured', { clientId });
            ws.close(1008, 'Server configuration error');
            return;
          }

          const result = await handleHandshake(handshakeMessage, ws, db, serverIdentity);

          logger.info('Handshake result', {
            success: result.success,
            error: result.error || 'No error (success)',
            hasSessionState: !!result.sessionState,
            messageType: handshakeMessage?.type,
            errorDetails: result.error || 'No error (success)',
            resultKeys: Object.keys(result),
          });

          // handleClientHello returns { success: true } without sessionState
          // handleClientAuth returns { success: true, sessionState: ... }
          if (result.success) {
            if (result.sessionState) {
              // Client auth succeeded, establish session
              const newSessionState = result.sessionState;

              // Clear handshake timeout FIRST to prevent race condition
              // This must happen before any other async operations
              const timeout = handshakeTimeouts.get(ws);
              if (timeout) {
                clearTimeout(timeout);
                handshakeTimeouts.delete(ws);
              }

              // Double-check handshake wasn't completed concurrently
              if (handshakeComplete || sessionState) {
                logger.warn('Handshake completed concurrently, ignoring duplicate completion', {
                  clientId,
                });
                return;
              }

              // Atomically check connection limits and increment count
              // This prevents race conditions where multiple connections bypass limits
              const connectionResult = tryIncrementConnection(
                newSessionState.userId,
                newSessionState.deviceId
              );
              if (!connectionResult.success) {
                auditLog(AuditEventType.CONNECTION_LIMIT_EXCEEDED, {
                  userId: newSessionState.userId,
                  deviceId: newSessionState.deviceId,
                });
                logger.warn('Connection limit exceeded', {
                  userId: newSessionState.userId.substring(0, 16) + '...',
                  deviceId: newSessionState.deviceId,
                });
                ws.close(1008, connectionResult.error);
                return;
              }

              // Atomically check per-user concurrent device limit and track device (max 5 devices)
              const deviceTrackResult = tryTrackUserDevice(newSessionState.userId, newSessionState.deviceId, 5);
              if (!deviceTrackResult.success) {
                auditLog(AuditEventType.CONNECTION_LIMIT_EXCEEDED, {
                  userId: newSessionState.userId,
                  deviceId: newSessionState.deviceId,
                  details: { reason: 'too_many_devices' },
                });
                logger.warn('Per-user device limit exceeded', {
                  userId: newSessionState.userId.substring(0, 16) + '...',
                  deviceId: newSessionState.deviceId,
                });
                // Rollback connection count since we're rejecting
                decrementConnection(newSessionState.userId, newSessionState.deviceId);
                ws.close(1008, deviceTrackResult.error);
                return;
              }

              sessionState = newSessionState;
              handshakeComplete = true;

              // Attach session to WebSocket for access in timeout checks
              (ws as any)._sessionState = newSessionState;

              // Update device online status in database
              try {
                await db.pool.query(
                  'UPDATE user_devices SET is_online = TRUE, last_seen = NOW() WHERE device_id = $1::uuid',
                  [newSessionState.deviceId]
                );
                logger.debug('Device marked as online', { deviceId: newSessionState.deviceId });
              } catch (error) {
                logger.error(
                  'Failed to update device online status',
                  { deviceId: newSessionState.deviceId },
                  error instanceof Error ? error : new Error(String(error))
                );
              }

              // Check if this device ID is already connected for this user
              const existingSession = sessionManager.getSession(
                newSessionState.userId,
                newSessionState.deviceId
              );
              if (existingSession) {
                logger.warn('⚠️  DUPLICATE DEVICE_ID - Closing old connection', {
                  userId: newSessionState.userId.substring(0, 16) + '...',
                  deviceId: newSessionState.deviceId,
                  existingSessionAge: Date.now() - existingSession.createdAt,
                });

                // Get the old WebSocket and close it
                const oldWs = sessionManager.getWebSocket(
                  newSessionState.userId,
                  newSessionState.deviceId
                );
                if (oldWs && oldWs.readyState === WebSocket.OPEN) {
                  logger.info('Closing old WebSocket for duplicate device', {
                    deviceId: newSessionState.deviceId,
                  });
                  oldWs.close(1000, 'New connection established for this device');
                }
              }

              sessionManager.addSession(
                newSessionState.userId,
                newSessionState.deviceId,
                newSessionState,
                ws
              );

              logger.info('✅ Session added to manager', {
                userId: newSessionState.userId.substring(0, 16) + '...',
                deviceId: newSessionState.deviceId,
                totalDevicesForUser: sessionManager.getOnlineDevices(newSessionState.userId).length,
                allDeviceIds: sessionManager.getOnlineDevices(newSessionState.userId),
              });

              // Device already tracked atomically above with tryTrackUserDevice

              // Update status to connected
              connectionStatuses.set(ws, 'connected');

              // Track metrics
              incrementCounter('websocket_handshakes_total', { status: 'success' });
              incrementCounter('websocket_connections_total', { status: 'connected' });
              setGauge('websocket_connections_active', wss.clients.size);
              setGauge('users_active', sessionManager.getAllUsers().length);
              setGauge('devices_active', sessionManager.getTotalSessions());

              // Store session in Redis for horizontal scaling
              await storeSession(redis, newSessionState);

              // Connection count already incremented atomically in tryIncrementConnection above

              // Subscribe to Redis channel for this device
              try {
                const subscriber = await subscribeToDeviceChannel(
                  redis,
                  newSessionState.userId,
                  newSessionState.deviceId,
                  ws
                );
                subscribers.set(ws, subscriber);
                activeSubscriberCount++;
                setGauge('redis_subscribers_active', activeSubscriberCount);
                logger.debug('Subscribed to Redis channel', {
                  deviceId: newSessionState.deviceId,
                  activeSubscribers: activeSubscriberCount,
                });
              } catch (error) {
                logger.error(
                  'Failed to subscribe to device channel',
                  {
                    deviceId: newSessionState.deviceId,
                  },
                  error instanceof Error ? error : new Error(String(error))
                );
                incrementCounter('redis_subscriber_errors_total');
                // Continue without Redis subscription (degraded mode)
              }

              // Update presence
              try {
                await updatePresence(redis, newSessionState.deviceId, true);
              } catch (error) {
                logger.error(
                  'Failed to update presence',
                  {
                    deviceId: newSessionState.deviceId,
                  },
                  error instanceof Error ? error : new Error(String(error))
                );
                // Continue without presence update (degraded mode)
              }

              // Broadcast device online to other devices (presence update)
              try {
                const result = await db.pool.query(
                  `SELECT device_id, device_name, device_type, device_os, is_online, last_seen, ip_address
                   FROM user_devices 
                   WHERE user_id = $1 AND device_id = $2`,
                  [newSessionState.userId, newSessionState.deviceId]
                );

                if (result.rows.length > 0) {
                  const device = result.rows[0];
                  const deviceInfo = {
                    device_id: device.device_id,
                    device_name: device.device_name || 'Unknown Device',
                    device_type: device.device_type || 'web',
                    device_os: device.device_os,
                    is_online: true,
                    last_seen: Date.now(),
                  };

                  // Publish device online event to other devices
                  await presenceBroadcaster.publishDeviceOnline(newSessionState.userId, deviceInfo);
                  // Cache device status in Redis
                  await presenceBroadcaster.cacheDeviceStatus(
                    newSessionState.userId,
                    newSessionState.deviceId,
                    true
                  );

                  // Broadcast presence update to other devices for real-time UI
                  await deviceRelay.broadcastSystemMessage(
                    newSessionState.userId,
                    {
                      type: 'device_status_changed',
                      payload: {
                        type: 'device_status_changed',
                        user_id: newSessionState.userId,
                        device_id: newSessionState.deviceId,
                        device_name: device.device_name || 'Unknown Device',
                        device_type: device.device_type || 'web',
                        is_online: true,
                        timestamp: Date.now(),
                      },
                    },
                    newSessionState.deviceId
                  );
                }
              } catch (error) {
                logger.warn(
                  'Failed to publish device online presence',
                  {
                    userId: newSessionState.userId.substring(0, 16) + '...',
                    deviceId: newSessionState.deviceId,
                  },
                  error instanceof Error ? error : new Error(String(error))
                );
              }

              // Start heartbeat (ping every 30 seconds)
              startHeartbeat(ws, sessionState);

              auditLog(AuditEventType.AUTHENTICATION_SUCCESS, {
                userId: newSessionState.userId,
                deviceId: newSessionState.deviceId,
              });
              logger.info('Session established', {
                deviceId: newSessionState.deviceId,
                userId: newSessionState.userId.substring(0, 16) + '...',
              });
            } else {
              // Client hello succeeded, waiting for client_auth
              logger.debug('Client hello processed, waiting for client_auth');
            }
          } else {
            incrementCounter('websocket_handshakes_total', {
              status: 'failed',
              error: result.error || 'unknown',
            });
            auditLog(AuditEventType.AUTHENTICATION_FAILURE, {
              clientId,
              details: { error: result.error },
            });
            logger.warn('Handshake failed', {
              clientId,
              error: result.error,
            });
            ws.close(1008, result.error || 'Handshake failed');
          }
        } else {
          // Handle authenticated messages
          if (!sessionState) {
            logger.warn('No session state for authenticated message', { clientId });
            ws.close(1008, 'No session state');
            return;
          }

          // Check if device is revoked before processing any message (security)
          const revoked = await isDeviceRevoked(db, sessionState.deviceId);
          if (revoked) {
            auditLog(AuditEventType.DEVICE_REVOKED, {
              userId: sessionState.userId,
              deviceId: sessionState.deviceId,
              details: { reason: 'Revoked device attempted to send message' },
            });
            logger.warn('Revoked device attempted to send message', {
              deviceId: sessionState.deviceId,
              userId: sessionState.userId.substring(0, 16) + '...',
            });
            ws.close(1008, 'Device has been revoked');
            return;
          }

          if (message.type === 'event') {
            // RELAY: Automatically relay event to all other devices of the same user
            await handleEvent(message.payload, sessionState, db, redis, deviceRelay);

            // Send ACK back to sender to confirm event was processed (or was a duplicate)
            // This allows the client to clean up its pending queue
            const eventPayload = message.payload as { device_seq?: number };
            if (eventPayload.device_seq !== undefined) {
              safeSend(
                ws,
                JSON.stringify({
                  type: 'ack',
                  payload: { device_seq: eventPayload.device_seq },
                }),
                { userId: sessionState.userId, deviceId: sessionState.deviceId }
              );
            }

            // Check if keys should be rotated (based on session age)
            // Note: Event count tracking would require additional state management
            // For now, we rotate based on session age (24 hours)
            if (shouldRotateKeys(sessionState)) {
              logger.info('Session keys should be rotated - forcing re-handshake', {
                deviceId: sessionState.deviceId,
                sessionAge: Date.now() - sessionState.createdAt,
                sessionAgeHours: ((Date.now() - sessionState.createdAt) / (60 * 60 * 1000)).toFixed(
                  2
                ),
              });

              // Force re-handshake by closing connection with rotation code
              // Client will reconnect and perform new handshake
              ws.close(1001, 'Session key rotation required');
              return;
            }

            // Update session in Redis (refresh TTL)
            await updateSession(redis, sessionState);
            // Refresh presence cache TTL to match session TTL
            await presenceBroadcaster.cacheDeviceStatus(
              sessionState.userId,
              sessionState.deviceId,
              true
            );
          } else if (message.type === 'scratchpad_sync') {
            // Direct relay for scratchpad Yjs updates
            // No storage, no sequence tracking, no ACKs
            // Yjs CRDT handles convergence and conflict resolution natively
            console.log('[ScratchpadSync:BACKEND] Received scratchpad_sync from device:', sessionState.deviceId, 'user:', sessionState.userId.substring(0, 16) + '...');
            const relayResult = await deviceRelay.broadcastSystemMessage(
              sessionState.userId,
              { type: 'scratchpad_sync', payload: message.payload },
              sessionState.deviceId // exclude sender
            );
            console.log('[ScratchpadSync:BACKEND] Relay result — sent:', relayResult.sent, 'failed:', relayResult.failed);
          } else if (message.type === 'ping') {
            // Respond to heartbeat ping with pong
            safeSend(
              ws,
              JSON.stringify({
                type: 'pong',
                payload: { timestamp: Date.now() },
              }),
              { userId: sessionState.userId, deviceId: sessionState.deviceId }
            );
          } else if (message.type === 'replay_request') {
            await handleReplayRequest(message as ReplayRequest, sessionState, db, ws);
          } else if (message.type === 'ack') {
            await handleAck(message.payload, sessionState, db);
            // Update session in Redis
            await updateSession(redis, sessionState);
            // Refresh presence cache TTL to match session TTL
            await presenceBroadcaster.cacheDeviceStatus(
              sessionState.userId,
              sessionState.deviceId,
              true
            );
          } else if (message.type === 'initiate_pairing') {
            // Device initiates pairing - generates 6-digit code
            try {
              if (!redis) {
                throw new Error('Redis client not available');
              }
              const code = await initiatePairing(redis, sessionState.userId, sessionState.deviceId);
              const expiresIn = 5 * 60 * 1000; // 5 minutes
              safeSend(
                ws,
                JSON.stringify({
                  type: 'pairing_initiated',
                  payload: {
                    code,
                    expiresIn,
                  },
                }),
                { userId: sessionState.userId, deviceId: sessionState.deviceId }
              );
              logger.info('Pairing code generated', {
                userId: sessionState.userId.substring(0, 12) + '...',
                deviceId: sessionState.deviceId,
                code: code.substring(0, 3) + '***',
              });
            } catch (error) {
              logger.error('Failed to initiate pairing', {
                userId: sessionState.userId.substring(0, 12) + '...',
                deviceId: sessionState.deviceId,
                error: error instanceof Error ? error.message : String(error),
              }, error);
              safeSend(
                ws,
                JSON.stringify({
                  type: 'pairing_failed',
                  payload: {
                    error: error instanceof Error ? error.message : 'Failed to generate pairing code',
                  },
                })
              );
            }
          } else if (message.type === 'complete_pairing') {
            // Device completes pairing - verifies code and links to initiating user
            const pairingCode = message.payload?.pairing_code;
            if (!pairingCode || typeof pairingCode !== 'string' || !/^\d{6}$/.test(pairingCode)) {
              safeSend(
                ws,
                JSON.stringify({
                  type: 'pairing_failed',
                  payload: {
                    error: 'Invalid pairing code format',
                  },
                }),
                { userId: sessionState.userId, deviceId: sessionState.deviceId }
              );
              return;
            }

            try {
              const { linkedUserId, success } = await completePairing(
                redis,
                db,
                pairingCode,
                sessionState.userId,
                sessionState.deviceId
              );

              if (success) {
                // ATOMIC SESSION STATE UPDATE with rollback capability
                // CRITICAL: We defer updating sessionState.userId until ALL operations succeed
                // This prevents messages being processed with wrong userId during the transition
                const oldUserId = sessionState.userId;
                const oldLastAckDeviceSeq = sessionState.lastAckDeviceSeq; // Save for rollback
                let subscriptionUpdated = false;
                let sessionManagerUpdated = false;
                let oldSubscriber: ReturnType<typeof subscribers.get> | null = null;
                let newSubscriber: Awaited<ReturnType<typeof subscribeToDeviceChannel>> | null = null;

                try {
                  // Step 1: Update Redis subscription
                  // IMPORTANT: Subscribe to NEW channel BEFORE unsubscribing from OLD channel
                  // This ensures no events are lost during the transition (we may receive duplicates briefly,
                  // but that's better than losing events)
                  oldSubscriber = subscribers.get(ws) || null;

                  // First, subscribe to new channel (now subscribed to both)
                  newSubscriber = await subscribeToDeviceChannel(
                    redis,
                    linkedUserId,
                    sessionState.deviceId,
                    ws
                  );
                  // Don't update subscribers map yet - wait until old subscription is cleaned up
                  activeSubscriberCount++;
                  setGauge('redis_subscribers_active', activeSubscriberCount);

                  // Now, unsubscribe from old channel (subscribed only to new)
                  if (oldSubscriber) {
                    await oldSubscriber.unsubscribe();
                    oldSubscriber.disconnect();
                    activeSubscriberCount--;
                    setGauge('redis_subscribers_active', activeSubscriberCount);
                  }

                  // Update subscribers map to new subscriber
                  subscribers.set(ws, newSubscriber);
                  subscriptionUpdated = true;

                  logger.info('Redis subscription updated after pairing', {
                    oldUserId: oldUserId.substring(0, 12) + '...',
                    newUserId: linkedUserId.substring(0, 12) + '...',
                    deviceId: sessionState.deviceId,
                  });

                  // Step 2: Update sessionState BEFORE session manager transfer
                  // This ensures the sessionState has the correct userId when added to the new user's sessions
                  sessionState.userId = linkedUserId;
                  // CRITICAL: Reset lastAckDeviceSeq to 0 to match DB state after pairing
                  // The DB was reset to 0 in completePairing, so in-memory state must match
                  // Otherwise client events will fail "Device sequence not monotonic" check
                  sessionState.lastAckDeviceSeq = 0;

                  // Step 3: Atomically transfer session from old user to new user
                  // This prevents a gap where the device isn't in any session list
                  sessionManager.transferSession(oldUserId, linkedUserId, sessionState.deviceId, sessionState, ws);
                  sessionManagerUpdated = true;

                  logger.info('Session manager updated after pairing', {
                    oldUserId: oldUserId.substring(0, 12) + '...',
                    newUserId: linkedUserId.substring(0, 12) + '...',
                    deviceId: sessionState.deviceId,
                  });

                  // All updates successful - send confirmation
                  safeSend(
                    ws,
                    JSON.stringify({
                      type: 'pairing_completed',
                      payload: {
                        success: true,
                        linkedUserId,
                      },
                    }),
                    { userId: linkedUserId, deviceId: sessionState.deviceId }
                  );

                  // Broadcast pairing notification to all other devices of the new user
                  try {
                    await deviceRelay.broadcastSystemMessage(
                      linkedUserId,
                      {
                        type: 'device_paired',
                        payload: {
                          type: 'device_paired',
                          device_id: sessionState.deviceId,
                          timestamp: Date.now(),
                        },
                      },
                      sessionState.deviceId
                    );
                  } catch (broadcastError) {
                    logger.warn('Failed to broadcast pairing notification', {
                      linkedUserId: linkedUserId.substring(0, 12) + '...',
                    }, broadcastError);
                  }

                  logger.info('Device paired successfully', {
                    linkedUserId: linkedUserId.substring(0, 12) + '...',
                    joiningDeviceId: sessionState.deviceId,
                  });
                } catch (updateError) {
                  // ROLLBACK: Revert all changes on failure
                  logger.error('Session update failed after pairing, rolling back', {
                    oldUserId: oldUserId.substring(0, 12) + '...',
                    linkedUserId: linkedUserId.substring(0, 12) + '...',
                    deviceId: sessionState.deviceId,
                    subscriptionUpdated,
                    sessionManagerUpdated,
                    sessionUserIdChanged: sessionState.userId !== oldUserId,
                  }, updateError);

                  // Rollback session manager if it was updated (transfer back to old user)
                  if (sessionManagerUpdated) {
                    try {
                      // Revert sessionState fields first
                      sessionState.userId = oldUserId;
                      sessionState.lastAckDeviceSeq = oldLastAckDeviceSeq;
                      // Transfer session back atomically
                      sessionManager.transferSession(linkedUserId, oldUserId, sessionState.deviceId, sessionState, ws);
                    } catch (rollbackError) {
                      logger.error('Failed to rollback session manager', {}, rollbackError);
                      // Still try to revert sessionState fields even if transfer failed
                      sessionState.userId = oldUserId;
                      sessionState.lastAckDeviceSeq = oldLastAckDeviceSeq;
                    }
                  } else if (sessionState.userId !== oldUserId) {
                    // sessionState fields were changed but transfer wasn't complete
                    sessionState.userId = oldUserId;
                    sessionState.lastAckDeviceSeq = oldLastAckDeviceSeq;
                  }

                  // Rollback subscription if it was updated
                  if (subscriptionUpdated) {
                    try {
                      const currentSubscriber = subscribers.get(ws);
                      if (currentSubscriber) {
                        await currentSubscriber.unsubscribe();
                        currentSubscriber.disconnect();
                        activeSubscriberCount--;
                      }
                      // Re-subscribe to old channel
                      const restoredSubscriber = await subscribeToDeviceChannel(
                        redis,
                        oldUserId,
                        sessionState.deviceId,
                        ws
                      );
                      subscribers.set(ws, restoredSubscriber);
                      activeSubscriberCount++;
                      setGauge('redis_subscribers_active', activeSubscriberCount);
                    } catch (rollbackError) {
                      logger.error('Failed to rollback Redis subscription', {}, rollbackError);
                    }
                  }

                  // Send failure message to client
                  safeSend(
                    ws,
                    JSON.stringify({
                      type: 'pairing_failed',
                      payload: {
                        error: 'Failed to update session state after pairing. Please try again.',
                      },
                    }),
                    { userId: sessionState.userId, deviceId: sessionState.deviceId }
                  );
                  return;
                }
              }
            } catch (error) {
              const errorMessage = error instanceof Error
                ? (error.message || 'Failed to complete pairing')
                : 'Failed to complete pairing';

              logger.error(`Pairing completion failed: ${errorMessage}`, {
                userId: sessionState.userId.substring(0, 12) + '...',
                deviceId: sessionState.deviceId,
                pairingCode,
                errorType: error instanceof Error ? error.constructor.name : typeof error,
                errorMessage,
              }, error);

              safeSend(
                ws,
                JSON.stringify({
                  type: 'pairing_failed',
                  payload: {
                    error: errorMessage,
                  },
                })
              );
            }
          } else {
            logger.warn('Unknown message type', { type: message.type, clientId });
          }
        }

        // Buffered message count is decremented in finally block (not here to avoid double decrement)
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        const isProduction = process.env.NODE_ENV === 'production';

        // Extract message context for better debugging
        let messageContext: Record<string, unknown> = {
          clientId,
          message: err.message,
          name: err.name,
          hasSessionState: !!sessionState,
          handshakeComplete,
          messageType: message?.type,
        };

        // Add stack trace (always log it, but don't expose to client)
        if (err.stack) {
          messageContext.stack = err.stack;
        }

        // Graceful handling: device record missing (deleted or moved). Close quietly to avoid log spam.
        if (err instanceof ValidationError && err.message === 'Device not found or has been deleted') {
          logger.warn('Closing session because device is missing', {
            clientId,
            deviceId: sessionState?.deviceId,
            userId: sessionState?.userId?.substring(0, 12) + '...',
          });
          ws.close(1008, err.message);
          return;
        }

        // Log error with full details (for debugging)
        const errorContext = {
          ...messageContext,
          errorType: err.constructor.name,
        };
        
        logger.error(errorContext, 'WebSocket message error');
        console.error('[ERROR] WebSocket message error:', {
          ...errorContext,
          fullError: error,
        });

        // Sanitize error message for client (don't expose internal details)
        let clientErrorMessage: string;
        if (err instanceof ValidationError) {
          // Validation errors are safe to expose (user input issues)
          clientErrorMessage = err.message;
        } else if (isProduction) {
          // In production, don't expose internal error details
          clientErrorMessage = 'An error occurred processing your message';
        } else {
          // In development, show error message for debugging
          clientErrorMessage = err.message || 'Internal error';
        }

        // Only close connection for critical errors
        // Some errors might be recoverable (e.g., invalid message format)
        const shouldClose = !(err instanceof ValidationError && err.message.includes('format'));
        
        if (shouldClose) {
          // Close connection with sanitized error message
          ws.close(1011, clientErrorMessage);
        } else {
          // Log warning but don't close - allow client to retry
          logger.warn('Non-critical WebSocket error, keeping connection open', errorContext);
        }
      } finally {
        // Always decrement buffered message count, even on error
        const currentBuffered = bufferedMessageCount.get(ws) || 0;
        if (currentBuffered > 0) {
          bufferedMessageCount.set(ws, currentBuffered - 1);
        }
      }
    });

    // Handle pong (response to ping)
    ws.on('pong', () => {
      if (sessionState) {
        lastPongTime.set(ws, Date.now());
        // Update lastSeen in session (for status API)
        sessionState.createdAt = Date.now(); // Using createdAt as lastSeen for now
        logger.debug('Received pong', { deviceId: sessionState.deviceId });
      }
    });

    // Handle connection close
    ws.on('close', async () => {
      // Cleanup handshake timeout
      const handshakeTimeout = handshakeTimeouts.get(ws);
      if (handshakeTimeout) {
        clearTimeout(handshakeTimeout);
        handshakeTimeouts.delete(ws);
      }

      // Cleanup heartbeat
      const heartbeatInterval = heartbeatIntervals.get(ws);
      if (heartbeatInterval) {
        clearInterval(heartbeatInterval);
        heartbeatIntervals.delete(ws);
      }
      lastPongTime.delete(ws);

      // Cleanup expiration warning flag
      expirationWarningsent.delete(ws);

      // Cleanup attached session state
      (ws as any)._sessionState = undefined;

      // Cleanup subscriber with timeout to prevent hanging
      const subscriber = subscribers.get(ws);
      if (subscriber) {
        let cleanupSuccess = false;
        try {
          // Add timeout wrapper to prevent hanging indefinitely
          await Promise.race([
            (async () => {
              // Unsubscribe from channel before quitting
              if (subscriber.unsubscribe && typeof subscriber.unsubscribe === 'function') {
                const channel = sessionState
                  ? `user:${sessionState.userId}:device:${sessionState.deviceId}`
                  : 'unknown';
                await subscriber.unsubscribe(channel);
                logger.debug('Unsubscribed from Redis channel', {
                  channel,
                  deviceId: sessionState?.deviceId,
                });
              }

              // Quit the subscriber connection
              if (subscriber.quit && typeof subscriber.quit === 'function') {
                await subscriber.quit();
              } else if (subscriber.disconnect && typeof subscriber.disconnect === 'function') {
                await subscriber.disconnect();
              }
              cleanupSuccess = true;
            })(),
            new Promise((_, reject) =>
              setTimeout(() => reject(new Error('Redis cleanup timeout')), 5000)
            ),
          ]);

          // Only decrement counter and remove from map if cleanup succeeded
          if (cleanupSuccess) {
            activeSubscriberCount = Math.max(0, activeSubscriberCount - 1);
            setGauge('redis_subscribers_active', activeSubscriberCount);
            subscribers.delete(ws);
            logger.debug('Redis subscriber cleaned up successfully', {
              deviceId: sessionState?.deviceId,
              activeSubscribers: activeSubscriberCount,
            });
          }
        } catch (error) {
          logger.error(
            'Failed to cleanup Redis subscriber',
            {
              deviceId: sessionState?.deviceId,
              cleanupSuccess,
            },
            error instanceof Error ? error : new Error(String(error))
          );
          incrementCounter('redis_subscriber_cleanup_errors_total');

          // Force remove from subscribers map even on error to prevent memory leak
          // But don't decrement counter since cleanup failed
          subscribers.delete(ws);
        }
      }

      // Cleanup heartbeat interval if still active
      const heartbeatTimeoutCheck = heartbeatIntervals.get(ws);
      if (heartbeatTimeoutCheck) {
        clearInterval(heartbeatTimeoutCheck);
        heartbeatIntervals.delete(ws);
      }

      if (sessionState) {
        // Track disconnection metrics
        incrementCounter('websocket_connections_total', { status: 'disconnected' });
        setGauge('websocket_connections_active', wss.clients.size);

        // Untrack device for per-user rate limiting
        untrackUserDevice(sessionState.userId, sessionState.deviceId);

        sessionManager.removeSession(sessionState.userId, sessionState.deviceId);
        setGauge('users_active', sessionManager.getAllUsers().length);
        setGauge('devices_active', sessionManager.getTotalSessions());

        try {
          await deleteSession(redis, sessionState.deviceId);
        } catch (error) {
          logger.error(
            'Failed to delete session from Redis',
            {},
            error instanceof Error ? error : new Error(String(error))
          );
        }
        decrementConnection(sessionState.userId, sessionState.deviceId);
        try {
          await updatePresence(redis, sessionState.deviceId, false);
        } catch (error) {
          logger.error(
            'Failed to update presence on disconnect',
            {
              deviceId: sessionState.deviceId,
            },
            error instanceof Error ? error : new Error(String(error))
          );
        }

        // Update device offline status in database (single update, no duplicate)
        try {
          await db.pool.query(
            `UPDATE user_devices
               SET is_online = FALSE, last_seen = NOW()
               WHERE device_id = $1::uuid`,
            [sessionState.deviceId]
          );
          logger.debug('Device marked as offline', { deviceId: sessionState.deviceId });
        } catch (error) {
          logger.warn(
            'Failed to update offline status in DB',
            {
              userId: sessionState.userId.substring(0, 16) + '...',
              deviceId: sessionState.deviceId,
            },
            error instanceof Error ? error : new Error(String(error))
          );
        }

        // Broadcast device offline to other devices (presence update)
        try {
          await presenceBroadcaster.publishDeviceOffline(
            sessionState.userId,
            sessionState.deviceId
          );
          await presenceBroadcaster.cacheDeviceStatus(
            sessionState.userId,
            sessionState.deviceId,
            false
          );
          await deviceRelay.broadcastSystemMessage(
            sessionState.userId,
            {
              type: 'device_status_changed',
              payload: {
                type: 'device_status_changed',
                user_id: sessionState.userId,
                device_id: sessionState.deviceId,
                is_online: false,
                timestamp: Date.now(),
              },
            },
            sessionState.deviceId
          );
        } catch (error) {
          logger.warn(
            'Failed to publish device offline presence',
            {
              userId: sessionState.userId.substring(0, 16) + '...',
              deviceId: sessionState.deviceId,
            },
            error instanceof Error ? error : new Error(String(error))
          );
        }

        logger.info('Session closed', { deviceId: sessionState.deviceId });
      }

      // Update status to disconnected
      connectionStatuses.set(ws, 'disconnected');
    });

    // Handle errors
    ws.on('error', error => {
      logger.error(
        'WebSocket error',
        { clientId },
        error instanceof Error ? error : new Error(String(error))
      );
    });
  });

  /**
   * Start heartbeat for a WebSocket connection
   * Sends ping every 30 seconds, closes connection if no pong within 60 seconds
   */
  function startHeartbeat(ws: WebSocket, sessionState: SessionState): void {
    const HEARTBEAT_INTERVAL = 30000; // 30 seconds
    const PONG_TIMEOUT = 60000; // 60 seconds

    // Record initial pong time (connection just established)
    lastPongTime.set(ws, Date.now());

    // Send ping every 30 seconds
    const interval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.ping();
          logger.debug('Sent ping', { deviceId: sessionState.deviceId });

          // Check if we received pong within timeout
          const lastPong = lastPongTime.get(ws);
          if (lastPong && Date.now() - lastPong > PONG_TIMEOUT) {
            logger.warn('No pong received within timeout, closing connection', {
              deviceId: sessionState.deviceId,
              lastPong,
              timeout: PONG_TIMEOUT,
            });
            ws.close(1008, 'Heartbeat timeout');
            clearInterval(interval);
            heartbeatIntervals.delete(ws);
          }
        } catch (error) {
          logger.error(
            'Failed to send ping',
            { deviceId: sessionState.deviceId },
            error instanceof Error ? error : new Error(String(error))
          );
          clearInterval(interval);
          heartbeatIntervals.delete(ws);
        }
      } else {
        // Connection is not open, stop heartbeat
        clearInterval(interval);
        heartbeatIntervals.delete(ws);
      }
    }, HEARTBEAT_INTERVAL);

    heartbeatIntervals.set(ws, interval);
    logger.debug('Heartbeat started', {
      deviceId: sessionState.deviceId,
      interval: HEARTBEAT_INTERVAL,
    });
  }

  // Return sessions Map for status API access, along with cleanup function
  const sessionsMap = sessionManager.getAllSessionsFlat();
  
  // Attach cleanup function to returned object (stored as a property for graceful shutdown)
  (sessionsMap as any)._cleanup = () => {
    clearInterval(sessionTimeoutInterval);
    logger.debug('Session timeout interval cleared');

    // Also clear all active handshake timeouts
    handshakeTimeouts.forEach((timeout: NodeJS.Timeout) => {
      clearTimeout(timeout);
    });

    // Clear all active heartbeat intervals
    heartbeatIntervals.forEach((interval: NodeJS.Timeout) => {
      clearInterval(interval);
    });
  };

  // Attach function to notify a device it has been revoked
  // This sends a message to the device before closing the connection,
  // allowing the device to restore its original identity
  (sessionsMap as any)._notifyDeviceRevoked = (userId: string, deviceId: string, reason?: string): boolean => {
    const ws = sessionManager.getWebSocket(userId, deviceId);
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      logger.debug('Device not online, cannot send revocation notice', { deviceId, userId: userId.substring(0, 16) + '...' });
      return false;
    }

    try {
      // Send device_revoked message to the device
      const sent = safeSend(
        ws,
        JSON.stringify({
          type: 'device_revoked',
          payload: {
            type: 'device_revoked',
            reason: reason || 'Device has been removed',
            timestamp: Date.now(),
          },
        }),
        { userId, deviceId }
      );

      if (sent) {
        logger.info('Sent device_revoked notification', {
          deviceId,
          userId: userId.substring(0, 16) + '...',
          reason: reason || 'Device has been removed',
        });
      }

      // Close the connection after a short delay to allow message delivery
      setTimeout(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.close(1000, 'Device revoked');
        }
      }, 500);

      return true;
    } catch (error) {
      logger.error('Failed to send device_revoked notification', {
        deviceId,
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  };

  return sessionsMap;
}

/**
 * Subscribe to Redis channel for device events
 */
async function subscribeToDeviceChannel(
  redis: RedisConnection,
  userId: string,
  deviceId: string,
  ws: WebSocket
): Promise<any> {
  // Subscribe to USER BROADCAST channel (Apple-like ecosystem)
  // ALL devices of the same user share this channel for seamless sync
  const channel = `user:${userId}:broadcast`;

  // Subscribe to Redis Pub/Sub
  const subscriber = redis.client.duplicate();

  // Connect subscriber if connect method exists (Redis v4+)
  if (subscriber.connect && typeof subscriber.connect === 'function') {
    await subscriber.connect();
  }

  await subscriber.subscribe(channel, (message: string) => {
    try {
      const event = JSON.parse(message);
      // Skip events sent by this device — the direct relay in event-handler.ts
      // already delivered to other devices. Without this check, the sender
      // receives its own events back via Redis pub/sub.
      if (event.device_id === deviceId) {
        return;
      }
      safeSend(
        ws,
        JSON.stringify({ type: 'event', payload: event }),
        { userId, deviceId }
      );
    } catch (error) {
      logger.error(
        'Failed to forward event from Redis',
        { channel },
        error instanceof Error ? error : new Error(String(error))
      );
    }
  });

  return subscriber;
}

/**
 * Update device presence
 */
async function updatePresence(redis: RedisConnection, deviceId: string, isOnline: boolean): Promise<void> {
  if (!redis) {
    return; // Skip if Redis not available
  }

  const key = `presence:${deviceId}`;
  try {
    if (isOnline) {
      await redis.client.setEx(key, 300, 'online'); // 5 minute TTL
    } else {
      await redis.client.del(key);
    }
  } catch (error) {
    // Log but don't throw - presence is not critical
    logger.debug(
      'Failed to update presence in Redis',
      {
        deviceId,
        isOnline,
      },
      error instanceof Error ? error : new Error(String(error))
    );
  }
}

/**
 * Create HMAC-signed continuation token
 * Token is bound to device_id to prevent cross-device token reuse
 */
function createContinuationToken(
  data: number | { created_at: number; event_id: string },
  deviceId: string
): string {
  // Support both old format (deviceSeq as number) and new format (object with created_at and event_id)
  const tokenData = typeof data === 'number'
    ? { device_seq: data, device_id: deviceId, timestamp: Date.now() }
    : { created_at: data.created_at, event_id: data.event_id, device_id: deviceId, timestamp: Date.now() };

  const payload = JSON.stringify(tokenData);

  // Sign with server private key (or use a dedicated secret from config)
  const secret = config.serverIdentity?.privateKeyHex || 'default-continuation-token-secret';
  const signature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  // Token format: base64(payload).signature
  const payloadBase64 = Buffer.from(payload).toString('base64');
  return `${payloadBase64}.${signature}`;
}

/**
 * Verify and parse HMAC-signed continuation token
 * Returns null if token is invalid, tampered, or for a different device
 * Supports both old format (device_seq) and new format (created_at, event_id)
 */
function parseContinuationToken(
  token: string,
  deviceId: string
): { device_seq?: number; created_at?: number; event_id?: string; timestamp?: number } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) {
      return null;
    }

    const [payloadBase64, providedSignature] = parts;
    const payload = Buffer.from(payloadBase64, 'base64').toString('utf8');

    // Verify signature
    const secret = config.serverIdentity?.privateKeyHex || 'default-continuation-token-secret';
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex');

    // Use timing-safe comparison to prevent timing attacks
    if (!crypto.timingSafeEqual(
      Buffer.from(providedSignature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    )) {
      return null;
    }

    const parsed = JSON.parse(payload);

    // Verify token is for this device (prevents cross-device token reuse)
    if (parsed.device_id !== deviceId) {
      return null;
    }

    // Verify required fields
    if (typeof parsed.device_seq !== 'number' || typeof parsed.timestamp !== 'number') {
      return null;
    }

    // Optional: Reject tokens older than 1 hour (prevents token replay attacks)
    const tokenAge = Date.now() - parsed.timestamp;
    const maxTokenAge = 60 * 60 * 1000; // 1 hour
    if (tokenAge > maxTokenAge) {
      return null;
    }

    return {
      device_seq: parsed.device_seq,
      timestamp: parsed.timestamp,
    };
  } catch {
    return null;
  }
}

/**
 * Handle replay request with window enforcement and size limits
 */
async function handleReplayRequest(
  request: ReplayRequest,
  sessionState: SessionState,
  db: Database,
  ws: WebSocket
): Promise<void> {
  // Prevent concurrent replay requests to avoid duplicate deliveries
  if (inFlightReplayRequests.get(ws)) {
    logger.warn('Rejecting concurrent replay request', {
      deviceId: sessionState.deviceId,
      userId: sessionState.userId.substring(0, 16) + '...',
    });
    safeSend(
      ws,
      JSON.stringify({
        type: 'replay_failed',
        payload: {
          error: 'Concurrent replay request rejected. Please wait for current replay to complete.',
        },
      }),
      { userId: sessionState.userId, deviceId: sessionState.deviceId }
    );
    return;
  }

  // Mark replay as in-flight
  inFlightReplayRequests.set(ws, true);

  try {
    const { last_ack_device_seq, limit: requestedLimit, continuation_token } = request;

  // Get device's last received event timestamp for global event tracking
  const deviceResult = await db.pool.query(
    `SELECT last_received_created_at FROM user_devices WHERE device_id = $1::uuid`,
    [sessionState.deviceId]
  );
  const lastReceivedAt = deviceResult.rows[0]?.last_received_created_at || new Date(0);

  // Parse continuation token if provided (contains the created_at to continue from)
  let startCreatedAt = lastReceivedAt;
  let startEventId = '';
  if (continuation_token) {
    const tokenData = parseContinuationToken(continuation_token, sessionState.deviceId);
    if (tokenData) {
      // Token contains: { created_at, event_id }
      startCreatedAt = new Date(tokenData.created_at);
      startEventId = tokenData.event_id;
    } else {
      logger.warn('Invalid or tampered continuation token, using lastReceivedAt', {
        deviceId: sessionState.deviceId,
      });
      startCreatedAt = lastReceivedAt;
    }
  }

  // Validate and set page limit (default: 100, max: 1000)
  const pageLimit = Math.min(
    Math.max(requestedLimit || 100, 1), // Default to 100, minimum 1
    1000 // Maximum 1000 per page
  );

  // Enforce replay window
  const replayWindowMs = config.websocket.replayWindowDays * 24 * 60 * 60 * 1000;
  const cutoffTime = new Date(Date.now() - replayWindowMs);

  // Count total events only on first page (when no continuation token)
  let totalEvents: number | undefined;
  if (!continuation_token) {
    const countResult = await db.pool.query(
      `SELECT COUNT(*) as total FROM events
       WHERE user_id = $1
       AND created_at > $2
       AND created_at > $3`,
      [sessionState.userId, startCreatedAt, cutoffTime]
    );

    totalEvents = parseInt(countResult.rows[0].total, 10);

    // Check if replay exceeds safe threshold (10,000 events or 30 days)
    const maxReplayEvents = 10000;
    const maxReplayAge = 30 * 24 * 60 * 60 * 1000; // 30 days
    const ageMs = Date.now() - sessionState.createdAt;

    if (totalEvents > maxReplayEvents || ageMs > maxReplayAge) {
      // Too many events or too old - request full resync
      logger.warn('Replay exceeds safe limits, requesting full resync', {
        deviceId: sessionState.deviceId,
        totalEvents,
        maxReplayEvents,
        ageMs,
        maxReplayAge,
      });

      safeSend(
        ws,
        JSON.stringify({
          type: 'full_resync_required',
          payload: {
            type: 'full_resync_required',
            reason: totalEvents > maxReplayEvents ? 'too_many_events' : 'session_too_old',
            event_count: totalEvents,
            last_ack_device_seq,
            recommendation: 'Clear local state and re-sync from scratch',
          },
        }),
        { userId: sessionState.userId, deviceId: sessionState.deviceId }
      );
      return;
    }
  }

  // Query events with pagination (request one extra to check if there are more)
  // Use >= for created_at to include events with same timestamp, and event_id as tiebreaker
  const queryLimit = pageLimit + 1;

  // Build parameterized query for proper pagination that handles same-timestamp events
  let query: string;
  let params: any[];

  // If continuing from a previous page, use >= with event_id tiebreaker
  if (continuation_token && startEventId) {
    query = `SELECT * FROM events
             WHERE user_id = $1
             AND (created_at > $2 OR (created_at = $2 AND event_id > $4))
             AND created_at > $3
             ORDER BY created_at ASC, event_id ASC
             LIMIT $5`;
    params = [sessionState.userId, startCreatedAt, cutoffTime, startEventId, queryLimit];
  } else {
    query = `SELECT * FROM events
             WHERE user_id = $1
             AND created_at > $2
             AND created_at > $3
             ORDER BY created_at ASC, event_id ASC
             LIMIT $4`;
    params = [sessionState.userId, startCreatedAt, cutoffTime, queryLimit];
  }

  const result = await db.pool.query(query, params);

  // Check if there are more events
  const hasMore = result.rows.length > pageLimit;
  const eventsToReturn = hasMore ? result.rows.slice(0, pageLimit) : result.rows;

  const events = eventsToReturn.map(row => ({
    event_id: row.event_id,
    user_id: row.user_id,
    device_id: row.device_id,
    device_seq: parseInt(row.device_seq, 10),
    stream_id: row.stream_id,
    stream_seq: parseInt(row.stream_seq, 10),
    type: row.type,
    encrypted_payload: row.encrypted_payload,
    ttl: row.ttl ? new Date(row.ttl).getTime() : undefined,
    created_at: new Date(row.created_at).getTime(),
  }));

  // Generate HMAC-signed continuation token if there are more events
  let continuationToken: string | undefined;
  if (hasMore && events.length > 0) {
    const lastEvent = events[events.length - 1];
    // Use signed token to prevent tampering and cross-device reuse
    // Token now contains: { created_at, event_id } for global ordering
    continuationToken = createContinuationToken(
      { created_at: lastEvent.created_at, event_id: lastEvent.event_id },
      sessionState.deviceId
    );
  }

  // Update device's last received event for global tracking
  const maxCreatedAt = events.length > 0 ? new Date(events[events.length - 1].created_at) : startCreatedAt;
  const lastEventId = events.length > 0 ? events[events.length - 1].event_id : '';
  if (events.length > 0) {
    await db.pool.query(
      `UPDATE user_devices
       SET last_received_created_at = $1, last_received_event_id = $2
       WHERE device_id = $3::uuid`,
      [maxCreatedAt, lastEventId, sessionState.deviceId]
    );
  }

  // Edge case: No events to replay
  if (events.length === 0) {
    logger.debug('Replay request returned no events (empty state)', {
      deviceId: sessionState.deviceId,
      userId: sessionState.userId.substring(0, 16) + '...',
      last_ack_device_seq: startDeviceSeq,
    });

    const emptyResponse: ReplayResponse = {
      type: 'replay_response',
      events: [],
      has_more: false,
      page_size: 0,
      ...(totalEvents !== undefined && { total_events: totalEvents }),
    };
    // Send wrapped in WSMessage format for consistency
    safeSend(
      ws,
      JSON.stringify({
        type: 'replay_response',
        payload: emptyResponse,
      }),
      { userId: sessionState.userId, deviceId: sessionState.deviceId }
    );
    return;
  }

  logger.info('Replay response (paginated)', {
    deviceId: sessionState.deviceId,
    eventCount: events.length,
    hasMore,
    pageLimit,
    totalEvents,
  });

  // Send paginated replay response
  const response: ReplayResponse = {
    type: 'replay_response',
    events,
    has_more: hasMore,
    page_size: events.length,
    ...(continuationToken && { continuation_token: continuationToken }),
    ...(totalEvents !== undefined && { total_events: totalEvents }),
  };

  // Send wrapped in WSMessage format for consistency
  safeSend(
    ws,
    JSON.stringify({
      type: 'replay_response',
      payload: response,
    }),
    { userId: sessionState.userId, deviceId: sessionState.deviceId }
  );
  } finally {
    // Always clear in-flight flag, even if replay fails
    inFlightReplayRequests.delete(ws);
  }
}

/**
 * Handle acknowledgment
 *
 * NOTE: ACKs are sent by clients when they RECEIVE events from other devices.
 * The device_seq in the ACK is the SENDER's device_seq, not the ACK sender's.
 *
 * IMPORTANT: We do NOT update last_ack_device_seq based on ACKs because:
 * 1. The device_seq in ACKs is from a different device (the event sender)
 * 2. last_ack_device_seq tracks THIS device's sent event sequence
 * 3. Mixing these values causes "Device sequence not monotonic" errors
 *
 * Instead, last_ack_device_seq is updated in handleEvent when events are sent.
 */
async function handleAck(
  ack: { device_seq: number },
  sessionState: SessionState,
  db: Database
): Promise<void> {
  // ACKs are informational only - they tell us the client received an event
  // We log this for debugging but do NOT update last_ack_device_seq
  // because the device_seq in the ACK is from the event sender, not this device
  logger.debug('Received ACK for event', {
    deviceId: sessionState.deviceId,
    ackDeviceSeq: ack.device_seq,
    sessionLastAckDeviceSeq: sessionState.lastAckDeviceSeq,
    note: 'ACK device_seq is from event sender, not updating this device\'s last_ack_device_seq',
  });

  // Update last_seen timestamp only (not last_ack_device_seq)
  await db.pool.query(
    `UPDATE user_devices SET last_seen = NOW() WHERE device_id = $1::uuid`,
    [sessionState.deviceId]
  );
}
