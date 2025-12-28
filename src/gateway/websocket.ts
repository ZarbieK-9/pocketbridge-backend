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
} from '../middleware/rate-limit.js';
import {
  checkConnectionLimit,
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
import type { ServerIdentityKeypair } from '../crypto/utils.js';

interface GatewayDependencies {
  db: Database;
  redis: RedisConnection;
  serverIdentity?: ServerIdentityKeypair;
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
  const handshakeTimeouts = new WeakMap<WebSocket, NodeJS.Timeout>();

  // Store heartbeat intervals
  const heartbeatIntervals = new WeakMap<WebSocket, NodeJS.Timeout>();

  // Store last pong time per connection
  const lastPongTime = new WeakMap<WebSocket, number>();

  // Store connection status per WebSocket
  const connectionStatuses = new WeakMap<WebSocket, ConnectionStatus>();

  // Track which sessions have received expiration warning (avoid spamming)
  const expirationWarningsent = new WeakMap<WebSocket, boolean>();

  // Track buffered message count per WebSocket (for overflow protection)
  const bufferedMessageCount = new WeakMap<WebSocket, number>();
  const MAX_BUFFERED_MESSAGES = 100; // Maximum messages to buffer before closing connection

  // Enforce session timeouts periodically
  setInterval(() => {
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
          try {
            ws.send(
              JSON.stringify({
                type: 'session_expiring_soon',
                payload: {
                  type: 'session_expiring_soon',
                  expires_in_seconds: Math.ceil(remainingMs / 1000),
                  expires_at: now + remainingMs,
                },
              })
            );
            expirationWarningsent.set(ws, true);
            logger.info('Session expiration warning sent', {
              deviceId: sessionState.deviceId,
              expiresInSeconds: Math.ceil(remainingMs / 1000),
            });
          } catch (error) {
            logger.warn(
              'Failed to send session expiration warning',
              {
                deviceId: sessionState.deviceId,
              },
              error instanceof Error ? error : new Error(String(error))
            );
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

    // Set handshake timeout (30 seconds)
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
        logger.warn('Handshake timeout', { clientId, readyState: ws.readyState });
        if (ws.readyState === WebSocket.OPEN) {
          ws.close(1008, 'Handshake timeout');
        }
      }
    }, 30000);
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
        if (data.length > 10 * 1024 * 1024) {
          // 10MB
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

              // Check connection limits
              const connectionLimit = checkConnectionLimit(
                newSessionState.userId,
                newSessionState.deviceId
              );
              if (!connectionLimit.allowed) {
                auditLog(AuditEventType.CONNECTION_LIMIT_EXCEEDED, {
                  userId: newSessionState.userId,
                  deviceId: newSessionState.deviceId,
                });
                logger.warn('Connection limit exceeded', {
                  userId: newSessionState.userId.substring(0, 16) + '...',
                  deviceId: newSessionState.deviceId,
                });
                ws.close(1008, connectionLimit.error);
                return;
              }

              // Check per-user concurrent device limit (max 5 devices)
              const deviceLimit = checkConcurrentDeviceLimit(newSessionState.userId, 5);
              if (!deviceLimit.allowed) {
                auditLog(AuditEventType.CONNECTION_LIMIT_EXCEEDED, {
                  userId: newSessionState.userId,
                  deviceId: newSessionState.deviceId,
                  details: { reason: 'too_many_devices' },
                });
                logger.warn('Per-user device limit exceeded', {
                  userId: newSessionState.userId.substring(0, 16) + '...',
                  deviceId: newSessionState.deviceId,
                });
                ws.close(1008, deviceLimit.error);
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

              sessionManager.addSession(
                newSessionState.userId,
                newSessionState.deviceId,
                newSessionState,
                ws
              );

              // Track device for per-user rate limiting
              trackUserDevice(newSessionState.userId, newSessionState.deviceId);

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

              // Increment connection count
              incrementConnection(newSessionState.userId, newSessionState.deviceId);

              // Subscribe to Redis channel for this device
              try {
                const subscriber = await subscribeToDeviceChannel(
                  redis.client,
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
                await updatePresence(redis.client, newSessionState.deviceId, true);
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
          } else if (message.type === 'replay_request') {
            await handleReplayRequest(message as ReplayRequest, sessionState, db, ws);
          } else if (message.type === 'ack') {
            await handleAck(message.payload, sessionState, db);
            // Update session in Redis
            await updateSession(redis, sessionState);
          } else {
            logger.warn('Unknown message type', { type: message.type, clientId });
          }
        }

        // Decrement buffered message count after processing
        const bufferedAfter = bufferedMessageCount.get(ws) || 0;
        if (bufferedAfter > 0) {
          bufferedMessageCount.set(ws, bufferedAfter - 1);
        }
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

      // Cleanup subscriber
      const subscriber = subscribers.get(ws);
      if (subscriber) {
        try {
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

          activeSubscriberCount = Math.max(0, activeSubscriberCount - 1);
          setGauge('redis_subscribers_active', activeSubscriberCount);
          logger.debug('Redis subscriber cleaned up', {
            deviceId: sessionState?.deviceId,
            activeSubscribers: activeSubscriberCount,
          });
        } catch (error) {
          logger.error(
            'Failed to cleanup Redis subscriber',
            {
              deviceId: sessionState?.deviceId,
            },
            error instanceof Error ? error : new Error(String(error))
          );
          incrementCounter('redis_subscriber_cleanup_errors_total');
        }
        subscribers.delete(ws);
      }

      // Cleanup handshake timeout
      const timeout = handshakeTimeouts.get(ws);
      if (timeout) {
        clearTimeout(timeout);
        handshakeTimeouts.delete(ws);
      }

      if (sessionState) {
        // Update device offline status in database
        try {
          await db.pool.query(
            'UPDATE user_devices SET is_online = FALSE, last_seen = NOW() WHERE device_id = $1::uuid',
            [sessionState.deviceId]
          );
          logger.debug('Device marked as offline', { deviceId: sessionState.deviceId });
        } catch (error) {
          logger.error(
            'Failed to update device offline status',
            { deviceId: sessionState.deviceId },
            error instanceof Error ? error : new Error(String(error))
          );
        }

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
          await updatePresence(redis.client, sessionState.deviceId, false);
        } catch (error) {
          logger.error(
            'Failed to update presence on disconnect',
            {
              deviceId: sessionState.deviceId,
            },
            error instanceof Error ? error : new Error(String(error))
          );
        }

        // Persist offline status in DB (eventual consistency)
        try {
          await db.pool.query(
            `UPDATE user_devices
               SET is_online = FALSE, last_seen = NOW()
               WHERE device_id = $1::uuid`,
            [sessionState.deviceId]
          );
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

  // Return sessions Map for status API access
  return sessionManager.getAllSessionsFlat();
}

/**
 * Subscribe to Redis channel for device events
 */
async function subscribeToDeviceChannel(
  redis: any,
  userId: string,
  deviceId: string,
  ws: WebSocket
): Promise<any> {
  const channel = `user:${userId}:device:${deviceId}`;

  // Subscribe to Redis Pub/Sub
  const subscriber = redis.duplicate();

  // Connect subscriber if connect method exists (Redis v4+)
  if (subscriber.connect && typeof subscriber.connect === 'function') {
    await subscriber.connect();
  }

  await subscriber.subscribe(channel, (message: string) => {
    try {
      if (ws.readyState === WebSocket.OPEN) {
        const event = JSON.parse(message);
        ws.send(JSON.stringify({ type: 'event', payload: event }));
      }
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
async function updatePresence(redis: any, deviceId: string, isOnline: boolean): Promise<void> {
  if (!redis) {
    return; // Skip if Redis not available
  }

  const key = `presence:${deviceId}`;
  try {
    if (isOnline) {
      if (redis.setEx && typeof redis.setEx === 'function') {
        await redis.setEx(key, 300, 'online'); // 5 minute TTL
      } else if (redis.set && typeof redis.set === 'function') {
        // Fallback for older Redis clients
        await redis.set(key, 'online', 'EX', 300);
      }
    } else {
      if (redis.del && typeof redis.del === 'function') {
        await redis.del(key);
      } else if (redis.delete && typeof redis.delete === 'function') {
        // Fallback for some Redis clients
        await redis.delete(key);
      }
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
 * Handle replay request with window enforcement and size limits
 */
async function handleReplayRequest(
  request: ReplayRequest,
  sessionState: SessionState,
  db: Database,
  ws: WebSocket
): Promise<void> {
  const { last_ack_device_seq, limit: requestedLimit, continuation_token } = request;

  // Parse continuation token if provided (contains the device_seq to continue from)
  let startDeviceSeq = last_ack_device_seq;
  if (continuation_token) {
    try {
      const decoded = Buffer.from(continuation_token, 'base64').toString('utf8');
      const parsed = JSON.parse(decoded);
      if (parsed.device_seq && typeof parsed.device_seq === 'number') {
        startDeviceSeq = parsed.device_seq;
      } else {
        throw new Error('Invalid continuation token format');
      }
    } catch (error) {
      logger.warn('Invalid continuation token, using last_ack_device_seq', {
        deviceId: sessionState.deviceId,
        error: error instanceof Error ? error.message : String(error),
      });
      startDeviceSeq = last_ack_device_seq;
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
       WHERE device_id = $1 
       AND device_seq > $2 
       AND created_at > $3`,
      [sessionState.deviceId, last_ack_device_seq, cutoffTime]
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

      ws.send(
        JSON.stringify({
          type: 'full_resync_required',
          payload: {
            type: 'full_resync_required',
            reason: totalEvents > maxReplayEvents ? 'too_many_events' : 'session_too_old',
            event_count: totalEvents,
            last_ack_device_seq,
            recommendation: 'Clear local state and re-sync from scratch',
          },
        })
      );
      return;
    }
  }

  // Query events with pagination (request one extra to check if there are more)
  const queryLimit = pageLimit + 1;
  const result = await db.pool.query(
    `SELECT * FROM events 
     WHERE device_id = $1 
     AND device_seq > $2 
     AND created_at > $3
     ORDER BY device_seq ASC
     LIMIT $4`,
    [sessionState.deviceId, startDeviceSeq, cutoffTime, queryLimit]
  );

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

  // Generate continuation token if there are more events
  let continuationToken: string | undefined;
  if (hasMore && events.length > 0) {
    // Token contains the device_seq of the last event returned
    const lastEvent = events[events.length - 1];
    const tokenData = {
      device_seq: lastEvent.device_seq,
      timestamp: Date.now(),
    };
    continuationToken = Buffer.from(JSON.stringify(tokenData)).toString('base64');
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
    ws.send(JSON.stringify(emptyResponse));
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

  ws.send(JSON.stringify(response));
}

/**
 * Handle acknowledgment
 */
async function handleAck(
  ack: { device_seq: number },
  sessionState: SessionState,
  db: Database
): Promise<void> {
  // Update last_ack_device_seq
  await db.pool.query(
    `UPDATE user_devices 
     SET last_ack_device_seq = $1, last_seen = NOW()
     WHERE device_id = $2::uuid`,
    [ack.device_seq, sessionState.deviceId]
  );

  sessionState.lastAckDeviceSeq = ack.device_seq;
}
