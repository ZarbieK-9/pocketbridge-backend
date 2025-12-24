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
import { rateLimitConnection, rateLimitHandshake, getClientIdentifier, trackUserDevice, untrackUserDevice, checkConcurrentDeviceLimit } from '../middleware/rate-limit.js';
import { checkConnectionLimit, incrementConnection, decrementConnection } from '../middleware/connection-limits.js';
import { auditLog, AuditEventType } from '../utils/audit-log.js';
import { storeSession, deleteSession, updateSession } from '../services/session-store.js';
import { shouldRotateKeys } from '../services/session-rotation.js';
import MultiDeviceSessionManager from '../services/multi-device-sessions.js';
import PresenceBroadcaster from '../services/presence-broadcaster.js';
import type { SessionState, ReplayRequest } from '../types/index.js';
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
  
  // Create presence broadcaster for Redis pub/sub
  const presenceBroadcaster = new PresenceBroadcaster(redis.client);
  
  // Store Redis subscribers per connection (for cleanup)
  const subscribers = new WeakMap<WebSocket, any>();
  
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
            ws.send(JSON.stringify({
              type: 'session_expiring_soon',
              payload: {
                type: 'session_expiring_soon',
                expires_in_seconds: Math.ceil(remainingMs / 1000),
                expires_at: now + remainingMs,
              },
            }));
            expirationWarningsent.set(ws, true);
            logger.info('Session expiration warning sent', {
              deviceId: sessionState.deviceId,
              expiresInSeconds: Math.ceil(remainingMs / 1000),
            });
          } catch (error) {
            logger.warn('Failed to send session expiration warning', {
              deviceId: sessionState.deviceId,
            }, error instanceof Error ? error : new Error(String(error)));
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
    logger.info('New WebSocket connection', { clientId });
    
    // Set initial status to connecting
    connectionStatuses.set(ws, 'connecting');

    // Rate limit connection (enabled with higher limits for production)
    const connectionLimit = rateLimitConnection(clientId);
    if (!connectionLimit.allowed) {
      auditLog(AuditEventType.RATE_LIMIT_HIT, { clientId, details: { type: 'connection' } });
      logger.warn('Connection rate limited', { clientId });
      ws.close(1008, connectionLimit.error);
      return;
    }

    let sessionState: SessionState | null = null;
    let handshakeComplete = false;

    // Set handshake timeout (30 seconds)
    const handshakeTimeout = setTimeout(() => {
      // Double-check handshakeComplete and sessionState to avoid race condition
      const currentTimeout = handshakeTimeouts.get(ws);
      if (currentTimeout === handshakeTimeout && !handshakeComplete && !sessionState) {
        auditLog(AuditEventType.HANDSHAKE_TIMEOUT, { clientId });
        logger.warn('Handshake timeout', { clientId });
        ws.close(1008, 'Handshake timeout');
      }
    }, 30000);
    handshakeTimeouts.set(ws, handshakeTimeout);

    // Handle incoming messages
    ws.on('message', async (data: Buffer) => {
      try {
        // Validate message size (prevent DoS)
        if (data.length > 10 * 1024 * 1024) { // 10MB
          throw new Error('Message too large');
        }

        const message = JSON.parse(data.toString('utf8'));

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
          
          const result = await handleHandshake(
            handshakeMessage,
            ws,
            db,
            serverIdentity
          );
          
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
              const timeout = handshakeTimeouts.get(ws);
              if (timeout) {
                clearTimeout(timeout);
                handshakeTimeouts.delete(ws);
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
              
              sessionManager.addSession(newSessionState.userId, newSessionState.deviceId, newSessionState, ws);
              
              // Track device for per-user rate limiting
              trackUserDevice(newSessionState.userId, newSessionState.deviceId);
              
              // Update status to connected
              connectionStatuses.set(ws, 'connected');
              
              // Store session in Redis for horizontal scaling
              await storeSession(redis, newSessionState);
              
              // Increment connection count
              incrementConnection(newSessionState.userId, newSessionState.deviceId);
              
              // Subscribe to Redis channel for this device
              const subscriber = await subscribeToDeviceChannel(
                redis.client,
                newSessionState.userId,
                newSessionState.deviceId,
                ws
              );
              subscribers.set(ws, subscriber);

              // Update presence
              await updatePresence(redis.client, newSessionState.deviceId, true);
              
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
                  await presenceBroadcaster.cacheDeviceStatus(newSessionState.userId, newSessionState.deviceId, true);
                }
              } catch (error) {
                logger.warn('Failed to publish device online presence', {
                  userId: newSessionState.userId.substring(0, 16) + '...',
                  deviceId: newSessionState.deviceId,
                }, error instanceof Error ? error : new Error(String(error)));
              }
              
              // Start heartbeat (ping every 30 seconds)
              startHeartbeat(ws, sessionState);
              
              auditLog(AuditEventType.AUTHENTICATION_SUCCESS, {
                userId: newSessionState.userId,
                deviceId: newSessionState.deviceId,
              });
              logger.info('Session established', { 
                deviceId: newSessionState.deviceId, 
                userId: newSessionState.userId.substring(0, 16) + '...' 
              });
            } else {
              // Client hello succeeded, waiting for client_auth
              logger.debug('Client hello processed, waiting for client_auth');
            }
          } else {
            auditLog(AuditEventType.AUTHENTICATION_FAILURE, {
              clientId,
              details: { error: result.error },
            });
            logger.warn('Handshake failed', { 
              clientId, 
              error: result.error 
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

          if (message.type === 'event') {
            await handleEvent(message.payload, sessionState, db, redis);
            
            // Check if keys should be rotated
            if (shouldRotateKeys(sessionState)) {
              logger.info('Session keys should be rotated', { deviceId: sessionState.deviceId });
              // In production, trigger key rotation
              // For now, we'll rotate on next reconnect
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
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        logger.error('WebSocket message error', {
          clientId,
          message: err.message,
          stack: err.stack,
          name: err.name,
        }, err);
        console.error('WebSocket Error Details:', {
          message: err.message,
          stack: err.stack,
          name: err.name,
        });
        ws.close(1011, err.message || 'Internal error');
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
          await subscriber.quit();
        } catch (error) {
          logger.error('Failed to cleanup Redis subscriber', {}, error instanceof Error ? error : new Error(String(error)));
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
        // Untrack device for per-user rate limiting
        untrackUserDevice(sessionState.userId, sessionState.deviceId);
        
        sessionManager.removeSession(sessionState.userId, sessionState.deviceId);
        await deleteSession(redis, sessionState.deviceId);
        decrementConnection(sessionState.userId, sessionState.deviceId);
        await updatePresence(redis.client, sessionState.deviceId, false);
        
        // Broadcast device offline to other devices (presence update)
        try {
          await presenceBroadcaster.publishDeviceOffline(sessionState.userId, sessionState.deviceId);
          await presenceBroadcaster.cacheDeviceStatus(sessionState.userId, sessionState.deviceId, false);
        } catch (error) {
          logger.warn('Failed to publish device offline presence', {
            userId: sessionState.userId.substring(0, 16) + '...',
            deviceId: sessionState.deviceId,
          }, error instanceof Error ? error : new Error(String(error)));
        }
        
        logger.info('Session closed', { deviceId: sessionState.deviceId });
      }
      
      // Update status to disconnected
      connectionStatuses.set(ws, 'disconnected');
    });

    // Handle errors
    ws.on('error', (error) => {
      logger.error('WebSocket error', { clientId }, error instanceof Error ? error : new Error(String(error)));
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
          logger.error('Failed to send ping', { deviceId: sessionState.deviceId }, error instanceof Error ? error : new Error(String(error)));
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
    logger.debug('Heartbeat started', { deviceId: sessionState.deviceId, interval: HEARTBEAT_INTERVAL });
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
  await subscriber.connect();
  
  await subscriber.subscribe(channel, (message: string) => {
    try {
      const event = JSON.parse(message);
      ws.send(JSON.stringify({ type: 'event', payload: event }));
    } catch (error) {
      logger.error('Failed to forward event from Redis', { channel }, error instanceof Error ? error : new Error(String(error)));
    }
  });

  return subscriber;
}

/**
 * Update device presence
 */
async function updatePresence(
  redis: any,
  deviceId: string,
  isOnline: boolean
): Promise<void> {
  const key = `presence:${deviceId}`;
  if (isOnline) {
    await redis.setEx(key, 300, 'online'); // 5 minute TTL
  } else {
    await redis.del(key);
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
  const { last_ack_device_seq } = request;

  // Enforce replay window
  const replayWindowMs = config.websocket.replayWindowDays * 24 * 60 * 60 * 1000;
  const cutoffTime = new Date(Date.now() - replayWindowMs);

  // First, count how many events need to be replayed
  const countResult = await db.pool.query(
    `SELECT COUNT(*) as total FROM events 
     WHERE device_id = $1 
     AND device_seq > $2 
     AND created_at > $3`,
    [sessionState.deviceId, last_ack_device_seq, cutoffTime]
  );
  
  const totalEvents = parseInt(countResult.rows[0].total, 10);
  
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
    
    ws.send(JSON.stringify({
      type: 'full_resync_required',
      payload: {
        type: 'full_resync_required',
        reason: totalEvents > maxReplayEvents ? 'too_many_events' : 'session_too_old',
        event_count: totalEvents,
        last_ack_device_seq,
        recommendation: 'Clear local state and re-sync from scratch',
      },
    }));
    return;
  }

  // Query events after last_ack_device_seq for this device, within replay window
  const result = await db.pool.query(
    `SELECT * FROM events 
     WHERE device_id = $1 
     AND device_seq > $2 
     AND created_at > $3
     ORDER BY device_seq ASC
     LIMIT 1000`,
    [sessionState.deviceId, last_ack_device_seq, cutoffTime]
  );

  const events = result.rows.map(row => ({
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

  logger.info('Replay response', { 
    deviceId: sessionState.deviceId, 
    eventCount: events.length,
    totalEvents,
  });

  ws.send(JSON.stringify({
    type: 'replay_response',
    payload: {
      type: 'replay_response',
    events,
    },
  }));
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
    `UPDATE devices 
     SET last_ack_device_seq = $1, last_seen = NOW()
     WHERE device_id = $2`,
    [ack.device_seq, sessionState.deviceId]
  );

  sessionState.lastAckDeviceSeq = ack.device_seq;
}
