/**
 * Handshake Handler
 *
 * Implements MTProto-inspired handshake protocol:
 * 1. Client Hello (ephemeral ECDH + nonce)
 * 2. Server Hello (ephemeral ECDH + server signature + nonce)
 * 3. Client Auth (user_id + device_id + client signature)
 * 4. Session Established (confirmation + replay state)
 *
 * Thread Safety:
 * - Uses message queue per connection to serialize handshake messages
 * - State transitions are atomic and guarded
 * - Prevents concurrent processing of handshake messages
 */

import { WebSocket } from 'ws';
import type { Database } from '../db/postgres.js';
import type { SessionState } from '../types/index.js';
import { config } from '../config.js';
import {
  generateECDHKeypair,
  computeECDHSecret,
  deriveSessionKeys,
  signEd25519,
  verifyEd25519,
  generateNonce,
  validateNonce,
  hashForSignature,
} from '../crypto/utils.js';
import { logger } from '../utils/logger.js';
import type {
  ClientHello,
  ServerHello,
  ClientAuth,
  SessionEstablished,
  WSMessage,
} from '../types/index.js';
import type { ServerIdentityKeypair } from '../crypto/utils.js';
import { isDeviceRevoked } from '../services/device-revocation.js';

interface HandshakeState {
  step: 'client_hello' | 'server_hello' | 'client_auth';
  clientEphemeralPub?: string;
  serverEphemeralKeypair?: ReturnType<typeof generateECDHKeypair>;
  nonceC?: string;
  nonceS?: string;
  nonceC2?: string;
  sharedSecret?: Buffer;
  sessionKeys?: ReturnType<typeof deriveSessionKeys>;
  processing?: boolean; // Guard flag to prevent concurrent processing
}

// Store handshake state per WebSocket connection
const handshakeStates = new WeakMap<WebSocket, HandshakeState>();

// Message queue per connection to serialize handshake processing
const messageQueues = new WeakMap<
  WebSocket,
  Array<{
    message: unknown;
    resolve: (result: HandshakeResult) => void;
    reject: (error: Error) => void;
  }>
>();

// Helper to reset handshake state on error (must be top-level for all usages)
function resetHandshakeStateOnError(ws: WebSocket, reason: string) {
  handshakeStates.delete(ws);
  messageQueues.delete(ws);
}

// Attach WebSocket close handler to reset handshake state
export function attachHandshakeCleanup(ws: WebSocket) {
  ws.on('close', () => {
    resetHandshakeStateOnError(ws, 'connection_closed');
  });
}

interface HandshakeResult {
  success: boolean;
  sessionState?: SessionState;
  error?: string;
  response?: WSMessage;
}

/**
 * Handle handshake message with serialization to prevent race conditions
 * Messages are queued and processed one at a time per connection
 */
export async function handleHandshake(
  message: unknown,
  ws: WebSocket,
  db: Database,
  serverIdentity: ServerIdentityKeypair
): Promise<HandshakeResult> {
  // Ensure cleanup is attached (idempotent)
  if (!(ws as any)._handshakeCleanupAttached) {
    attachHandshakeCleanup(ws);
    (ws as any)._handshakeCleanupAttached = true;
  }

  // Get or create message queue for this connection
  let queue = messageQueues.get(ws);
  if (!queue) {
    queue = [];
    messageQueues.set(ws, queue);
  }

  // Create promise for this message
  return new Promise<HandshakeResult>((resolve, reject) => {
    queue!.push({ message, resolve, reject });

    // Process queue if not already processing
    processHandshakeQueue(ws, db, serverIdentity).catch(reject);
  });
}

/**
 * Process handshake message queue serially (one at a time per connection)
 */
async function processHandshakeQueue(
  ws: WebSocket,
  db: Database,
  serverIdentity: ServerIdentityKeypair
): Promise<void> {
  const queue = messageQueues.get(ws);
  if (!queue || queue.length === 0) {
    return;
  }

  // Get or create handshake state
  let state = handshakeStates.get(ws);
  if (!state) {
    state = { step: 'client_hello', processing: false };
    handshakeStates.set(ws, state);
  }

  // If already processing, wait for current message to complete
  if (state.processing) {
    return; // Queue will be processed when current message completes
  }

  // Mark as processing to prevent concurrent execution
  state.processing = true;

  try {
    while (queue.length > 0) {
      const { message, resolve, reject } = queue.shift()!;

      try {
        // Validate message structure
        if (typeof message !== 'object' || message === null) {
          logger.warn('Invalid message format in handshake', { message });
          resetHandshakeStateOnError(ws, 'invalid_message_format');
          resolve({ success: false, error: 'Invalid message format' });
          continue;
        }

        const msg = message as Record<string, unknown>;
        const currentState = handshakeStates.get(ws);

        // Re-check state after potential concurrent modifications
        if (!currentState) {
          resolve({ success: false, error: 'Handshake state lost' });
          continue;
        }

        let result: HandshakeResult;

        // Handle Client Hello
        if (msg.type === 'client_hello' && currentState.step === 'client_hello') {
          result = await handleClientHello(
            msg as unknown as ClientHello,
            ws,
            currentState,
            serverIdentity
          );
        }
        // Handle Client Auth
        else if (msg.type === 'client_auth' && currentState.step === 'server_hello') {
          result = await handleClientAuth(
            msg as unknown as ClientAuth,
            ws,
            currentState,
            db,
            serverIdentity
          );
        }
        // Invalid handshake step
        else {
          logger.warn('Invalid handshake step', {
            messageType: msg.type,
            currentStep: currentState.step,
            expectedStepForClientHello: 'client_hello',
            expectedStepForClientAuth: 'server_hello',
            stateKeys: Object.keys(currentState),
          });
          resetHandshakeStateOnError(ws, 'invalid_handshake_step');
          result = {
            success: false,
            error: `Invalid handshake step: expected ${msg.type === 'client_auth' ? 'server_hello' : 'client_hello'}, got ${currentState.step}`,
          };
        }

        resolve(result);

        // If handshake completed (session established), stop processing queue
        if (result.success && result.sessionState) {
          state.processing = false;
          messageQueues.delete(ws);
          return;
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error('Error processing handshake message', { error: errorMessage });
        reject(error instanceof Error ? error : new Error(errorMessage));
      }
    }
  } finally {
    // Clear processing flag
    const finalState = handshakeStates.get(ws);
    if (finalState) {
      finalState.processing = false;
    }
  }
}

/**
 * Handle Client Hello (Step 1)
 */
async function handleClientHello(
  message: ClientHello,
  ws: WebSocket,
  state: HandshakeState,
  serverIdentity: ServerIdentityKeypair
): Promise<HandshakeResult> {
  try {
    // Validate message structure
    if (!message || typeof message !== 'object') {
      logger.warn('handleClientHello: Invalid message structure', { message });
      resetHandshakeStateOnError(ws, 'invalid_message_structure');
      return { success: false, error: 'Invalid message structure' };
    }

    if (!message.client_ephemeral_pub || typeof message.client_ephemeral_pub !== 'string') {
      logger.warn('handleClientHello: Missing or invalid client_ephemeral_pub', {
        hasClientEphemeralPub: !!message.client_ephemeral_pub,
        type: typeof message.client_ephemeral_pub,
      });
      resetHandshakeStateOnError(ws, 'invalid_client_ephemeral_pub');
      return { success: false, error: 'Missing or invalid client_ephemeral_pub' };
    }

    if (!message.nonce_c || typeof message.nonce_c !== 'string') {
      logger.warn('handleClientHello: Missing or invalid nonce_c', {
        hasNonceC: !!message.nonce_c,
        type: typeof message.nonce_c,
      });
      resetHandshakeStateOnError(ws, 'invalid_nonce_c');
      return { success: false, error: 'Missing or invalid nonce_c' };
    }

    // Validate nonce format
    if (!validateNonce(message.nonce_c)) {
      logger.warn('handleClientHello: Invalid nonce format', {
        nonceCLength: message.nonce_c?.length,
        nonceCType: typeof message.nonce_c,
      });
      resetHandshakeStateOnError(ws, 'invalid_nonce_format');
      return { success: false, error: 'Invalid nonce format' };
    }

    // Validate we're in the correct state (double-check after queue processing)
    if (state.step !== 'client_hello') {
      logger.warn('handleClientHello: Invalid state', { currentStep: state.step });
      return { success: false, error: `Invalid state: expected client_hello, got ${state.step}` };
    }

    // Generate server ephemeral keypair
    const serverEphemeralKeypair = generateECDHKeypair();
    if (!serverEphemeralKeypair || !serverEphemeralKeypair.publicKey || !serverEphemeralKeypair.privateKey) {
      logger.error('handleClientHello: Failed to generate server ephemeral keypair', {
        hasKeypair: !!serverEphemeralKeypair,
        hasPublicKey: !!serverEphemeralKeypair?.publicKey,
        hasPrivateKey: !!serverEphemeralKeypair?.privateKey,
      });
      throw new Error('Failed to generate server ephemeral keypair');
    }
    const nonceS = generateNonce();

    // Compute shared secret
    const sharedSecret = computeECDHSecret(
      message.client_ephemeral_pub,
      serverEphemeralKeypair.privateKey
    );

    // Derive session keys
    const sessionKeys = deriveSessionKeys(
      sharedSecret,
      message.client_ephemeral_pub,
      serverEphemeralKeypair.publicKey
    );

    // Sign: SHA256(server_identity_pub || server_ephemeral_pub || nonce_c || nonce_s)
    const signatureData = hashForSignature(
      serverIdentity.publicKeyHex,
      serverEphemeralKeypair.publicKey,
      message.nonce_c,
      nonceS
    );

    // Use privateKeyHex if available, otherwise use privateKey (assuming hex format)
    const privateKeyHex = serverIdentity.privateKeyHex || serverIdentity.privateKey;
    if (!privateKeyHex) {
      logger.error('handleClientHello: Server private key not configured');
      return { success: false, error: 'Server private key not configured' };
    }

    const serverSignature = await signEd25519(privateKeyHex, signatureData);

    // Atomically update state (all fields at once to prevent partial updates)
    state.step = 'server_hello';
    state.clientEphemeralPub = message.client_ephemeral_pub;
    state.serverEphemeralKeypair = serverEphemeralKeypair;
    state.nonceC = message.nonce_c;
    state.nonceS = nonceS;
    state.sharedSecret = sharedSecret;
    state.sessionKeys = sessionKeys;

    // Send Server Hello
    const serverHello: ServerHello = {
      type: 'server_hello',
      server_ephemeral_pub: serverEphemeralKeypair.publicKey,
      server_identity_pub: serverIdentity.publicKeyHex,
      server_signature: serverSignature,
      nonce_s: nonceS,
    };

    const response: WSMessage = {
      type: 'server_hello',
      payload: serverHello,
    };

    try {
      ws.send(JSON.stringify(response));
    } catch (sendError) {
      const errorContext = {
        error: sendError instanceof Error ? sendError.message : String(sendError),
        stack: sendError instanceof Error ? sendError.stack : undefined,
      };
      logger.error(errorContext, 'handleClientHello: Failed to send server_hello');
      console.error('[ERROR] handleClientHello: Failed to send server_hello:', {
        ...errorContext,
        fullError: sendError,
      });
      resetHandshakeStateOnError(ws, 'failed_to_send_server_hello');
      return {
        success: false,
        error: `Failed to send server_hello: ${sendError instanceof Error ? sendError.message : String(sendError)}`,
      };
    }

    return { success: true, response };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;
    const errorContext = {
      error: errorMessage,
      errorType: error instanceof Error ? error.constructor.name : typeof error,
      stack: errorStack,
      messageType: message?.type,
      hasClientEphemeralPub: !!message?.client_ephemeral_pub,
      hasNonceC: !!message?.nonce_c,
      serverIdentityConfigured: !!(serverIdentity?.publicKeyHex && serverIdentity?.privateKey),
    };
    
    // Log with both logger and console.error to ensure visibility
    logger.error(errorContext, 'handleClientHello: Exception occurred');
    console.error('[ERROR] handleClientHello: Exception occurred:', {
      ...errorContext,
      fullError: error,
    });
    
    resetHandshakeStateOnError(ws, 'handleClientHello_exception');
    return { success: false, error: `handleClientHello failed: ${errorMessage}` };
  }
}

/**
 * Handle Client Auth (Step 3)
 */
async function handleClientAuth(
  message: ClientAuth,
  ws: WebSocket,
  state: HandshakeState,
  db: Database,
  serverIdentity: ServerIdentityKeypair
): Promise<HandshakeResult> {
  try {
    // Validate message structure
    if (!message || typeof message !== 'object') {
      logger.warn('handleClientAuth: Invalid message structure', { message });
      resetHandshakeStateOnError(ws, 'invalid_message_structure');
      return { success: false, error: 'Invalid message structure' };
    }

    if (!message.user_id || typeof message.user_id !== 'string') {
      logger.warn('handleClientAuth: Missing or invalid user_id', {
        hasUserId: !!message.user_id,
        type: typeof message.user_id,
      });
      resetHandshakeStateOnError(ws, 'invalid_user_id');
      return { success: false, error: 'Missing or invalid user_id' };
    }

    if (!message.device_id || typeof message.device_id !== 'string') {
      logger.warn('handleClientAuth: Missing or invalid device_id', {
        hasDeviceId: !!message.device_id,
        type: typeof message.device_id,
      });
      resetHandshakeStateOnError(ws, 'invalid_device_id');
      return { success: false, error: 'Missing or invalid device_id' };
    }

    if (!message.client_signature || typeof message.client_signature !== 'string') {
      logger.warn('handleClientAuth: Missing or invalid client_signature', {
        hasClientSignature: !!message.client_signature,
        type: typeof message.client_signature,
      });
      resetHandshakeStateOnError(ws, 'invalid_client_signature');
      return { success: false, error: 'Missing or invalid client_signature' };
    }

    // Validate we're in the correct state (double-check after queue processing)
    if (state.step !== 'server_hello') {
      logger.warn('handleClientAuth: Invalid state', { currentStep: state.step });
      resetHandshakeStateOnError(ws, 'invalid_state');
      return { success: false, error: `Invalid state: expected server_hello, got ${state.step}` };
    }

    if (!state.nonceC || !state.nonceS || !state.serverEphemeralKeypair) {
      logger.warn('handleClientAuth: Handshake state incomplete', {
        hasNonceC: !!state.nonceC,
        hasNonceS: !!state.nonceS,
        hasServerEphemeralKeypair: !!state.serverEphemeralKeypair,
        stateStep: state.step,
      });
      resetHandshakeStateOnError(ws, 'handshake_state_incomplete');
      return { success: false, error: 'Handshake state incomplete' };
    }

    // Validate nonce_c2
    if (!message.nonce_c2 || typeof message.nonce_c2 !== 'string') {
      logger.warn('handleClientAuth: Missing or invalid nonce_c2', {
        hasNonceC2: !!message.nonce_c2,
        type: typeof message.nonce_c2,
      });
      resetHandshakeStateOnError(ws, 'invalid_nonce_c2');
      return { success: false, error: 'Missing or invalid nonce_c2' };
    }

    // Validate nonce format
    if (!validateNonce(message.nonce_c2)) {
      logger.warn('handleClientAuth: Invalid nonce_c2 format', {
        nonceC2Length: message.nonce_c2?.length,
        nonceC2Type: typeof message.nonce_c2,
      });
      resetHandshakeStateOnError(ws, 'invalid_nonce_c2_format');
      return { success: false, error: 'Invalid nonce_c2 format' };
    }

    // Verify client signature
    // Signature data: SHA256(user_id || device_id || nonce_c || nonce_s || server_ephemeral_pub)
    // IMPORTANT: The client uses the server_ephemeral_pub from the server_hello message (hex string)
    // We need to use the same value that was sent to the client
    const serverEphemeralPubHex = state.serverEphemeralKeypair.publicKey;

    // Log the exact values being hashed for debugging
    // Show only keys for debug
    logger.info(`[KEYS] user_id: ${message.user_id}`);
    logger.info(`[KEYS] device_id: ${message.device_id}`);
    logger.info(`[KEYS] nonceC: ${state.nonceC}`);
    logger.info(`[KEYS] nonceS: ${state.nonceS}`);
    logger.info(`[KEYS] serverEphemeralPub: ${serverEphemeralPubHex}`);

    // Hash the signature data in the same order as the client
    const signatureData = hashForSignature(
      message.user_id,
      message.device_id,
      state.nonceC,
      state.nonceS,
      serverEphemeralPubHex
    );

    // Log the computed hash for comparison with client (use INFO level so it's visible)
    const signatureDataHex = Buffer.from(signatureData).toString('hex');
    logger.info(`[KEYS] signatureDataHash: ${signatureDataHex}`);

    // Verify signature using hex format (user_id is Ed25519 public key in hex)
    const publicKeyHex = message.user_id;
    if (publicKeyHex.length !== 64) {
      // 32 bytes = 64 hex chars
      resetHandshakeStateOnError(ws, 'invalid_public_key_length');
      return { success: false, error: 'Invalid public key length' };
    }

    // Check if device is revoked before completing handshake (security)
    const revoked = await isDeviceRevoked(db, message.device_id);
    if (revoked) {
      logger.warn('Revoked device attempted handshake', {
        deviceId: message.device_id,
        userId: message.user_id.substring(0, 16) + '...',
      });
      resetHandshakeStateOnError(ws, 'device_revoked');
      return { success: false, error: 'Device has been revoked' };
    }

    // Verify signature using tweetnacl-compatible hex format
    logger.info(`[KEYS] clientSignature: ${message.client_signature}`);

    const isValid = await verifyEd25519(publicKeyHex, signatureData, message.client_signature);

    if (!isValid) {
      // No log except keys
      resetHandshakeStateOnError(ws, 'invalid_client_signature');
      return { success: false, error: 'Invalid client signature' };
    }

    // Get or create user
    await db.pool.query('INSERT INTO users (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING', [
      message.user_id,
    ]);

    // Get or create device in multi-schema and get last_ack_device_seq
    const deviceResult = await db.pool.query(
      `INSERT INTO user_devices (device_id, user_id, last_ack_device_seq, is_online, last_seen)
       VALUES ($1::uuid, $2, 0, TRUE, NOW())
       ON CONFLICT (device_id)
       DO UPDATE SET last_seen = NOW(), is_online = TRUE
       RETURNING last_ack_device_seq`,
      [message.device_id, message.user_id]
    );

    const lastAckDeviceSeq = deviceResult.rows[0]?.last_ack_device_seq || 0;

    // Create session state
    const sessionState: SessionState = {
      userId: message.user_id,
      deviceId: message.device_id,
      sessionKeys: {
        clientKey: state.sessionKeys!.clientKey,
        serverKey: state.sessionKeys!.serverKey,
      },
      lastAckDeviceSeq,
      createdAt: Date.now(),
    };

    // Send Session Established
    const expiresAt = Date.now() + config.websocket.sessionTimeout;
    const sessionEstablished: SessionEstablished = {
      type: 'session_established',
      device_id: message.device_id,
      last_ack_device_seq: lastAckDeviceSeq,
      expires_at: expiresAt,
    };

    const sessionEstablishedMessage = {
      type: 'session_established',
      payload: sessionEstablished,
    };

    try {
      ws.send(JSON.stringify(sessionEstablishedMessage));
    } catch (error) {
      const errorContext = {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      };
      logger.error(errorContext, 'Failed to send session_established message');
      console.error('[ERROR] Failed to send session_established message:', {
        ...errorContext,
        fullError: error,
      });
      throw error;
    }

    // Clear handshake state
    handshakeStates.delete(ws);

    return {
      success: true,
      sessionState,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;
    const errorContext = {
      error: errorMessage,
      errorType: error instanceof Error ? error.constructor.name : typeof error,
      stack: errorStack,
      hasUserId: !!message?.user_id,
      hasDeviceId: !!message?.device_id,
      hasClientSignature: !!message?.client_signature,
      stateStep: state?.step,
    };
    
    // Log with both logger and console.error to ensure visibility
    logger.error(errorContext, 'handleClientAuth: Exception occurred');
    console.error('[ERROR] handleClientAuth: Exception occurred:', {
      ...errorContext,
      fullError: error,
    });
    
    resetHandshakeStateOnError(ws, 'handleClientAuth_exception');
    return { success: false, error: `handleClientAuth failed: ${errorMessage}` };
  }
}
