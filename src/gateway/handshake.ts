/**
 * Handshake Handler
 * 
 * Implements MTProto-inspired handshake protocol:
 * 1. Client Hello (ephemeral ECDH + nonce)
 * 2. Server Hello (ephemeral ECDH + server signature + nonce)
 * 3. Client Auth (user_id + device_id + client signature)
 * 4. Session Established (confirmation + replay state)
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
import type { ClientHello, ServerHello, ClientAuth, SessionEstablished, WSMessage } from '../types/index.js';
import type { ServerIdentityKeypair } from '../crypto/utils.js';

interface HandshakeState {
  step: 'client_hello' | 'server_hello' | 'client_auth';
  clientEphemeralPub?: string;
  serverEphemeralKeypair?: ReturnType<typeof generateECDHKeypair>;
  nonceC?: string;
  nonceS?: string;
  nonceC2?: string;
  sharedSecret?: Buffer;
  sessionKeys?: ReturnType<typeof deriveSessionKeys>;
}


// Store handshake state per WebSocket connection
const handshakeStates = new WeakMap<WebSocket, HandshakeState>();

// Helper to reset handshake state on error (must be top-level for all usages)
function resetHandshakeStateOnError(ws: WebSocket, reason: string) {
  handshakeStates.delete(ws);
}

// Attach WebSocket close handler to reset handshake state
export function attachHandshakeCleanup(ws: WebSocket) {
  ws.on('close', () => {
    handshakeStates.delete(ws);
  });
}

interface HandshakeResult {
  success: boolean;
  sessionState?: SessionState;
  error?: string;
  response?: WSMessage;
}

/**
 * Handle handshake message
 */
export async function handleHandshake(
  message: unknown,
  ws: WebSocket,
  db: Database,
  serverIdentity: ServerIdentityKeypair
): Promise<HandshakeResult> {
  // Get or create handshake state
  let state = handshakeStates.get(ws);
  // Ensure cleanup is attached (idempotent)
  if (!(ws as any)._handshakeCleanupAttached) {
    attachHandshakeCleanup(ws);
    (ws as any)._handshakeCleanupAttached = true;
  }
  if (!state) {
    state = { step: 'client_hello' };
    handshakeStates.set(ws, state);
  }


  // Validate message structure
  if (typeof message !== 'object' || message === null) {
    logger.warn('Invalid message format in handshake', { message });
    resetHandshakeStateOnError(ws, 'invalid_message_format');
    return { success: false, error: 'Invalid message format' };
  }

  const msg = message as Record<string, unknown>;

  // Handle Client Hello
  if (msg.type === 'client_hello' && state.step === 'client_hello') {
    return handleClientHello(msg as unknown as ClientHello, ws, state, serverIdentity);
  }

  // Handle Client Auth
  if (msg.type === 'client_auth' && state.step === 'server_hello') {
    return handleClientAuth(msg as unknown as ClientAuth, ws, state, db, serverIdentity);
  }

  // Log why handshake step is invalid
  logger.warn('Invalid handshake step', {
    messageType: msg.type,
    currentStep: state.step,
    expectedStepForClientHello: 'client_hello',
    expectedStepForClientAuth: 'server_hello',
    stateKeys: Object.keys(state),
  });

  resetHandshakeStateOnError(ws, 'invalid_handshake_step');
  return { success: false, error: `Invalid handshake step: expected ${msg.type === 'client_auth' ? 'server_hello' : 'client_hello'}, got ${state.step}` };
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
    // Validate nonce
    if (!validateNonce(message.nonce_c)) {
      resetHandshakeStateOnError(ws, 'invalid_nonce_format');
      return { success: false, error: 'Invalid nonce format' };
    }

    // Generate server ephemeral keypair
    const serverEphemeralKeypair = generateECDHKeypair();
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

    // Update state
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
    
    try {
      ws.send(JSON.stringify({
        type: 'server_hello',
        payload: serverHello,
      }));
    } catch (sendError) {
      logger.error('handleClientHello: Failed to send server_hello', {}, sendError instanceof Error ? sendError : new Error(String(sendError)));
      resetHandshakeStateOnError(ws, 'failed_to_send_server_hello');
      return { success: false, error: `Failed to send server_hello: ${sendError instanceof Error ? sendError.message : String(sendError)}` };
    }

    return { success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;
    logger.error('handleClientHello: Exception occurred', {
      error: errorMessage,
      errorType: error instanceof Error ? error.constructor.name : typeof error,
      hasStack: !!errorStack,
    }, error instanceof Error ? error : new Error(String(error)));
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
  if (!state.nonceC || !state.nonceS || !state.serverEphemeralKeypair) {
    return { success: false, error: 'Handshake state incomplete' };
  }

  // Validate nonce
  if (!validateNonce(message.nonce_c2)) {
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
  if (publicKeyHex.length !== 64) { // 32 bytes = 64 hex chars
    resetHandshakeStateOnError(ws, 'invalid_public_key_length');
    return { success: false, error: 'Invalid public key length' };
  }

  // Verify signature using tweetnacl-compatible hex format
  logger.info(`[KEYS] clientSignature: ${message.client_signature}`);

  const isValid = await verifyEd25519(
    publicKeyHex,
    signatureData,
    message.client_signature
  );

  if (!isValid) {
    // No log except keys
    resetHandshakeStateOnError(ws, 'invalid_client_signature');
    return { success: false, error: 'Invalid client signature' };
  }

  // Get or create user
  await db.pool.query(
    'INSERT INTO users (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING',
    [message.user_id]
  );

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
    logger.error('Failed to send session_established message', {}, error instanceof Error ? error : new Error(String(error)));
    throw error;
  }

  // Clear handshake state
  handshakeStates.delete(ws);

  return {
    success: true,
    sessionState,
  };
}
