/**
 * Cryptographic Utilities
 *
 * Server-side crypto operations:
 * - Ed25519 signature verification (client authentication)
 * - ECDH key exchange (session handshake)
 * - HKDF key derivation (session keys)
 * - Nonce generation and validation
 *
 * NOTE: Server never decrypts payloads. This module only handles
 * authentication, key exchange, and session establishment.
 */

import crypto from 'crypto';
// tweetnacl uses default export in ESM
import nacl from 'tweetnacl';
import { logger } from '../utils/logger.js';

// Validate tweetnacl import at module load time
if (!nacl || !nacl.sign || !nacl.sign.keyPair || !nacl.sign.keyPair.fromSeed) {
  const errorMsg = 'tweetnacl import failed or API not available. Check tweetnacl installation.';
  console.error('[CRITICAL]', errorMsg, {
    hasNacl: !!nacl,
    hasNaclSign: !!nacl?.sign,
    hasKeyPair: !!(nacl?.sign && nacl.sign.keyPair),
    naclKeys: nacl ? Object.keys(nacl) : [],
    naclType: typeof nacl,
  });
  throw new Error(errorMsg);
}

// Using tweetnacl for Ed25519 across backend

export interface ServerIdentityKeypair {
  publicKey: string; // Hex format (for compatibility)
  privateKey: string; // Hex format (for compatibility)
  publicKeyHex: string; // Hex format for transmission
  privateKeyHex?: string; // Hex format for signing
}

export interface ECDHKeypair {
  publicKey: string; // Hex
  privateKey: string; // Hex
  ecdh: crypto.ECDH; // Keep ECDH instance for computeSecret
}

export interface SessionKeys {
  clientKey: Buffer;
  serverKey: Buffer;
  clientKeyHex: string;
  serverKeyHex: string;
}

/**
 * Generate Ed25519 keypair for server identity
 * In production, load from secure storage (env var, HSM, etc.)
 */
export async function generateServerIdentityKeypair(): Promise<ServerIdentityKeypair> {
  try {
    // Generate 32-byte seed and derive Ed25519 keypair via tweetnacl
    const privateKey = nacl.randomBytes(32);
    const kp = nacl.sign.keyPair.fromSeed(privateKey);
    const publicKey = kp.publicKey;

    const privateKeyHex = Buffer.from(privateKey).toString('hex');
    const publicKeyHex = Buffer.from(publicKey).toString('hex');

    return {
      publicKey: publicKeyHex, // Hex format
      privateKey: privateKeyHex, // Hex format
      publicKeyHex: publicKeyHex,
      privateKeyHex: privateKeyHex,
    };
  } catch (error) {
    console.error('Error generating server identity keypair:', error);
    throw error;
  }
}

/**
 * Sign data with Ed25519 private key (hex or PEM format)
 */
export async function signEd25519(privateKeyHex: string, data: Buffer | string): Promise<string> {
  const dataBytes = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;

  let privateKeyBytes: Uint8Array | null = null;

  // Check if it's PEM format
  if (privateKeyHex.includes('-----BEGIN') || privateKeyHex.includes('\\n')) {
    try {
      // Handle escaped newlines from environment variables
      const pemKey = privateKeyHex.replace(/\\n/g, '\n');
      const privateKeyObject = crypto.createPrivateKey(pemKey);
      // Use Node.js crypto to sign with Ed25519 PKCS8 directly (avoids noble sha512 setup)
      const signatureBuf = crypto.sign(null, dataBytes, privateKeyObject);
      return Buffer.from(signatureBuf).toString('hex');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(
        'Failed to parse PEM private key',
        {
          keyPrefix: privateKeyHex.substring(0, 50),
          error: errorMessage,
        },
        error instanceof Error ? error : new Error(String(error))
      );
      throw new Error(`Invalid private key format (expected hex or PEM): ${errorMessage}`);
    }
  } else {
    // Assume hex format
    try {
      const hexBytes = Buffer.from(privateKeyHex, 'hex');
      if (hexBytes.length !== 32) {
        throw new Error(
          `Invalid Ed25519 private key length: expected 32 bytes (64 hex chars), got ${hexBytes.length} bytes (${privateKeyHex.length} hex chars)`
        );
      }
      privateKeyBytes = new Uint8Array(hexBytes);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(
        'Failed to parse hex private key',
        {
          keyLength: privateKeyHex.length,
          error: errorMessage,
        },
        error instanceof Error ? error : new Error(String(error))
      );
      throw new Error(`Invalid hex private key format: ${errorMessage}`);
    }
  }

  // Final check - TypeScript guard
  if (!privateKeyBytes || privateKeyBytes.length !== 32) {
    throw new Error('Failed to extract valid 32-byte Ed25519 private key');
  }
  
  // Validate nacl.sign exists
  if (!nacl.sign || !nacl.sign.keyPair || !nacl.sign.keyPair.fromSeed) {
    const errorMsg = 'tweetnacl sign API not available. Check tweetnacl import and version.';
    logger.error(errorMsg, {
      hasNacl: !!nacl,
      hasNaclSign: !!nacl.sign,
      hasKeyPair: !!(nacl.sign && nacl.sign.keyPair),
      hasFromSeed: !!(nacl.sign && nacl.sign.keyPair && nacl.sign.keyPair.fromSeed),
    });
    throw new Error(errorMsg);
  }
  
  // tweetnacl requires secretKey (64 bytes); derive from seed
  const kp = nacl.sign.keyPair.fromSeed(privateKeyBytes);
  if (!kp || !kp.secretKey) {
    throw new Error('Failed to generate keypair from seed');
  }
  const signature = nacl.sign.detached(new Uint8Array(dataBytes), kp.secretKey);
  return Buffer.from(signature).toString('hex');
}

/**
 * Verify Ed25519 signature (hex format)
 */
export async function verifyEd25519(
  publicKeyHex: string,
  data: Buffer | string,
  signatureHex: string
): Promise<boolean> {
  // Convert data to Uint8Array - handle Buffer explicitly
  let dataBytes: Uint8Array;
  if (typeof data === 'string') {
    dataBytes = new TextEncoder().encode(data);
  } else if (Buffer.isBuffer(data)) {
    // Convert Buffer to Uint8Array - create a new array to avoid buffer sharing issues
    dataBytes = new Uint8Array(data.length);
    dataBytes.set(data);
  } else {
    dataBytes = new Uint8Array(data);
  }
  const signatureBytes = new Uint8Array(Buffer.from(signatureHex, 'hex'));

  try {
    let publicKeyBytes: Uint8Array;
    // Raw 32-byte hex
    if (publicKeyHex.length === 64) {
      publicKeyBytes = new Uint8Array(Buffer.from(publicKeyHex, 'hex'));
    } else {
      // Try SPKI DER prefix: 302a300506032b6570032100
      const prefix = '302a300506032b6570032100';
      if (publicKeyHex.startsWith(prefix) && publicKeyHex.length === prefix.length + 64) {
        publicKeyBytes = new Uint8Array(Buffer.from(publicKeyHex.slice(prefix.length), 'hex'));
      } else {
        // Fallback to Node crypto verify for unknown formats
        const publicKeyDer = Buffer.from(publicKeyHex, 'hex');
        const publicKeyObject = crypto.createPublicKey({
          key: publicKeyDer,
          format: 'der',
          type: 'spki',
        });
        return crypto.verify(
          null,
          Buffer.from(dataBytes),
          publicKeyObject,
          Buffer.from(signatureBytes)
        );
      }
    }
    return nacl.sign.detached.verify(dataBytes, signatureBytes, publicKeyBytes);
  } catch (e) {
    logger.error('Ed25519 verify failed', { error: e instanceof Error ? e.message : String(e) });
    return false;
  }
}

/**
 * Generate ECDH keypair (P-256) for ephemeral session keys
 */
export function generateECDHKeypair(): ECDHKeypair {
  const ecdh = crypto.createECDH('prime256v1'); // P-256
  ecdh.generateKeys();
  return {
    publicKey: ecdh.getPublicKey('hex'),
    privateKey: ecdh.getPrivateKey('hex'),
    ecdh, // Keep ECDH instance for computeSecret
  };
}

/**
 * Compute shared secret from ECDH
 *
 * @param publicKeyHex - Other party's public key in hex format (uncompressed, 65 bytes = 130 hex chars)
 * @param privateKeyHex - Our private key in hex format (32 bytes = 64 hex chars)
 * @returns Shared secret as Buffer
 */
export function computeECDHSecret(publicKeyHex: string, privateKeyHex: string): Buffer {
  try {
    // Validate input lengths
    if (publicKeyHex.length !== 130) {
      throw new Error(
        `Invalid public key hex length: expected 130 (65 bytes), got ${publicKeyHex.length}`
      );
    }
    if (privateKeyHex.length !== 64) {
      throw new Error(
        `Invalid private key hex length: expected 64 (32 bytes), got ${privateKeyHex.length}`
      );
    }

    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(Buffer.from(privateKeyHex, 'hex'));

    // Convert hex string to Buffer
    const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');

    // Validate public key format
    // For P-256, raw format should be 65 bytes (0x04 + 32-byte X + 32-byte Y)
    if (publicKeyBuffer.length !== 65) {
      throw new Error(
        `Invalid public key buffer length: expected 65 bytes, got ${publicKeyBuffer.length}`
      );
    }

    // Ensure first byte is 0x04 (uncompressed point indicator)
    if (publicKeyBuffer[0] !== 0x04) {
      throw new Error(
        `Invalid public key format: expected uncompressed (0x04), got 0x${publicKeyBuffer[0].toString(16).padStart(2, '0')}`
      );
    }

    // Compute shared secret - Node.js ECDH accepts raw uncompressed format
    return ecdh.computeSecret(publicKeyBuffer);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error('ECDH secret computation failed', {
      error: errorMessage,
      publicKeyHexLength: publicKeyHex.length,
      publicKeyHexPrefix: publicKeyHex.substring(0, 8),
      privateKeyHexLength: privateKeyHex.length,
    });
    throw new Error(`ECDH secret computation failed: ${errorMessage}`);
  }
}

/**
 * Derive session keys using HKDF (RFC 5869)
 *
 * HKDF(shared_secret, salt, info, length)
 * - salt: SHA256(client_ephemeral_pub || server_ephemeral_pub)
 * - info: direction-specific string to derive separate keys
 * - length: 32 bytes (AES-256)
 *
 * SECURITY: Derives separate keys for each direction to prevent reflection attacks.
 * - clientKey: Key for client-to-server direction (server uses to decrypt FROM client)
 * - serverKey: Key for server-to-client direction (server uses to encrypt TO client)
 */
export function deriveSessionKeys(
  sharedSecret: Buffer,
  clientEphemeralPub: string,
  serverEphemeralPub: string
): SessionKeys {
  // Salt = SHA256(client_pub || server_pub)
  const salt = crypto
    .createHash('sha256')
    .update(Buffer.from(clientEphemeralPub, 'hex'))
    .update(Buffer.from(serverEphemeralPub, 'hex'))
    .digest();

  // HKDF extract (same PRK for both keys)
  const prk = crypto.createHmac('sha256', salt).update(sharedSecret).digest();

  // Derive client-to-server key (used by server to decrypt messages FROM client)
  const clientToServerInfo = Buffer.from('pocketbridge_client_to_server_v1', 'utf8');
  const clientKeyHmac = crypto.createHmac('sha256', prk);
  clientKeyHmac.update(clientToServerInfo);
  clientKeyHmac.update(Buffer.from([0x01])); // Counter
  const clientKey = clientKeyHmac.digest();

  // Derive server-to-client key (used by server to encrypt messages TO client)
  const serverToClientInfo = Buffer.from('pocketbridge_server_to_client_v1', 'utf8');
  const serverKeyHmac = crypto.createHmac('sha256', prk);
  serverKeyHmac.update(serverToClientInfo);
  serverKeyHmac.update(Buffer.from([0x01])); // Counter
  const serverKey = serverKeyHmac.digest();

  return {
    clientKey,
    serverKey,
    clientKeyHex: clientKey.toString('hex'),
    serverKeyHex: serverKey.toString('hex'),
  };
}

/**
 * Generate cryptographically random nonce (32 bytes)
 */
export function generateNonce(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Validate nonce format (32 bytes hex)
 */
export function validateNonce(nonce: string): boolean {
  if (typeof nonce !== 'string') return false;
  if (nonce.length !== 64) return false; // 32 bytes = 64 hex chars
  return /^[0-9a-f]+$/i.test(nonce);
}

/**
 * Hash data for signature verification
 */
export function hashForSignature(...parts: (Buffer | Uint8Array | string | object)[]): Buffer {
  const hash = crypto.createHash('sha256');
  parts.forEach(part => {
    let str: string;
    if (Buffer.isBuffer(part) || part instanceof Uint8Array) {
      // Convert Buffer/Uint8Array to hex string
      str = Buffer.from(part).toString('hex');
    } else {
      str = String(part);
    }
    hash.update(Buffer.from(str, 'utf8'));
  });
  return hash.digest();
}

/**
 * Convert hex string to Buffer
 */
export function hexToBuffer(hex: string): Buffer {
  return Buffer.from(hex, 'hex');
}

/**
 * Convert Buffer to hex string
 */
export function bufferToHex(buffer: Buffer): string {
  return buffer.toString('hex');
}
