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
import * as ed25519 from '@noble/ed25519';
import { logger } from '../utils/logger.js';

// Set up SHA-512 hash function for @noble/ed25519 v3 in Node.js
// @noble/ed25519 v3 uses `etc.sha512Sync` and `etc.sha512Async`
const sha512 = (m: Uint8Array): Uint8Array => {
  return crypto.createHash('sha512').update(m).digest();
};

const sha512Async = async (m: Uint8Array): Promise<Uint8Array> => {
  return sha512(m);
};

// Set the hash functions on the exported `etc` object
// @noble/ed25519 v2.3.0 exports `etc` which contains sha512Sync and sha512Async
try {
  const ed25519Any = ed25519 as any;
  // The etc object is exported in some versions; set sha512 if available
  if (ed25519Any.etc) {
    ed25519Any.etc.sha512Sync = sha512;
    ed25519Any.etc.sha512Async = sha512Async;
  } else {
    logger.warn('ed25519.etc not available; skipping sha512 hook setup (using Node crypto for Ed25519 ops)');
  }
} catch (e) {
  logger.warn('Could not set up SHA-512 for ed25519; continuing with Node crypto', e instanceof Error ? e : new Error(String(e)));
}

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
    // Use randomSecretKey (32-byte seed) compatible with v3
    const privateKey = ed25519.utils.randomSecretKey();
    const publicKey = await ed25519.getPublicKey(privateKey);
    
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
  const dataBytes = typeof data === 'string' 
    ? Buffer.from(data, 'utf8') 
    : data;
  
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
      logger.error('Failed to parse PEM private key', {
        keyPrefix: privateKeyHex.substring(0, 50),
        error: errorMessage,
      }, error instanceof Error ? error : new Error(String(error)));
      throw new Error(`Invalid private key format (expected hex or PEM): ${errorMessage}`);
    }
  } else {
    // Assume hex format
    try {
      const hexBytes = Buffer.from(privateKeyHex, 'hex');
      if (hexBytes.length !== 32) {
        throw new Error(`Invalid Ed25519 private key length: expected 32 bytes (64 hex chars), got ${hexBytes.length} bytes (${privateKeyHex.length} hex chars)`);
      }
      privateKeyBytes = new Uint8Array(hexBytes);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('Failed to parse hex private key', {
        keyLength: privateKeyHex.length,
        error: errorMessage,
      }, error instanceof Error ? error : new Error(String(error)));
      throw new Error(`Invalid hex private key format: ${errorMessage}`);
    }
  }
  
  // Final check - TypeScript guard
  if (!privateKeyBytes || privateKeyBytes.length !== 32) {
    throw new Error('Failed to extract valid 32-byte Ed25519 private key');
  }
  
  const signature = await ed25519.sign(dataBytes, privateKeyBytes);
  return Buffer.from(signature).toString('hex');
}

/**
 * Verify Ed25519 signature (hex format)
 */
export async function verifyEd25519(publicKeyHex: string, data: Buffer | string, signatureHex: string): Promise<boolean> {
  const dataBytes = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  const signatureBytes = Buffer.from(signatureHex, 'hex');

  try {
    // If the publicKeyHex appears to be raw 32-byte hex, wrap it in SPKI DER.
    // SPKI DER prefix for Ed25519 public key: 302a300506032b6570032100
    let publicKeyDer: Buffer;
    if (publicKeyHex.length === 64) {
      const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
      const rawPub = Buffer.from(publicKeyHex, 'hex');
      publicKeyDer = Buffer.concat([spkiPrefix, rawPub]);
    } else {
      // Assume already DER-encoded (like SERVER_PUBLIC_KEY_HEX format)
      publicKeyDer = Buffer.from(publicKeyHex, 'hex');
    }

    const publicKeyObject = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    // For Ed25519, algorithm must be null
    return crypto.verify(null, dataBytes, publicKeyObject, signatureBytes);
  } catch (e) {
    logger.error('Ed25519 verify via Node crypto failed, falling back to noble', {
      error: e instanceof Error ? e.message : String(e),
      pubKeyLen: publicKeyHex.length,
    });
    // Fallback to noble (requires sha512 configured); may fail in some environments
    try {
      const publicKeyBytes = Buffer.from(publicKeyHex.length === 64 ? publicKeyHex : '', 'hex');
      if (publicKeyBytes.length !== 32) {
        throw new Error('Fallback noble verify requires raw 32-byte public key');
      }
      return await ed25519.verify(signatureBytes, dataBytes, publicKeyBytes);
    } catch (e2) {
      logger.error('Ed25519 noble verify failed', { error: e2 instanceof Error ? e2.message : String(e2) });
      return false;
    }
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
      throw new Error(`Invalid public key hex length: expected 130 (65 bytes), got ${publicKeyHex.length}`);
    }
    if (privateKeyHex.length !== 64) {
      throw new Error(`Invalid private key hex length: expected 64 (32 bytes), got ${privateKeyHex.length}`);
    }
    
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(Buffer.from(privateKeyHex, 'hex'));
    
    // Convert hex string to Buffer
    const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');
    
    // Validate public key format
    // For P-256, raw format should be 65 bytes (0x04 + 32-byte X + 32-byte Y)
    if (publicKeyBuffer.length !== 65) {
      throw new Error(`Invalid public key buffer length: expected 65 bytes, got ${publicKeyBuffer.length}`);
    }
    
    // Ensure first byte is 0x04 (uncompressed point indicator)
    if (publicKeyBuffer[0] !== 0x04) {
      throw new Error(`Invalid public key format: expected uncompressed (0x04), got 0x${publicKeyBuffer[0].toString(16).padStart(2, '0')}`);
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
 * - info: "pocketbridge_session_v1"
 * - length: 32 bytes (AES-256)
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

  // Info = protocol identifier
  const info = Buffer.from('pocketbridge_session_v1', 'utf8');

  // HKDF extract
  const prk = crypto.createHmac('sha256', salt).update(sharedSecret).digest();

  // HKDF expand (32 bytes = AES-256 key)
  const hmac = crypto.createHmac('sha256', prk);
  hmac.update(info);
  hmac.update(Buffer.from([0x01])); // Counter
  const sessionKey = hmac.digest();

  return {
    clientKey: sessionKey, // Same key for both directions (simplified)
    serverKey: sessionKey,
    clientKeyHex: sessionKey.toString('hex'),
    serverKeyHex: sessionKey.toString('hex'),
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
export function hashForSignature(...parts: (Buffer | string | object)[]): Buffer {
  const hash = crypto.createHash('sha256');
  for (const part of parts) {
    if (Buffer.isBuffer(part)) {
      hash.update(part);
    } else if (typeof part === 'string') {
      hash.update(Buffer.from(part, 'utf8'));
    } else {
      hash.update(Buffer.from(JSON.stringify(part), 'utf8'));
    }
  }
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





