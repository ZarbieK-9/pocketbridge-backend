#!/usr/bin/env node

/**
 * Generate Ed25519 server identity keys for PocketBridge backend
 * 
 * Usage: node generate-keys.js
 * 
 * This will output environment variables that you can add to your .env file
 * 
 * Keys are generated in raw hex format (64 hex characters = 32 bytes)
 * matching the format expected by the backend crypto utilities.
 */

import crypto from 'crypto';
import nacl from 'tweetnacl';

function generateKeys() {
  // Generate 32-byte seed and derive Ed25519 keypair via tweetnacl
  // This matches the format used in backend/src/crypto/utils.ts
  const privateKeySeed = crypto.randomBytes(32);
  const keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(privateKeySeed));
  
  // Convert to hex format (64 hex characters = 32 bytes)
  const privateKeyHex = Buffer.from(privateKeySeed).toString('hex');
  const publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex');

  console.log('\n=== PocketBridge Server Identity Keys ===\n');
  console.log('Add these to your .env file or Railway variables:\n');
  console.log(`SERVER_PUBLIC_KEY_HEX=${publicKeyHex}`);
  console.log(`SERVER_PUBLIC_KEY=${publicKeyHex}`);
  console.log(`SERVER_PRIVATE_KEY_HEX=${privateKeyHex}`);
  console.log(`SERVER_PRIVATE_KEY=${privateKeyHex}`);
  console.log('\n⚠️  Keep these keys secure! Never commit them to git.\n');
  console.log('The backend will also auto-generate keys if these are missing,');
  console.log('but you should set them explicitly for production.\n');
}

generateKeys();

