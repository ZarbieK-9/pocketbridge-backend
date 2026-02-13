#!/usr/bin/env node

/**
 * Generate Ed25519 server identity keys for PocketBridge backend
 * 
 * Usage: 
 *   node generate-keys.js              - Generate new keys
 *   node generate-keys.js --validate   - Validate existing keys from env
 *   node generate-keys.js --json       - Output as JSON
 *   node generate-keys.js --verify     - Generate and verify keys work
 * 
 * This will output environment variables that you can add to your .env file
 * 
 * Keys are generated in raw hex format (64 hex characters = 32 bytes)
 * matching the format expected by the backend crypto utilities.
 */

import crypto from 'crypto';
import nacl from 'tweetnacl';

/**
 * Generate Ed25519 keypair
 * @returns {Object} Object containing publicKeyHex and privateKeyHex
 */
function generateKeypair() {
  // Generate 32-byte seed and derive Ed25519 keypair via tweetnacl
  // This matches the format used in backend/src/crypto/utils.ts
  const privateKeySeed = crypto.randomBytes(32);
  const keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(privateKeySeed));
  
  // Convert to hex format (64 hex characters = 32 bytes)
  const privateKeyHex = Buffer.from(privateKeySeed).toString('hex');
  const publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex');

  return { publicKeyHex, privateKeyHex };
}

/**
 * Verify that generated keys work correctly by signing and verifying data
 * @param {string} publicKeyHex - Public key in hex format
 * @param {string} privateKeyHex - Private key in hex format
 * @returns {boolean} True if keys work correctly
 */
function verifyKeys(publicKeyHex, privateKeyHex) {
  try {
    const privateKeyBytes = new Uint8Array(Buffer.from(privateKeyHex, 'hex'));
    const publicKeyBytes = new Uint8Array(Buffer.from(publicKeyHex, 'hex'));
    
    // Create keypair from seed
    const keyPair = nacl.sign.keyPair.fromSeed(privateKeyBytes);
    
    // Test message
    const testMessage = new TextEncoder().encode('PocketBridge key verification test');
    
    // Sign the message
    const signature = nacl.sign.detached(testMessage, keyPair.secretKey);
    
    // Verify the signature
    const isValid = nacl.sign.detached.verify(testMessage, signature, publicKeyBytes);
    
    return isValid;
  } catch (error) {
    console.error('Key verification failed:', error.message);
    return false;
  }
}

/**
 * Validate existing keys from environment variables
 * @returns {Object} Validation result
 */
function validateExistingKeys() {
  const publicKey = process.env.SERVER_PUBLIC_KEY || process.env.SERVER_PUBLIC_KEY_HEX;
  const privateKey = process.env.SERVER_PRIVATE_KEY || process.env.SERVER_PRIVATE_KEY_HEX;
  
  if (!publicKey || !privateKey) {
    return {
      valid: false,
      error: 'SERVER_PUBLIC_KEY and SERVER_PRIVATE_KEY environment variables are not set'
    };
  }
  
  // Validate hex format
  const hexRegex = /^[0-9a-fA-F]{64}$/;
  
  if (!hexRegex.test(publicKey)) {
    return {
      valid: false,
      error: `Invalid public key format: expected 64 hex characters, got ${publicKey.length}`
    };
  }
  
  if (!hexRegex.test(privateKey)) {
    return {
      valid: false,
      error: `Invalid private key format: expected 64 hex characters, got ${privateKey.length}`
    };
  }
  
  // Verify keys work correctly
  const isValid = verifyKeys(publicKey, privateKey);
  
  if (!isValid) {
    return {
      valid: false,
      error: 'Key verification failed: keys are invalid or corrupted'
    };
  }
  
  return {
    valid: true,
    publicKey,
    privateKey,
    message: 'Keys are valid and working correctly'
  };
}

/**
 * Output keys in JSON format
 * @param {Object} keys - Keypair object
 */
function outputJson(keys) {
  const output = {
    publicKeyHex: keys.publicKeyHex,
    privateKeyHex: keys.privateKeyHex,
    algorithm: 'Ed25519',
    createdAt: new Date().toISOString()
  };
  console.log(JSON.stringify(output, null, 2));
}

/**
 * Output keys in .env format
 * @param {Object} keys - Keypair object
 */
function outputEnvFormat(keys) {
  console.log('\n=== PocketBridge Server Identity Keys ===\n');
  console.log('Add these to your .env file or Railway variables:\n');
  console.log(`SERVER_PUBLIC_KEY_HEX=${keys.publicKeyHex}`);
  console.log(`SERVER_PUBLIC_KEY=${keys.publicKeyHex}`);
  console.log(`SERVER_PRIVATE_KEY_HEX=${keys.privateKeyHex}`);
  console.log(`SERVER_PRIVATE_KEY=${keys.privateKeyHex}`);
  console.log('\n⚠️  Keep these keys secure! Never commit them to git.\n');
  console.log('The backend will also auto-generate keys if these are missing,');
  console.log('but you should set them explicitly for production.\n');
}

/**
 * Main function
 */
function main() {
  const args = process.argv.slice(2);
  
  // Handle --validate flag
  if (args.includes('--validate')) {
    const result = validateExistingKeys();
    if (result.valid) {
      console.log('\n✅ Keys are valid!\n');
      console.log(`Public Key: ${result.publicKey.substring(0, 16)}...${result.publicKey.substring(48)}`);
      console.log(`Message: ${result.message}\n`);
    } else {
      console.log('\n❌ Key validation failed!\n');
      console.log(`Error: ${result.error}\n`);
      process.exit(1);
    }
    return;
  }
  
  // Handle --json flag
  if (args.includes('--json')) {
    const keys = generateKeypair();
    outputJson(keys);
    return;
  }
  
  // Handle --verify flag (generate and verify)
  if (args.includes('--verify')) {
    const keys = generateKeypair();
    const isValid = verifyKeys(keys.publicKeyHex, keys.privateKeyHex);
    
    if (isValid) {
      console.log('\n✅ Keys generated and verified successfully!\n');
      outputEnvFormat(keys);
    } else {
      console.log('\n❌ Key verification failed! There may be an issue with the cryptographic library.\n');
      process.exit(1);
    }
    return;
  }
  
  // Default: generate and output keys
  const keys = generateKeypair();
  outputEnvFormat(keys);
}

main();

