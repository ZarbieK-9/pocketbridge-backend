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

/**
 * Generate Ed25519 keypair for server identity
 * @returns {Object} Object containing privateKeyHex and publicKeyHex
 */
function generateKeys() {
  // Generate 32-byte seed and derive Ed25519 keypair via tweetnacl
  // This matches the format used in backend/src/crypto/utils.ts
  const privateKeySeed = crypto.randomBytes(32);
  const keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(privateKeySeed));
  
  // Convert to hex format (64 hex characters = 32 bytes)
  const privateKeyHex = Buffer.from(privateKeySeed).toString('hex');
  const publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex');

  return { privateKeyHex, publicKeyHex };
}

/**
 * Validate that generated keys are in correct format
 * @param {string} privateKeyHex - Private key in hex format
 * @param {string} publicKeyHex - Public key in hex format
 * @returns {boolean} True if keys are valid
 */
function validateKeys(privateKeyHex, publicKeyHex) {
  // Check key lengths (64 hex chars = 32 bytes)
  if (privateKeyHex.length !== 64 || publicKeyHex.length !== 64) {
    return false;
  }
  
  // Check hex format (only contains 0-9, a-f)
  const hexRegex = /^[0-9a-f]{64}$/;
  if (!hexRegex.test(privateKeyHex) || !hexRegex.test(publicKeyHex)) {
    return false;
  }
  
  return true;
}

/**
 * Test that keys work with tweetnacl for signing/verification
 * @param {string} privateKeyHex - Private key in hex format
 * @param {string} publicKeyHex - Public key in hex format
 * @returns {boolean} True if keys work correctly
 */
function testKeyCompatibility(privateKeyHex, publicKeyHex) {
  try {
    // Convert hex to buffers
    const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
    const publicKeyBytes = Buffer.from(publicKeyHex, 'hex');
    
    // Test that the keys can be used for signing/verification
    // Note: tweetnacl expects 64-byte secret key (32 bytes seed + 32 bytes public key)
    const fullSecretKey = Buffer.concat([privateKeyBytes, publicKeyBytes]);
    const message = Buffer.from('test message');
    const signature = nacl.sign.detached(message, fullSecretKey);
    const isValid = nacl.sign.detached.verify(message, signature, publicKeyBytes);
    
    return isValid;
  } catch (error) {
    return false;
  }
}

/**
 * Output the generated keys in the required format
 * @param {string} privateKeyHex - Private key in hex format
 * @param {string} publicKeyHex - Public key in hex format
 */
function outputKeys(privateKeyHex, publicKeyHex) {
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

/**
 * Run tests to validate key generation
 */
function runTests() {
  console.log('Running key generation tests...\n');
  
  // Test 1: Generate keys
  const { privateKeyHex, publicKeyHex } = generateKeys();
  console.log('✓ Generated Ed25519 keypair');
  
  // Test 2: Validate key format
  const isValidFormat = validateKeys(privateKeyHex, publicKeyHex);
  console.log(`✓ Key format validation: ${isValidFormat ? 'PASSED' : 'FAILED'}`);
  
  if (!isValidFormat) {
    console.error('ERROR: Generated keys have invalid format');
    process.exit(1);
  }
  
  // Test 3: Test key compatibility with tweetnacl
  const isCompatible = testKeyCompatibility(privateKeyHex, publicKeyHex);
  console.log(`✓ Key compatibility test: ${isCompatible ? 'PASSED' : 'FAILED'}`);
  
  if (!isCompatible) {
    console.error('ERROR: Generated keys are not compatible with tweetnacl');
    process.exit(1);
  }
  
  // Test 4: Generate multiple keys to ensure randomness
  const keys1 = generateKeys();
  const keys2 = generateKeys();
  const isRandom = keys1.privateKeyHex !== keys2.privateKeyHex;
  console.log(`✓ Randomness test: ${isRandom ? 'PASSED' : 'FAILED'}`);
  
  if (!isRandom) {
    console.error('ERROR: Keys are not random');
    process.exit(1);
  }
  
  console.log('\n✓ All tests passed! Keys are ready for use.\n');
  
  // Output the first generated keys
  outputKeys(privateKeyHex, publicKeyHex);
}

// Main execution
if (process.argv.includes('--test') || process.argv.includes('-t')) {
  runTests();
} else {
  const { privateKeyHex, publicKeyHex } = generateKeys();
  outputKeys(privateKeyHex, publicKeyHex);
}

