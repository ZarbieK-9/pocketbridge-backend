#!/usr/bin/env node

/**
 * Generate Ed25519 server identity keys for PocketBridge backend
 * 
 * Usage: node generate-keys.js
 * 
 * This will output environment variables that you can add to your .env file
 */

import crypto from 'crypto';

function generateKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicKeyHex = publicKeyDer.toString('hex');

  console.log('\n=== PocketBridge Server Identity Keys ===\n');
  console.log('Add these to Railway variables:\n');
  console.log(`SERVER_PUBLIC_KEY=${publicKeyHex}`);
  console.log(`SERVER_PRIVATE_KEY=${privateKeyPem.replace(/\n/g, '\\n')}`);
  console.log(`SERVER_PUBLIC_KEY_HEX=${publicKeyHex}`);
  console.log('\n⚠️  Keep these keys secure! Never commit them to git.\n');
  console.log('The backend will also auto-generate keys if these are missing,');
  console.log('but you should set them explicitly for production.\n');
}

generateKeys();

