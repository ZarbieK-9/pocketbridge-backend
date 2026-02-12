/**
 * Generate Keys Script Tests
 * 
 * Tests for the generate-keys.js script that creates Ed25519 server identity keys
 */

import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

describe('Generate Keys Script', () => {
  describe('Key Generation', () => {
    it('should generate valid Ed25519 keypair', () => {
      // Execute the generate-keys.js script
      const output = execSync('node generate-keys.js', { 
        encoding: 'utf8',
        cwd: path.join(process.cwd())
      });
      
      // Parse the output to extract keys
      const lines = output.split('\n');
      const privateKeyLine = lines.find(line => line.includes('SERVER_PRIVATE_KEY='));
      const publicKeyLine = lines.find(line => line.includes('SERVER_PUBLIC_KEY='));
      
      expect(privateKeyLine).toBeDefined();
      expect(publicKeyLine).toBeDefined();
      
      // Extract hex values
      const privateKeyHex = privateKeyLine!.split('=')[1];
      const publicKeyHex = publicKeyLine!.split('=')[1];
      
      // Validate key formats
      expect(privateKeyHex).toBeDefined();
      expect(publicKeyHex).toBeDefined();
      expect(privateKeyHex.length).toBe(64); // 32 bytes = 64 hex chars
      expect(publicKeyHex.length).toBe(64);  // 32 bytes = 64 hex chars
      
      // Validate hex format (only contains 0-9, a-f)
      expect(privateKeyHex).toMatch(/^[0-9a-f]{64}$/);
      expect(publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    });
    
    it('should generate different keys on each run', () => {
      // Run the script twice
      const output1 = execSync('node generate-keys.js', { 
        encoding: 'utf8',
        cwd: path.join(process.cwd())
      });
      const output2 = execSync('node generate-keys.js', { 
        encoding: 'utf8',
        cwd: path.join(process.cwd())
      });
      
      // Extract private keys
      const privateKey1 = output1.split('\n').find(line => line.includes('SERVER_PRIVATE_KEY='))!.split('=')[1];
      const privateKey2 = output2.split('\n').find(line => line.includes('SERVER_PRIVATE_KEY='))!.split('=')[1];
      
      // Keys should be different (random generation)
      expect(privateKey1).not.toBe(privateKey2);
    });
    
    it('should output all required environment variables', () => {
      const output = execSync('node generate-keys.js', { 
        encoding: 'utf8',
        cwd: path.join(process.cwd())
      });
      
      // Check for all required environment variables
      expect(output).toContain('SERVER_PUBLIC_KEY_HEX=');
      expect(output).toContain('SERVER_PUBLIC_KEY=');
      expect(output).toContain('SERVER_PRIVATE_KEY_HEX=');
      expect(output).toContain('SERVER_PRIVATE_KEY=');
    });
    
    it('should include security warning in output', () => {
      const output = execSync('node generate-keys.js', { 
        encoding: 'utf8',
        cwd: path.join(process.cwd())
      });
      
      expect(output).toContain('⚠️');
      expect(output).toContain('Keep these keys secure');
      expect(output).toContain('Never commit them to git');
    });
  });
  
  describe('Key Format Validation', () => {
    it('should generate keys compatible with tweetnacl', async () => {
      const output = execSync('node generate-keys.js', { 
        encoding: 'utf8',
        cwd: path.join(process.cwd())
      });
      
      const privateKeyHex = output.split('\n').find(line => line.includes('SERVER_PRIVATE_KEY='))!.split('=')[1];
      const publicKeyHex = output.split('\n').find(line => line.includes('SERVER_PUBLIC_KEY='))!.split('=')[1];
      
      // Import tweetnacl for validation
      const nacl = await import('tweetnacl');
      
      // Convert hex to buffers
      const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
      const publicKeyBytes = Buffer.from(publicKeyHex, 'hex');
      
      // Validate key lengths
      expect(privateKeyBytes.length).toBe(32); // 32 bytes for Ed25519 private key
      expect(publicKeyBytes.length).toBe(32);  // 32 bytes for Ed25519 public key
      
      // Test that the keys can be used for signing/verification
      // Note: tweetnacl expects 64-byte secret key (32 bytes seed + 32 bytes public key)
      const fullSecretKey = Buffer.concat([privateKeyBytes, publicKeyBytes]);
      const message = Buffer.from('test message');
      const signature = nacl.sign.detached(message, fullSecretKey);
      const isValid = nacl.sign.detached.verify(message, signature, publicKeyBytes);
      
      expect(isValid).toBe(true);
    });
    
    it('should generate keys that match backend crypto utils format', () => {
      const output = execSync('node generate-keys.js', { 
        encoding: 'utf8',
        cwd: path.join(process.cwd())
      });
      
      const privateKeyHex = output.split('\n').find(line => line.includes('SERVER_PRIVATE_KEY='))!.split('=')[1];
      const publicKeyHex = output.split('\n').find(line => line.includes('SERVER_PUBLIC_KEY='))!.split('=')[1];
      
      // These should be raw hex strings (64 chars each)
      expect(typeof privateKeyHex).toBe('string');
      expect(typeof publicKeyHex).toBe('string');
      expect(privateKeyHex.length).toBe(64);
      expect(publicKeyHex.length).toBe(64);
      
      // Should not contain any non-hex characters
      expect(privateKeyHex).toMatch(/^[0-9a-f]{64}$/);
      expect(publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    });
  });
  
  describe('Output Format', () => {
    it('should include proper header and footer messages', () => {
      const output = execSync('node generate-keys.js', { 
        encoding: 'utf8',
        cwd: path.join(process.cwd())
      });
      
      expect(output).toContain('=== PocketBridge Server Identity Keys ===');
      expect(output).toContain('Add these to your .env file or Railway variables:');
      expect(output).toContain('The backend will also auto-generate keys if these are missing,');
      expect(output).toContain('but you should set them explicitly for production.');
    });
    
    it('should output keys in the correct format for .env files', () => {
      const output = execSync('node generate-keys.js', { 
        encoding: 'utf8',
        cwd: path.join(process.cwd())
      });
      
      const lines = output.split('\n').filter(line => line.includes('=') && line.includes('SERVER_'));
      
      // Each line should be in KEY=VALUE format with hex values
      lines.forEach(line => {
        expect(line).toMatch(/^[A-Z_]+=[a-f0-9]{64}$/);
      });
    });
  });
});