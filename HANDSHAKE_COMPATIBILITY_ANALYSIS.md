# Handshake Compatibility Analysis: Backend vs PocketBridge Web App

## Overview
This document analyzes the handshake protocol compatibility between the backend server and the pocketbridge web app client.

## Handshake Flow

### Step 1: Client Hello
**Client sends:**
```typescript
{
  type: 'client_hello',
  payload: {
    type: 'client_hello',
    client_ephemeral_pub: string, // P-256 public key (hex, 130 chars)
    nonce_c: string // 32 bytes hex (64 chars)
  }
}
```

**Backend receives:**
- Backend unwraps message: checks if `message.payload.type === message.type`, uses payload if true
- ✅ **COMPATIBLE**: Backend handles both wrapped and unwrapped messages

### Step 2: Server Hello
**Backend sends:**
```typescript
{
  type: 'server_hello',
  payload: {
    type: 'server_hello',
    server_ephemeral_pub: string, // P-256 public key (hex)
    server_identity_pub: string, // Ed25519 public key (hex, 64 chars)
    server_signature: string, // Ed25519 signature (hex)
    nonce_s: string // 32 bytes hex (64 chars)
  }
}
```

**Client receives:**
- Client expects `message.payload` to contain ServerHello
- ✅ **COMPATIBLE**: Message format matches

**Server Signature (Backend):**
```typescript
// Backend signs:
hashForSignature(
  serverIdentity.publicKeyHex,      // 1. server_identity_pub
  serverEphemeralKeypair.publicKey, // 2. server_ephemeral_pub
  message.nonce_c,                  // 3. nonce_c
  nonceS                             // 4. nonce_s
)
```

**Server Signature Verification (Client):**
```typescript
// Client verifies (currently disabled - TODO):
hashForSignature(
  clientEphemeralKeyPair.publicKeyHex, // 1. client_ephemeral_pub ❌ WRONG!
  message.server_ephemeral_pub,       // 2. server_ephemeral_pub
  nonceC,                              // 3. nonce_c
  message.nonce_s                      // 4. nonce_s
)
```

❌ **ISSUE FOUND**: Client verification logic is incorrect!
- Backend signs: `server_identity_pub || server_ephemeral_pub || nonce_c || nonce_s`
- Client verifies: `client_ephemeral_pub || server_ephemeral_pub || nonce_c || nonce_s`
- Client is missing `server_identity_pub` and has wrong first parameter

**Note**: Client verification is currently disabled (TODO comment), so this doesn't break the handshake yet, but needs to be fixed.

### Step 3: Client Auth
**Client sends:**
```typescript
{
  type: 'client_auth',
  payload: {
    type: 'client_auth',
    user_id: string, // Ed25519 public key (hex, 64 chars)
    device_id: string, // UUIDv4
    client_signature: string, // Ed25519 signature (hex)
    nonce_c2: string // 32 bytes hex (64 chars)
  }
}
```

**Backend receives:**
- Backend unwraps message same way as client_hello
- ✅ **COMPATIBLE**: Message format matches

**Client Signature (Client):**
```typescript
// Client signs:
hashForSignature(
  userId,                    // 1. user_id
  deviceId,                  // 2. device_id
  nonceC,                    // 3. nonce_c
  nonceS,                    // 4. nonce_s
  serverEphemeralPub         // 5. server_ephemeral_pub
)
```

**Client Signature Verification (Backend):**
```typescript
// Backend verifies:
hashForSignature(
  message.user_id,           // 1. user_id
  message.device_id,         // 2. device_id
  state.nonceC,              // 3. nonce_c
  state.nonceS,              // 4. nonce_s
  serverEphemeralPubHex     // 5. server_ephemeral_pub
)
```

✅ **COMPATIBLE**: Signature data matches exactly

### Step 4: Session Established
**Backend sends:**
```typescript
{
  type: 'session_established',
  payload: {
    type: 'session_established',
    device_id: string,
    last_ack_device_seq: number,
    expires_at: number // Unix timestamp (milliseconds)
  }
}
```

**Client receives:**
- Client expects `message.payload` to contain SessionEstablished
- ✅ **COMPATIBLE**: Message format matches

## Cryptographic Compatibility

### ECDH Key Exchange
**Backend:**
- Uses Node.js `crypto.createECDH('prime256v1')` (P-256)
- Public key format: uncompressed (65 bytes = 130 hex chars)
- Private key: 32 bytes (64 hex chars)

**Client:**
- Uses Web Crypto API `ECDH` with `namedCurve: 'P-256'`
- Public key format: raw (65 bytes = 130 hex chars)
- Private key: CryptoKey object

✅ **COMPATIBLE**: Both use P-256, same public key format

### Session Key Derivation (HKDF)
**Backend:**
```typescript
// Salt = SHA256(client_ephemeral_pub || server_ephemeral_pub)
// Info = "pocketbridge_session_v1"
// Length = 32 bytes (AES-256)
```

**Client:**
```typescript
// Salt = SHA256(client_ephemeral_pub || server_ephemeral_pub)
// Info = "pocketbridge_session_v1"
// Length = 32 bytes (AES-256)
```

✅ **COMPATIBLE**: HKDF parameters match exactly

### hashForSignature Implementation

**Backend:**
```typescript
function hashForSignature(...parts: (Buffer | Uint8Array | string | object)[]): Buffer {
  const hash = crypto.createHash('sha256');
  parts.forEach((part) => {
    let str: string;
    if (Buffer.isBuffer(part) || part instanceof Uint8Array) {
      str = Buffer.from(part).toString('hex'); // Convert to hex string
    } else {
      str = String(part);
    }
    hash.update(Buffer.from(str, 'utf8')); // UTF-8 encode string, update hash
  });
  return hash.digest();
}
```

**Client:**
```typescript
private async hashForSignature(...parts: (string | number)[]): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const combined: Uint8Array[] = [];
  parts.forEach((part) => {
    let str: string;
    if (Buffer.isBuffer(part)) {
      str = Buffer.from(part).toString('hex');
    } else if (ArrayBuffer.isView(part) && part.constructor.name === 'Uint8Array') {
      str = Array.from(new Uint8Array(part.buffer, part.byteOffset, part.byteLength))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    } else {
      str = String(part);
    }
    combined.push(encoder.encode(str)); // UTF-8 encode string
  });
  // Concatenate all UTF-8 encoded strings
  const totalLength = combined.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of combined) {
    result.set(arr, offset);
    offset += arr.length;
  }
  // Hash the concatenated result
  return new Uint8Array(await crypto.subtle.digest('SHA-256', result));
}
```

✅ **COMPATIBLE**: Both implementations:
1. Convert each part to string (hex for buffers/uint8arrays)
2. UTF-8 encode each string
3. Hash the concatenation (backend does incremental, client concatenates then hashes - mathematically equivalent)

### Ed25519 Signatures
**Backend:**
- Uses `tweetnacl` for signing/verification
- Private key: hex string (64 chars) or PEM format
- Public key: hex string (64 chars)
- Signature: hex string

**Client:**
- Uses `tweetnacl` for signing/verification
- Private key: Uint8Array (32 bytes)
- Public key: Uint8Array (32 bytes)
- Signature: Uint8Array, converted to hex for transmission

✅ **COMPATIBLE**: Both use tweetnacl, same algorithm

## Issues Found

### 1. ❌ Server Signature Verification (Client Side)
**Location:** `pocketbridge/lib/ws/client.ts:237-242`

**Problem:**
- Client comment says: "Server signs: SHA256(client_ephemeral_pub || server_ephemeral_pub || nonce_c || nonce_s)"
- Backend actually signs: `SHA256(server_identity_pub || server_ephemeral_pub || nonce_c || nonce_s)`
- Client verification uses wrong hash order (missing server_identity_pub, has client_ephemeral_pub instead)

**Impact:**
- Currently disabled (TODO comment), so doesn't break handshake
- When enabled, will fail to verify server signature

**Fix Required:**
```typescript
// Current (WRONG):
const signatureData = await this.hashForSignature(
  this.handshakeState.clientEphemeralKeyPair.publicKeyHex, // ❌ Wrong!
  message.server_ephemeral_pub,
  this.handshakeState.nonceC,
  message.nonce_s
);

// Should be:
const signatureData = await this.hashForSignature(
  message.server_identity_pub, // ✅ Correct
  message.server_ephemeral_pub,
  this.handshakeState.nonceC,
  message.nonce_s
);
```

## Summary

### ✅ Compatible Components
1. Message format and wrapping/unwrapping
2. ECDH key exchange (P-256)
3. Session key derivation (HKDF)
4. hashForSignature implementation (mathematically equivalent)
5. Ed25519 signatures (both use tweetnacl)
6. Client signature verification (backend correctly verifies client signatures)

### ❌ Issues Found
1. **Server signature verification on client side is incorrect** (currently disabled, needs fix before enabling)

### Recommendations
1. Fix server signature verification in client before enabling it
2. Update client comment to reflect correct signature data
3. Consider adding integration tests to verify handshake end-to-end

