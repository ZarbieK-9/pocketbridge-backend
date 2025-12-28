# Handshake Timing and Race Condition Analysis

## Overview
This document describes the timing guarantees and race condition protections implemented in the handshake protocol.

## Race Conditions Fixed

### 1. Backend: Concurrent Message Processing
**Problem:** Multiple handshake messages could arrive concurrently and process in parallel, causing:
- State corruption
- Duplicate processing
- Invalid state transitions

**Solution:** Message queue with serialization
- Each WebSocket connection has a message queue
- Messages are processed one at a time, serially
- Processing flag prevents concurrent execution
- Queue is cleared when handshake completes

**Implementation:**
```typescript
// Message queue per connection
const messageQueues = new WeakMap<WebSocket, Array<...>>();

// Serialized processing
async function processHandshakeQueue(...) {
  if (state.processing) return; // Guard
  state.processing = true;
  try {
    // Process messages one at a time
  } finally {
    state.processing = false;
  }
}
```

### 2. Backend: Timeout Race Condition
**Problem:** Handshake timeout could fire after handshake completed but before timeout was cleared.

**Solution:** Triple-check in timeout handler
- Check timeout still exists and matches
- Check handshake not completed
- Check session not established
- Clear timeout immediately when handshake completes

**Implementation:**
```typescript
// Set timeout
const handshakeTimeout = setTimeout(() => {
  const currentTimeout = handshakeTimeouts.get(ws);
  const currentSessionState = (ws as any)._sessionState;
  if (
    currentTimeout === handshakeTimeout &&
    !handshakeComplete &&
    !sessionState &&
    !currentSessionState
  ) {
    // Only timeout if all checks pass
  }
}, 30000);

// Clear timeout FIRST when handshake completes
const timeout = handshakeTimeouts.get(ws);
if (timeout) {
  clearTimeout(timeout);
  handshakeTimeouts.delete(ws);
}
```

### 3. Backend: State Transition Race Condition
**Problem:** State could be checked, then modified concurrently before use.

**Solution:** Atomic state updates and re-validation
- State is re-checked after queue processing
- All state fields updated atomically (in one operation)
- State transitions are guarded by step validation

**Implementation:**
```typescript
// Re-check state after queue processing
const currentState = handshakeStates.get(ws);
if (!currentState || currentState.step !== 'client_hello') {
  return { success: false, error: 'Invalid state' };
}

// Atomic state update
state.step = 'server_hello';
state.clientEphemeralPub = message.client_ephemeral_pub;
state.serverEphemeralKeypair = serverEphemeralKeypair;
// ... all fields updated together
```

### 4. Client: Concurrent Server Hello Processing
**Problem:** Multiple `server_hello` messages could arrive and process concurrently.

**Solution:** Processing guard flag
- Check if already processing before starting
- Set flag before async operations
- Clear flag in finally block
- Ignore duplicate messages if state already set

**Implementation:**
```typescript
if (this.handshakeState.processing) {
  console.warn('Server hello already being processed, ignoring duplicate');
  return;
}

this.handshakeState.processing = true;
try {
  // Process server hello
} finally {
  this.handshakeState.processing = false;
}
```

### 5. Client: Duplicate Client Auth Sends
**Problem:** `sendClientAuth` could be called multiple times concurrently.

**Solution:** Atomic flag check and set
- Check flag before any async operations
- Set flag immediately (atomically)
- Return early if already sent

**Implementation:**
```typescript
// Atomic check and set (before any async operations)
if (this.handshakeState.clientAuthSent) {
  return; // Already sent
}
this.handshakeState.clientAuthSent = true;

// Now safe to do async operations
```

### 6. Client: State Update Race Condition
**Problem:** Server values could be read, then modified before use.

**Solution:** Store values immediately
- Store `serverEphemeralPub` and `nonceS` immediately when received
- Validate state before processing
- Check for duplicates before storing

**Implementation:**
```typescript
// Store immediately to prevent race conditions
if (this.handshakeState.serverEphemeralPub || this.handshakeState.nonceS) {
  console.error('Received duplicate server_hello. Ignoring.');
  return;
}

this.handshakeState.serverEphemeralPub = message.server_ephemeral_pub;
this.handshakeState.nonceS = message.nonce_s;
```

## Timing Guarantees

### Handshake Timeout
- **Duration:** 30 seconds from connection
- **Behavior:** Connection closed if handshake not completed
- **Race Protection:** Triple-check before closing

### Message Processing
- **Order:** Messages processed serially per connection
- **Guarantee:** No concurrent processing of handshake messages
- **Queue:** Messages queued if processing in progress

### State Transitions
- **Atomic:** State transitions are atomic (all fields updated together)
- **Guarded:** State transitions validated before execution
- **Idempotent:** Duplicate messages are safely ignored

## Thread Safety Model

### Backend
1. **Per-Connection Serialization:** Each WebSocket connection has its own message queue
2. **Processing Guard:** `processing` flag prevents concurrent execution
3. **State Isolation:** WeakMap ensures state is per-connection
4. **Timeout Safety:** Timeout cleared before session establishment

### Client
1. **Processing Guard:** `processing` flag prevents concurrent message handling
2. **Atomic Flags:** `clientAuthSent` flag set before async operations
3. **Immediate Storage:** Server values stored immediately to prevent races
4. **Duplicate Detection:** State checked before processing

## Best Practices

1. **Always clear timeouts first** when handshake completes
2. **Set flags before async operations** to prevent races
3. **Re-validate state** after queue processing
4. **Use atomic updates** for state transitions
5. **Check for duplicates** before processing messages
6. **Use finally blocks** to clear processing flags

## Testing Recommendations

1. **Concurrent Message Test:** Send multiple handshake messages rapidly
2. **Timeout Race Test:** Complete handshake just before timeout
3. **Duplicate Message Test:** Send duplicate server_hello messages
4. **State Corruption Test:** Rapid connect/disconnect cycles
5. **Network Delay Test:** Simulate network delays during handshake

## Performance Impact

- **Message Queue:** Minimal overhead (only during handshake)
- **Processing Guard:** Single boolean check per message
- **State Validation:** O(1) operations
- **Overall:** Negligible performance impact, significant safety improvement

