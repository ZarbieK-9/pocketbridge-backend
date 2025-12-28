# Multi-Device Sync Behavior

## Overview
This document explains what happens when a user has multiple devices connected (up to 5) and all devices are syncing simultaneously.

---

## Connection Limits

### Maximum Devices Per User
- **Limit**: 5 concurrent devices per user
- **Enforcement**: `checkConcurrentDeviceLimit()` in `backend/src/middleware/rate-limit.ts`
- **Behavior**: 6th device connection is rejected with error: "Too many devices connected (max 5). Please disconnect another device."

### Example: All 5 Devices Connected
```
User: user_abc123
├── Device 1: laptop (online)
├── Device 2: phone (online)
├── Device 3: tablet (online)
├── Device 4: desktop (online)
└── Device 5: web (online)
```

---

## Event Relay Flow (5 Devices)

### Scenario: All 5 Devices Send Events Simultaneously

When **Device 1** sends an event:
1. Event is **validated** (device_seq, stream_id, etc.)
2. Event is **stored** in PostgreSQL with server-assigned `stream_seq`
3. Event is **relayed** to Devices 2, 3, 4, 5 (4 WebSocket sends)
4. Event is **published** to Redis channels for horizontal scaling

**Total WebSocket sends for 1 event**: 4 (to other devices)

### When All 5 Devices Send Events at Once

If all 5 devices send events **simultaneously**:

```
Device 1 sends Event A → relayed to Devices 2,3,4,5 (4 sends)
Device 2 sends Event B → relayed to Devices 1,3,4,5 (4 sends)
Device 3 sends Event C → relayed to Devices 1,2,4,5 (4 sends)
Device 4 sends Event D → relayed to Devices 1,2,3,5 (4 sends)
Device 5 sends Event E → relayed to Devices 1,2,3,4 (4 sends)
```

**Total WebSocket sends**: 5 events × 4 relays = **20 WebSocket messages**

**Each device receives**: 4 events (from the other 4 devices)

---

## Rate Limiting

### Per-User Event Rate Limit
- **Limit**: 1000 events per minute per user (all devices combined)
- **Enforcement**: `rateLimitUserEvent()` in `backend/src/middleware/rate-limit.ts`
- **Scope**: All devices of the same user share this limit

### Example with 5 Devices
If all 5 devices send events simultaneously:
- Each device can send up to ~200 events/min (1000 ÷ 5 = 200)
- If one device sends 600 events/min, others are limited to 400 total
- **Error**: "Your account is sending too many events. Please slow down."

### Rate Limit Behavior
- **In-memory tracking**: Uses sliding window algorithm
- **Redis fallback**: Falls back to in-memory if Redis unavailable
- **Per-user isolation**: Each user has independent rate limit

---

## Conflict Resolution

### Stream Sequence Conflicts

When multiple devices send events to the **same stream** with the same `stream_seq`:

1. **Conflict Detection**: Server checks if another device already used this `stream_seq` for the same `stream_id`
2. **Last-Write-Wins**: The event with the **later timestamp** wins
3. **Conflict Logging**: Both events are logged in `conflict_log` table for audit

### Example Conflict Scenario
```
Device 1 sends: stream_id="clipboard", stream_seq=5, timestamp=1000
Device 2 sends: stream_id="clipboard", stream_seq=5, timestamp=1001
→ Device 2's event wins (later timestamp)
→ Conflict logged in conflict_log table
```

### Conflict Resolution Code
Location: `backend/src/gateway/event-handler.ts:128-168`

```typescript
// Check for conflicts: same stream_id + stream_seq from different devices
const conflictCheck = await db.pool.query(
  `SELECT device_id, created_at FROM events 
   WHERE stream_id = $1 AND stream_seq = $2 AND device_id != $3
   ORDER BY created_at DESC LIMIT 1`,
  [encryptedEvent.stream_id, streamSeq, encryptedEvent.device_id]
);

if (conflictCheck.rows.length > 0) {
  // Last-write-wins: newer timestamp wins
  const winner = currentTimestamp > existingTimestamp ? 'current' : 'existing';
  // Log conflict for audit trail
}
```

---

## Event Storage

### Database Storage
- **Table**: `events` table in PostgreSQL
- **Conflict Handling**: `ON CONFLICT (event_id) DO NOTHING` (prevents duplicates)
- **Indexing**: Indexed on `device_id`, `user_id`, `stream_id`, `stream_seq`

### Storage Flow (5 Devices)
1. Each event is stored **once** in the database
2. Events are stored **before** relay (ensures persistence)
3. If relay fails, event is still stored (can be replayed later)

---

## Performance Characteristics

### WebSocket Broadcast
- **Method**: Sequential send to each device (not parallel)
- **Code**: `backend/src/services/multi-device-sessions.ts:141-168`
- **Error Handling**: Failed sends are tracked but don't block other sends

```typescript
broadcastToUser(userId, message, excludeDeviceId) {
  for (const [deviceId, _session] of Object.entries(userSessions)) {
    if (excludeDeviceId && deviceId === excludeDeviceId) continue;
    const ws = this.getWebSocket(userId, deviceId);
    if (ws && ws.readyState === ws.OPEN) {
      try {
        ws.send(message);  // Sequential, not parallel
        sent++;
      } catch (error) {
        failed++;
      }
    }
  }
}
```

### Performance Implications
- **Sequential sends**: Each device receives messages one at a time
- **No batching**: Each event is sent individually (not batched)
- **No backpressure**: Failed sends are logged but don't retry

### Potential Bottlenecks
1. **Database writes**: 5 simultaneous events = 5 DB writes
2. **WebSocket sends**: 20 total sends (5 events × 4 relays)
3. **Redis publishes**: 5 events × 2 channels = 10 Redis publishes

---

## Edge Cases and Considerations

### 1. Device Disconnects During Relay
- **Behavior**: Failed sends are tracked (`failed++`) but don't block other sends
- **Recovery**: Disconnected devices can replay missed events when reconnecting

### 2. Network Latency
- **Impact**: Sequential sends mean later devices receive events after earlier ones
- **Ordering**: Events are stored with `created_at` timestamp for ordering

### 3. Rate Limit Exceeded
- **Behavior**: Event is rejected with error message
- **Impact**: Only affects the device that exceeded the limit (per-user limit)

### 4. Stream Sequence Conflicts
- **Frequency**: Rare (only if devices use same `stream_id` and `stream_seq`)
- **Resolution**: Last-write-wins based on timestamp
- **Audit**: All conflicts are logged in `conflict_log` table

### 5. Redis Failure
- **Behavior**: Redis publish failures are logged but don't block event processing
- **Impact**: Events still stored and relayed via WebSocket (degraded mode)

---

## Metrics and Monitoring

### Key Metrics
- `events_relayed_total`: Total events relayed (with status: 'success' or 'no_targets')
- `events_relay_failed_total`: Failed relay attempts
- `event_relay_duration_ms`: Time taken to relay events
- `websocket_connections_active`: Current active connections
- `users_active`: Number of users with active sessions
- `devices_active`: Total number of active devices

### Example Metrics for 5 Devices
```
events_relayed_total{status="success"} = 20 (5 events × 4 relays)
events_relay_failed_total = 0 (if all devices online)
websocket_connections_active = 5
devices_active = 5
```

---

## Recommendations

### Current Implementation
✅ **Strengths**:
- User isolation (devices only see their own user's events)
- Conflict detection and resolution
- Rate limiting prevents abuse
- Events stored before relay (ensures persistence)

⚠️ **Potential Improvements**:
1. **Parallel WebSocket sends**: Use `Promise.all()` for parallel sends (faster)
2. **Event batching**: Batch multiple events into single WebSocket message
3. **Backpressure handling**: Queue events if WebSocket buffer is full
4. **Retry mechanism**: Retry failed WebSocket sends with exponential backoff
5. **Connection pooling**: Optimize database connection pool for concurrent writes

### Performance Optimization Example
```typescript
// Current: Sequential
for (const deviceId of targetDevices) {
  ws.send(message);  // One at a time
}

// Improved: Parallel
await Promise.all(
  targetDevices.map(deviceId => 
    sendToDevice(userId, deviceId, message)
  )
);
```

---

## Summary

### When All 5 Devices Sync Simultaneously:
1. **5 events** are stored in the database
2. **20 WebSocket messages** are sent (5 events × 4 relays each)
3. **10 Redis publishes** occur (5 events × 2 channels each)
4. **Rate limit**: 1000 events/min shared across all devices
5. **Conflicts**: Detected and resolved with last-write-wins
6. **Performance**: Sequential sends (could be optimized to parallel)

### Key Takeaways:
- ✅ System handles 5 devices correctly
- ✅ Events are persisted before relay
- ✅ Rate limiting prevents abuse
- ✅ Conflicts are detected and resolved
- ⚠️ Sequential sends could be optimized to parallel
- ⚠️ No retry mechanism for failed sends

