# PocketBridge Backend

Real-time sync server for PocketBridge - a secure, end-to-end encrypted cross-device synchronization platform.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         PocketBridge Backend                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐        │
│  │   Express    │     │  WebSocket   │     │    Redis     │        │
│  │   REST API   │     │   Gateway    │     │   Pub/Sub    │        │
│  └──────┬───────┘     └──────┬───────┘     └──────┬───────┘        │
│         │                    │                    │                 │
│         ▼                    ▼                    ▼                 │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │                    Service Layer                         │       │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐        │       │
│  │  │   Session   │ │   Device    │ │   Event     │        │       │
│  │  │   Manager   │ │   Pairing   │ │   Handler   │        │       │
│  │  └─────────────┘ └─────────────┘ └─────────────┘        │       │
│  └─────────────────────────────────────────────────────────┘       │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │                    PostgreSQL                            │       │
│  │   users | devices | events | pairing_codes | sessions   │       │
│  └─────────────────────────────────────────────────────────┘       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
src/
├── index.ts              # Application entry point
├── config.ts             # Environment configuration
├── types/                # TypeScript type definitions
├── gateway/              # WebSocket handling
│   ├── websocket.ts      # Main WebSocket gateway
│   ├── handshake.ts      # MTProto-inspired handshake
│   └── event-handler.ts  # Event routing & relay
├── routes/               # REST API endpoints
│   ├── auth.ts           # Authentication
│   ├── pairing.ts        # Device pairing codes
│   ├── devices.ts        # Device management
│   ├── status.ts         # Connection status
│   └── user-profile.ts   # User profiles
├── services/             # Business logic
│   ├── session-store.ts  # Redis session storage
│   ├── device-pairing.ts # Pairing flow
│   ├── device-relay.ts   # Event relay to devices
│   └── metrics.ts        # Prometheus metrics
├── middleware/           # Express middleware
│   ├── rate-limit.ts     # Rate limiting
│   ├── rest-auth.ts      # Request authentication
│   └── security-headers.ts
├── db/                   # Database layer
│   ├── postgres.ts       # PostgreSQL connection
│   ├── redis.ts          # Redis connection
│   └── migrations.ts     # Schema migrations
├── jobs/                 # Background jobs
│   ├── ttl-cleanup.ts    # Expired data cleanup
│   └── data-retention.ts # Data retention policies
└── utils/                # Utilities
    ├── logger.ts         # Structured logging
    ├── errors.ts         # Error classes
    └── validation.ts     # Input validation
```

## Core Flows

### 1. WebSocket Handshake (MTProto-inspired)

```
Client                              Server
  │                                    │
  │─── client_hello ──────────────────>│  (ephemeral ECDH pubkey + nonce)
  │                                    │
  │<── server_hello ───────────────────│  (server ECDH pubkey + nonce + signature)
  │                                    │
  │─── client_auth ───────────────────>│  (user_id + device_id + signature)
  │                                    │
  │<── session_established ────────────│  (session_id + last_ack_seq)
  │                                    │
  │<═══════ Encrypted Channel ════════>│
```

### 2. Device Pairing Flow

```
Device A (existing)                 Server                    Device B (new)
      │                               │                             │
      │── Generate 6-digit code ─────>│                             │
      │── POST /api/pairing/store ───>│                             │
      │                               │                             │
      │                               │<── GET /api/pairing/lookup ─│
      │                               │─── Return pairing data ────>│
      │                               │                             │
      │                               │<── completePairing ─────────│
      │<── pairing_complete ──────────│─── pairing_complete ───────>│
      │                               │                             │
```

### 3. Event Sync Flow

```
Device A                            Server                      Device B
   │                                  │                            │
   │── encrypted_event ──────────────>│                            │
   │   (device_seq, stream_seq)       │                            │
   │                                  │── Store in PostgreSQL      │
   │                                  │                            │
   │                                  │── Publish to Redis ───────>│
   │                                  │                            │
   │<── ack (device_seq) ─────────────│                            │
   │                                  │                            │
   │                                  │─── encrypted_event ───────>│
   │                                  │   (via Redis subscription) │
```

## Key Components

### WebSocket Gateway (`gateway/websocket.ts`)
- Manages WebSocket connections
- Handles handshake protocol
- Routes events between devices
- Maintains session state

### Session Store (`services/session-store.ts`)
- Redis-backed session storage
- Horizontal scaling support
- Session expiration & rotation

### Device Pairing (`services/device-pairing.ts`)
- Temporary pairing code generation
- Cross-device key exchange
- Trust establishment

### Event Handler (`gateway/event-handler.ts`)
- Event validation & routing
- Sequence number tracking
- Replay protection

## Security Features

- **E2E Encryption**: Server never sees plaintext
- **Ed25519 Signatures**: All messages signed
- **ECDH Key Exchange**: Perfect forward secrecy
- **Rate Limiting**: Per-IP and per-device limits
- **Session Rotation**: Automatic key rotation
- **Device Revocation**: Instant access removal

## Database Schema

```sql
-- Core tables
users           -- Ed25519 public keys as user IDs
user_devices    -- Registered devices per user
events          -- Encrypted event metadata
pairing_codes   -- Temporary pairing codes (10 min TTL)
sessions        -- Active WebSocket sessions
```

## Environment Variables

```bash
# Required
DATABASE_URL=postgresql://user:pass@host:5432/db
REDIS_URL=redis://host:6379
SERVER_PUBLIC_KEY_HEX=<64-char-hex>
SERVER_PRIVATE_KEY_HEX=<64-char-hex>

# Optional
PORT=3001
NODE_ENV=production
CORS_ORIGIN=http://localhost:3000
LOG_LEVEL=info
```

## Running

```bash
# Development
npm run dev

# Production
npm run build && npm start

# Docker
docker compose up -d
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/pairing/store` | Store pairing code |
| GET | `/api/pairing/lookup/:code` | Lookup pairing code |
| GET | `/api/devices` | List user devices |
| DELETE | `/api/devices/:id` | Revoke device |
| GET | `/api/connection-status` | Check connection status |
| WS | `/ws` | WebSocket endpoint |
