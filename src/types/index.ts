/**
 * TypeScript types for PocketBridge Backend
 */

/**
 * Connection status type (matches frontend)
 */
export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

/**
 * EncryptedEvent - Universal event envelope
 * Server sees metadata only, never decrypts payloads
 */
export interface EncryptedEvent {
  event_id: string; // UUIDv7
  user_id: string; // Ed25519 public key (hex)
  device_id: string; // UUIDv4
  device_seq: number; // Monotonic per device
  stream_id: string; // Feature-specific stream
  stream_seq: number; // Assigned by server per stream
  type: string; // Event type
  encrypted_payload: string; // Base64-encoded AES-GCM ciphertext
  ttl?: number; // Optional TTL (Unix timestamp)
  created_at?: number; // Server-assigned timestamp
}

/**
 * WebSocket message types
 */
export interface WSMessage {
  type: string;
  payload: unknown;
}

/**
 * Handshake messages
 */
export interface ClientHello {
  type: 'client_hello';
  client_ephemeral_pub: string; // P-256 public key (hex)
  nonce_c: string; // 32 bytes hex
}

export interface ServerHello {
  type: 'server_hello';
  server_ephemeral_pub: string; // P-256 public key (hex)
  server_identity_pub: string; // Server Ed25519 public key (hex)
  server_signature: string; // Ed25519 signature (hex)
  nonce_s: string; // 32 bytes hex
}

export interface ClientAuth {
  type: 'client_auth';
  user_id: string; // Ed25519 public key (hex)
  device_id: string; // UUIDv4
  client_signature: string; // Ed25519 signature (hex)
  nonce_c2: string; // 32 bytes hex
  device_name?: string; // Optional device name
  device_type?: 'mobile' | 'desktop' | 'web'; // Optional device type
}

export interface SessionEstablished {
  type: 'session_established';
  device_id: string;
  last_ack_device_seq: number;
  expires_at: number; // Unix timestamp (milliseconds) when session expires
}

/**
 * Session state (stored per WebSocket connection)
 */
export interface SessionState {
  userId: string;
  deviceId: string;
  sessionKeys: {
    clientKey: Buffer;
    serverKey: Buffer;
  };
  lastAckDeviceSeq: number;
  createdAt: number;
}

/**
 * Replay request with pagination support
 */
export interface ReplayRequest {
  type: 'replay_request';
  last_ack_device_seq: number;
  limit?: number; // Number of events per page (default: 100, max: 1000)
  continuation_token?: string; // Token for pagination (base64 encoded last device_seq)
}

/**
 * Replay response with pagination
 */
export interface ReplayResponse {
  type: 'replay_response';
  events: EncryptedEvent[];
  has_more: boolean; // Whether more events are available
  continuation_token?: string; // Token to request next page (if has_more is true)
  total_events?: number; // Total number of events available (only on first page)
  page_size: number; // Number of events in this response
}

/**
 * Device information
 */
export interface DeviceInfo {
  device_id: string;
  device_name?: string;
  device_type?: 'mobile' | 'desktop' | 'web';
  device_os?: string;
  is_online: boolean;
  last_seen: number; // Unix timestamp
  registered_at?: number; // Unix timestamp
  ip_address?: string;
}

/**
 * Multi-device presence message
 */
export interface DevicePresence {
  type: 'device_presence';
  user_id: string;
  online_devices: DeviceInfo[];
  timestamp: number;
}

/**
 * Device went online/offline
 */
export interface DeviceStatusChange {
  type: 'device_status_changed';
  device_id: string;
  device_name?: string;
  is_online: boolean;
  timestamp: number;
}

/**
 * Session expiration warning
 */
export interface SessionExpiringWarning {
  type: 'session_expiring_soon';
  expires_in_seconds: number;
  expires_at: number; // Unix timestamp
}
