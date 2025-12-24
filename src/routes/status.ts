/**
 * Connection Status Routes
 * 
 * Provides API endpoints to query connection status
 * NOTE: In production, add authentication/authorization middleware
 */

import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger.js';
import { ValidationError } from '../utils/errors.js';
import type { SessionState, ConnectionStatus } from '../types/index.js';
import { config } from '../config.js';

// Store reference to sessions Map from WebSocket gateway
let sessionsMap: Map<string, SessionState> | null = null;

export function setSessionsMap(sessions: Map<string, SessionState>): void {
  sessionsMap = sessions;
}

const router = Router();

/**
 * Get connection status for a device or user
 * GET /api/connection-status?deviceId=... OR ?userId=...
 */
router.get('/connection-status', async (req: Request, res: Response) => {
  try {
    const { deviceId, userId } = req.query;

    if (!deviceId && !userId) {
      throw new ValidationError('deviceId or userId query parameter is required');
    }

    if (!sessionsMap) {
      logger.warn('Sessions map not initialized');
      return res.status(503).json({ 
        error: 'Service unavailable',
        connected: false,
      });
    }

    let session: SessionState | undefined;

    if (deviceId) {
      // Query by deviceId (exact match)
      session = sessionsMap.get(deviceId as string);
    } else if (userId) {
      // Query by userId (find any device for user)
      session = Array.from(sessionsMap.values()).find(
        s => s.userId === userId as string
      );
    }

    if (!session) {
      return res.json({
        connected: false,
        deviceId: deviceId as string || undefined,
        userId: userId as string || undefined,
        status: 'disconnected' as ConnectionStatus,
      });
    }

    const now = Date.now();
    const sessionAge = now - session.createdAt;
    const expiresAt = session.createdAt + config.websocket.sessionTimeout;

    return res.json({
      connected: true,
      deviceId: session.deviceId,
      userId: session.userId,
      lastSeen: now, // TODO: Track actual lastSeen from heartbeat
      sessionAge,
      expiresAt,
      expiresIn: expiresAt - now, // Milliseconds until expiration
      status: 'connected' as ConnectionStatus,
    });
  } catch (error) {
    logger.error('Failed to get connection status', { query: req.query }, error instanceof Error ? error : new Error(String(error)));
    if (error instanceof ValidationError) {
      res.status(400).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Failed to get connection status' });
    }
  }
});

export default router;

