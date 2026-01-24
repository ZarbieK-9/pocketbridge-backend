/**
 * Device Management Routes
 *
 * APIs for multi-device management:
 * - List user's devices
 * - Get device details and online status
 * - Rename devices
 * - Remove/revoke devices
 * - Get real-time presence
 */

import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger.js';
import { ValidationError } from '../utils/errors.js';
import { sanitizeDeviceName } from '../utils/validation.js';
import type { SessionState, DeviceInfo } from '../types/index.js';
import type { Database } from '../db/postgres.js';
import { config } from '../config.js';

// Store reference to sessions Map from WebSocket gateway
let sessionsMap: Map<string, SessionState> | null = null;
let database: Database | null = null;

export function setSessionsMap(sessions: Map<string, SessionState>): void {
  sessionsMap = sessions;
}

export function setDatabase(db: Database): void {
  database = db;
}

const router = Router();

/**
 * Get all devices for current user
 * GET /api/devices
 */
router.get('/devices', async (req: Request, res: Response) => {
  try {
    // In production, extract user_id from JWT token
    // For now, query from authenticated session
    const userId = (req as any).userId as string | undefined;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized: No user context' });
    }

    // Validate user ID format (Ed25519 public key: 64 hex characters)
    if (!/^[0-9a-f]{64}$/i.test(userId)) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    // Update user activity (create user if doesn't exist)
    // Handle case where last_activity column might not exist (migration not run)
    try {
      await database.pool.query(
        `INSERT INTO users (user_id, last_activity) VALUES ($1, NOW())
         ON CONFLICT (user_id) DO UPDATE SET last_activity = NOW()`,
        [userId]
      );
    } catch (activityError: any) {
      // If last_activity column doesn't exist, try without it and set created_at
      if (activityError?.code === '42703') {
        logger.warn('last_activity column not found, using fallback query', { userId });
        await database.pool.query(
          `INSERT INTO users (user_id, created_at) VALUES ($1, NOW())
           ON CONFLICT (user_id) DO NOTHING`,
          [userId]
        );
      } else {
        // Re-throw if it's a different error
        throw activityError;
      }
    }

    // Get user's display name from user_profiles
    let userDisplayName: string | null = null;
    try {
      const profileResult = await database.pool.query(
        `SELECT display_name FROM user_profiles WHERE user_id = $1`,
        [userId]
      );
      if (profileResult.rows.length > 0 && profileResult.rows[0].display_name) {
        userDisplayName = profileResult.rows[0].display_name;
      }
    } catch (profileError) {
      logger.warn('Failed to fetch user profile for display name', { userId, error: profileError });
    }

    // Get all devices for user (from devices table)
    let result;
    try {
      result = await database.pool.query(
        `SELECT
          device_id, device_name, device_type, device_os,
          last_seen, registered_at, ip_address, is_online
         FROM user_devices
         WHERE user_id = $1
         ORDER BY is_online DESC, last_seen DESC`,
        [userId]
      );
    } catch (queryError) {
      const errorContext = {
        userId,
        error: queryError instanceof Error ? queryError.message : String(queryError),
        stack: queryError instanceof Error ? queryError.stack : undefined,
      };
      logger.error(errorContext, 'Database query failed in get devices');
      console.error('[ERROR] Database query failed in get devices:', {
        ...errorContext,
        fullError: queryError,
      });
      throw queryError;
    }

    const devices: DeviceInfo[] = result.rows.map((row: any) => {
      try {
        // Convert device_id to string for sessionsMap lookup (sessionsMap uses string keys)
        const deviceIdStr = typeof row.device_id === 'string' 
          ? row.device_id 
          : row.device_id?.toString() || String(row.device_id);
        
        // Safely convert last_seen to timestamp
        let lastSeenTimestamp: number;
        try {
          lastSeenTimestamp = row.last_seen 
            ? new Date(row.last_seen).getTime() 
            : Date.now();
          // Validate timestamp is a valid number
          if (isNaN(lastSeenTimestamp)) {
            logger.warn('Invalid last_seen timestamp, using current time', {
              deviceId: deviceIdStr,
              lastSeen: row.last_seen,
            });
            lastSeenTimestamp = Date.now();
          }
        } catch {
          lastSeenTimestamp = Date.now();
        }
        
        // Validate device_type is one of the allowed values
        let deviceType: 'mobile' | 'desktop' | 'web' | undefined = undefined;
        if (row.device_type) {
          if (['mobile', 'desktop', 'web'].includes(row.device_type)) {
            deviceType = row.device_type as 'mobile' | 'desktop' | 'web';
          } else {
            logger.warn('Invalid device_type, setting to undefined', {
              deviceId: deviceIdStr,
              deviceType: row.device_type,
            });
          }
        }
        
        // Safely convert registered_at to timestamp
        let registeredAtTimestamp: number | undefined = undefined;
        try {
          if (row.registered_at) {
            registeredAtTimestamp = new Date(row.registered_at).getTime();
            if (isNaN(registeredAtTimestamp)) {
              registeredAtTimestamp = undefined;
            }
          }
        } catch {
          registeredAtTimestamp = undefined;
        }

        // Determine online status: Check sessionsMap first (live connection),
        // then fall back to database value for devices that have connected but
        // WebSocket might be momentarily disconnected or handshake not yet complete
        let isOnline = false;
        if (sessionsMap && sessionsMap.has(deviceIdStr)) {
          // Device has active WebSocket connection
          isOnline = true;
        } else if (row.is_online === true) {
          // Device was marked online in database (from handshake or last connection)
          // This handles cases where device is mid-handshake or just connected
          isOnline = true;
        }

        return {
          device_id: deviceIdStr,
          device_name: row.device_name || undefined,
          device_type: deviceType,
          device_os: row.device_os || undefined,
          is_online: isOnline,
          last_seen: lastSeenTimestamp,
          registered_at: registeredAtTimestamp,
          ip_address: row.ip_address ? String(row.ip_address) : undefined,
        };
      } catch (mapError) {
        const errorContext = {
          row: JSON.stringify(row).substring(0, 200),
          error: mapError instanceof Error ? mapError.message : String(mapError),
          stack: mapError instanceof Error ? mapError.stack : undefined,
        };
        logger.error(errorContext, 'Error mapping device row');
        console.error('[ERROR] Error mapping device row:', {
          ...errorContext,
          fullError: mapError,
        });
        // Return a minimal valid device object to prevent complete failure
        return {
          device_id: String(row.device_id || 'unknown'),
          is_online: false,
          last_seen: Date.now(),
        };
      }
    });

    // Handle empty state
    const is_empty = devices.length === 0;
    
    // Build response object, ensuring all values are JSON-serializable
    const response: {
      devices: DeviceInfo[];
      count: number;
      is_empty: boolean;
      message?: string;
      user_display_name?: string;
      user_id: string;
    } = {
      devices: devices.filter(d => d !== null && d !== undefined), // Remove any null/undefined devices
      count: devices.length,
      is_empty,
      user_id: userId,
      ...(userDisplayName && { user_display_name: userDisplayName }),
    };
    
    if (is_empty) {
      response.message = 'No devices connected. Connect a device to start syncing.';
    }
    
    // Validate response is serializable before sending
    try {
      JSON.stringify(response);
    } catch (serializeError) {
      const errorContext = {
        error: serializeError instanceof Error ? serializeError.message : String(serializeError),
        stack: serializeError instanceof Error ? serializeError.stack : undefined,
        devicesCount: devices.length,
      };
      logger.error(errorContext, 'Response serialization failed');
      console.error('[ERROR] Response serialization failed:', {
        ...errorContext,
        fullError: serializeError,
      });
      throw new Error('Failed to serialize response');
    }
    
    return res.json(response);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;
    const errorName = error instanceof Error ? error.name : typeof error;
    
    // Log full error details - use console.error as fallback to ensure visibility
    const errorContext = {
      userId: (req as any).userId,
      error: errorMessage,
      errorName,
      stack: errorStack,
      path: req.path,
      method: req.method,
      hasDatabase: !!database,
      hasSessionsMap: !!sessionsMap,
    };
    
    // Log with both logger and console.error to ensure visibility
    logger.error(errorContext, 'Failed to get devices');
    console.error('[ERROR] Failed to get devices:', {
      ...errorContext,
      fullError: error,
    });
    
    // Return error response with details in development
    const isDevelopment = process.env.NODE_ENV === 'development';
    res.status(500).json({ 
      error: 'Failed to get devices',
      ...(isDevelopment && {
        message: errorMessage,
        errorName,
        stack: errorStack,
      }),
    });
  }
});

/**
 * Get device details
 * GET /api/devices/:deviceId
 */
router.get('/devices/:deviceId', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId as string | undefined;
    const { deviceId } = req.params;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    // Update user activity (create user if doesn't exist)
    await database.pool.query(
      `INSERT INTO users (user_id, last_activity) VALUES ($1, NOW())
       ON CONFLICT (user_id) DO UPDATE SET last_activity = NOW()`,
      [userId]
    );

    const result = await database.pool.query(
      `SELECT * FROM user_devices
       WHERE device_id = $1::uuid AND user_id = $2`,
      [deviceId, userId]
    );

    if (result.rows.length === 0) {
      // Edge case: Device doesn't exist or doesn't belong to user
      // This is normal for new devices that haven't connected yet
      return res.status(404).json({
        error: 'Device not found',
        is_empty: true,
        message:
          'The requested device was not found or does not belong to you. Connect the device to register it.',
      });
    }

    const device = result.rows[0];
    // Convert device_id to string for sessionsMap lookup
    const deviceIdStr = typeof device.device_id === 'string' 
      ? device.device_id 
      : device.device_id?.toString() || String(device.device_id);
    
    // Determine online status: Check sessionsMap first (live connection),
    // then fall back to database value
    let isOnline = false;
    if (sessionsMap && sessionsMap.has(deviceIdStr)) {
      // Device has active WebSocket connection
      isOnline = true;
    } else if (device.is_online === true) {
      // Device was marked online in database
      isOnline = true;
    }
    
    res.json({
      device_id: deviceIdStr,
      device_name: device.device_name || undefined,
      device_type: device.device_type || undefined,
      device_os: device.device_os || undefined,
      is_online: isOnline,
      last_seen: new Date(device.last_seen).getTime(),
      registered_at: new Date(device.registered_at).getTime(),
    });
  } catch (error) {
    logger.error(
      'Failed to get device',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to get device' });
  }
});

/**
 * Rename device
 * POST /api/devices/:deviceId/rename
 */
router.post('/devices/:deviceId/rename', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId as string | undefined;
    const { deviceId } = req.params;
    const { device_name } = req.body;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!device_name || typeof device_name !== 'string' || device_name.length === 0) {
      throw new ValidationError('Device name must be 1-50 characters');
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    // Update user activity (create user if doesn't exist)
    await database.pool.query(
      `INSERT INTO users (user_id, last_activity) VALUES ($1, NOW())
       ON CONFLICT (user_id) DO UPDATE SET last_activity = NOW()`,
      [userId]
    );

    // Sanitize device name (remove invalid UTF-8, truncate to 50 chars)
    const sanitizedName = sanitizeDeviceName(device_name, 50);
    if (sanitizedName.length === 0) {
      throw new ValidationError('Device name contains invalid characters');
    }

    // Verify device belongs to user
    const checkResult = await database.pool.query(
      `SELECT user_id FROM user_devices WHERE device_id = $1::uuid`,
      [deviceId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }

    if (checkResult.rows[0].user_id !== userId) {
      return res.status(403).json({ error: "Cannot rename another user's device" });
    }

    // Check if another device with the same name already exists for this user
    const duplicateCheck = await database.pool.query(
      `SELECT device_id FROM user_devices 
       WHERE user_id = $1 
       AND device_name = $2 
       AND device_id != $3::uuid`,
      [userId, sanitizedName, deviceId]
    );

    if (duplicateCheck.rows.length > 0) {
      throw new ValidationError('Another device with this name already exists');
    }

    // Update device name
    const updateResult = await database.pool.query(
      `UPDATE user_devices
       SET device_name = $1
       WHERE device_id = $2::uuid
       RETURNING *`,
      [sanitizedName, deviceId]
    );

    logger.info('Device renamed', { userId, deviceId, device_name });

    res.json({
      success: true,
      device_id: updateResult.rows[0].device_id,
      device_name: updateResult.rows[0].device_name,
    });
  } catch (error) {
    logger.error(
      'Failed to rename device',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    if (error instanceof ValidationError) {
      res.status(400).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Failed to rename device' });
    }
  }
});

/**
 * Remove/revoke device
 * DELETE /api/devices/:deviceId
 */
router.delete('/devices/:deviceId', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId as string | undefined;
    const { deviceId } = req.params;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    // Update user activity (create user if doesn't exist)
    await database.pool.query(
      `INSERT INTO users (user_id, last_activity) VALUES ($1, NOW())
       ON CONFLICT (user_id) DO UPDATE SET last_activity = NOW()`,
      [userId]
    );

    // Verify device belongs to user
    const checkResult = await database.pool.query(
      `SELECT user_id FROM user_devices WHERE device_id = $1::uuid`,
      [deviceId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }

    if (checkResult.rows[0].user_id !== userId) {
      return res.status(403).json({ error: "Cannot remove another user's device" });
    }

    // Hard delete device; events referencing it will cascade if configured
    await database.pool.query(
      `DELETE FROM user_devices WHERE device_id = $1::uuid AND user_id = $2`,
      [deviceId, userId]
    );

    logger.info('Device removed', { userId, deviceId });

    res.json({
      success: true,
      message: `Device ${deviceId} has been removed`,
    });
  } catch (error) {
    logger.error(
      'Failed to remove device',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to remove device' });
  }
});

/**
 * Get real-time presence (online/offline status of all user's devices)
 * GET /api/presence
 *
 * Could also be WebSocket for real-time:
 * - Client: { type: 'subscribe_presence' }
 * - Server: { type: 'presence_update', online_devices: [...] }
 */
router.get('/presence', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId as string | undefined;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    // Update user activity (create user if doesn't exist)
    await database.pool.query(
      `INSERT INTO users (user_id, last_activity) VALUES ($1, NOW())
       ON CONFLICT (user_id) DO UPDATE SET last_activity = NOW()`,
      [userId]
    );

    const result = await database.pool.query(
      `SELECT device_id, device_name, last_seen, is_online
       FROM user_devices
       WHERE user_id = $1
       ORDER BY last_seen DESC`,
      [userId]
    );

    const devices = result.rows.map((row: any) => {
      // Determine online status: Check sessionsMap first (live connection),
      // then fall back to database value
      let isOnline = false;
      if (sessionsMap && sessionsMap.has(row.device_id)) {
        // Device has active WebSocket connection
        isOnline = true;
      } else if (row.is_online === true) {
        // Device was marked online in database
        isOnline = true;
      }
      
      return {
        device_id: row.device_id,
        device_name: row.device_name,
        is_online: isOnline,
        last_seen: new Date(row.last_seen).getTime(),
      };
    });

    // Handle empty state
    const is_empty = devices.length === 0;
    res.json({
      user_id: userId,
      devices,
      online_count: devices.filter((d: any) => d.is_online).length,
      total_count: devices.length,
      is_empty,
      message: is_empty ? 'No devices found. Connect your first device to get started.' : undefined,
    });
  } catch (error) {
    logger.error(
      'Failed to get presence',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to get presence' });
  }
});

export default router;
