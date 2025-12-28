/**
 * User Profile Routes
 *
 * APIs for user profile management with signature verification:
 * - Get user profile
 * - Update user profile (requires Ed25519 signature)
 * - Verify user identity before allowing updates
 */

import { Router, Request, Response } from 'express';
import { logger } from '../utils/logger.js';
import { ValidationError } from '../utils/errors.js';
import { verifyEd25519 } from '../crypto/utils.js';
import { sanitizeDeviceName } from '../utils/validation.js';

let database: any = null;

export function setDatabase(db: any): void {
  database = db;
}

const router = Router();

/**
 * Hash data for signature verification
 * Must match client-side hashing
 */
function hashForSignature(...parts: string[]): Buffer {
  const crypto = require('crypto');
  const combined = parts.join('');
  return crypto.createHash('sha256').update(combined, 'utf8').digest();
}

/**
 * Verify user signature for profile updates
 * Signature proves user owns the private key for the user_id (public key)
 */
async function verifyUserSignature(
  userId: string,
  data: string,
  signature: string
): Promise<boolean> {
  try {
    return await verifyEd25519(userId, data, signature);
  } catch (error) {
    logger.error('Signature verification failed', {
      error: error instanceof Error ? error.message : String(error),
    });
    return false;
  }
}

/**
 * Get user profile
 * GET /api/user/profile
 */
router.get('/user/profile', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId as string | undefined;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    // Get or create user profile
    const result = await database.pool.query(
      `SELECT 
        user_id, display_name, email, avatar_url, preferences,
        onboarding_completed, created_at, updated_at, last_seen
       FROM user_profiles
       WHERE user_id = $1`,
      [userId]
    );

    if (result.rows.length === 0) {
      // Create default profile
      await database.pool.query(
        `INSERT INTO user_profiles (user_id, last_seen)
         VALUES ($1, NOW())
         ON CONFLICT (user_id) DO UPDATE SET last_seen = NOW()`,
        [userId]
      );

      return res.json({
        user_id: userId,
        display_name: null,
        email: null,
        avatar_url: null,
        preferences: {},
        onboarding_completed: false,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        last_seen: new Date().toISOString(),
      });
    }

    const profile = result.rows[0];

    // Update last seen
    await database.pool.query(
      `UPDATE user_profiles SET last_seen = NOW() WHERE user_id = $1`,
      [userId]
    );

    res.json({
      user_id: profile.user_id,
      display_name: profile.display_name || null,
      email: profile.email || null,
      avatar_url: profile.avatar_url || null,
      preferences: profile.preferences || {},
      onboarding_completed: profile.onboarding_completed || false,
      created_at: profile.created_at.toISOString(),
      updated_at: profile.updated_at.toISOString(),
      last_seen: profile.last_seen.toISOString(),
    });
  } catch (error) {
    logger.error(
      'Failed to get user profile',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to get user profile' });
  }
});

/**
 * Update user profile
 * POST /api/user/profile
 * Body: { display_name?, email?, preferences?, signature, timestamp }
 * 
 * Security: Requires Ed25519 signature to prove user owns the private key
 * Signature is over: SHA256(user_id || timestamp || JSON.stringify(updates))
 */
router.post('/user/profile', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId as string | undefined;
    const { display_name, email, preferences, signature, timestamp } = req.body;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    // Validate signature is provided
    if (!signature || typeof signature !== 'string') {
      return res.status(400).json({
        error: 'Signature required',
        code: 'SIGNATURE_REQUIRED',
        message: 'Ed25519 signature is required to update profile',
      });
    }

    // Validate timestamp (prevent replay attacks)
    if (!timestamp || typeof timestamp !== 'number') {
      return res.status(400).json({
        error: 'Timestamp required',
        code: 'TIMESTAMP_REQUIRED',
        message: 'Timestamp is required for signature verification',
      });
    }

    // Check timestamp is recent (within 5 minutes)
    // Allow small clock skew (up to 30 seconds in the future)
    const now = Date.now();
    const timestampAge = now - timestamp;
    const clockSkew = timestamp - now; // Positive if client clock is ahead
    
    // Allow up to 30 seconds clock skew (client clock ahead)
    // Reject if timestamp is more than 5 minutes old
    if (clockSkew > 30 * 1000 || timestampAge > 5 * 60 * 1000) {
      return res.status(400).json({
        error: 'Invalid timestamp',
        code: 'TIMESTAMP_EXPIRED',
        message: `Timestamp must be recent (within 5 minutes). Age: ${Math.round(timestampAge / 1000)}s, Skew: ${Math.round(clockSkew / 1000)}s`,
      });
    }

    // Build updates object (only include provided fields)
    const updates: Record<string, any> = {};
    if (display_name !== undefined) {
      if (typeof display_name !== 'string') {
        throw new ValidationError('display_name must be a string');
      }
      // Sanitize display name (similar to device name)
      const sanitized = sanitizeDeviceName(display_name, 100);
      if (!sanitized || sanitized.length === 0) {
        throw new ValidationError('display_name cannot be empty after sanitization');
      }
      updates.display_name = sanitized;
    }

    if (email !== undefined) {
      if (email !== null && typeof email !== 'string') {
        throw new ValidationError('email must be a string or null');
      }
      if (email && !/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$/i.test(email)) {
        throw new ValidationError('Invalid email format');
      }
      updates.email = email || null;
    }

    if (preferences !== undefined) {
      if (typeof preferences !== 'object' || preferences === null || Array.isArray(preferences)) {
        throw new ValidationError('preferences must be an object');
      }
      // Validate preferences structure
      const validPreferences: Record<string, any> = {};
      if (preferences.theme && ['light', 'dark', 'auto'].includes(preferences.theme)) {
        validPreferences.theme = preferences.theme;
      }
      if (typeof preferences.notifications === 'boolean') {
        validPreferences.notifications = preferences.notifications;
      }
      if (typeof preferences.autoSync === 'boolean') {
        validPreferences.autoSync = preferences.autoSync;
      }
      updates.preferences = validPreferences;
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid updates provided' });
    }

    // Verify signature
    // Signature data: SHA256(user_id || timestamp || JSON.stringify(updates))
    const signatureData = hashForSignature(
      userId,
      timestamp.toString(),
      JSON.stringify(updates)
    );

    const isValid = await verifyUserSignature(userId, signatureData.toString('hex'), signature);

    if (!isValid) {
      logger.warn('Invalid signature for profile update', {
        userId: userId.substring(0, 16) + '...',
        ip: req.ip,
      });
      return res.status(403).json({
        error: 'Invalid signature',
        code: 'INVALID_SIGNATURE',
        message: 'Signature verification failed. You must prove ownership of the private key.',
      });
    }

    // Build SQL update query dynamically
    const updateFields: string[] = [];
    const updateValues: any[] = [];
    let paramIndex = 1;

    if (updates.display_name !== undefined) {
      updateFields.push(`display_name = $${paramIndex++}`);
      updateValues.push(updates.display_name);
    }
    if (updates.email !== undefined) {
      updateFields.push(`email = $${paramIndex++}`);
      updateValues.push(updates.email);
    }
    if (updates.preferences !== undefined) {
      updateFields.push(`preferences = $${paramIndex++}::jsonb`);
      updateValues.push(JSON.stringify(updates.preferences));
    }

    updateValues.push(userId);

    // Update profile
    const result = await database.pool.query(
      `UPDATE user_profiles
       SET ${updateFields.join(', ')}, last_seen = NOW()
       WHERE user_id = $${paramIndex}
       RETURNING *`,
      updateValues
    );

    // If no profile exists, create it
    if (result.rows.length === 0) {
      const insertResult = await database.pool.query(
        `INSERT INTO user_profiles (user_id, display_name, email, preferences, last_seen)
         VALUES ($1, $2, $3, $4::jsonb, NOW())
         RETURNING *`,
        [
          userId,
          updates.display_name || null,
          updates.email || null,
          JSON.stringify(updates.preferences || {}),
        ]
      );

      const profile = insertResult.rows[0];
      return res.json({
        success: true,
        profile: {
          user_id: profile.user_id,
          display_name: profile.display_name,
          email: profile.email,
          avatar_url: profile.avatar_url,
          preferences: profile.preferences || {},
          onboarding_completed: profile.onboarding_completed,
          created_at: profile.created_at.toISOString(),
          updated_at: profile.updated_at.toISOString(),
          last_seen: profile.last_seen.toISOString(),
        },
      });
    }

    const profile = result.rows[0];

    logger.info('User profile updated', {
      userId: userId.substring(0, 16) + '...',
      updatedFields: Object.keys(updates),
    });

    res.json({
      success: true,
      profile: {
        user_id: profile.user_id,
        display_name: profile.display_name,
        email: profile.email,
        avatar_url: profile.avatar_url,
        preferences: profile.preferences || {},
        onboarding_completed: profile.onboarding_completed,
        created_at: profile.created_at.toISOString(),
        updated_at: profile.updated_at.toISOString(),
        last_seen: profile.last_seen.toISOString(),
      },
    });
  } catch (error) {
    if (error instanceof ValidationError) {
      return res.status(400).json({ error: error.message });
    }

    logger.error(
      'Failed to update user profile',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to update user profile' });
  }
});

/**
 * Mark onboarding as completed
 * POST /api/user/profile/onboarding-complete
 * Requires signature to prevent unauthorized completion
 */
router.post('/user/profile/onboarding-complete', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).userId as string | undefined;
    const { signature, timestamp } = req.body;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!database) {
      return res.status(503).json({ error: 'Database not initialized' });
    }

    // Verify signature
    if (!signature || !timestamp) {
      return res.status(400).json({
        error: 'Signature and timestamp required',
        code: 'SIGNATURE_REQUIRED',
      });
    }

    // Check timestamp (allow up to 30 seconds clock skew)
    const now = Date.now();
    const timestampAge = now - timestamp;
    const clockSkew = timestamp - now; // Positive if client clock is ahead
    
    // Allow up to 30 seconds clock skew (client clock ahead)
    // Reject if timestamp is more than 5 minutes old
    if (clockSkew > 30 * 1000 || timestampAge > 5 * 60 * 1000) {
      return res.status(400).json({
        error: 'Invalid timestamp',
        code: 'TIMESTAMP_EXPIRED',
        message: `Timestamp must be recent. Age: ${Math.round(timestampAge / 1000)}s, Skew: ${Math.round(clockSkew / 1000)}s`,
      });
    }

    // Verify signature: SHA256(user_id || timestamp || "onboarding_complete")
    const signatureData = hashForSignature(userId, timestamp.toString(), 'onboarding_complete');
    const isValid = await verifyUserSignature(userId, signatureData.toString('hex'), signature);

    if (!isValid) {
      return res.status(403).json({
        error: 'Invalid signature',
        code: 'INVALID_SIGNATURE',
      });
    }

    // Update profile
    await database.pool.query(
      `INSERT INTO user_profiles (user_id, onboarding_completed, last_seen)
       VALUES ($1, TRUE, NOW())
       ON CONFLICT (user_id)
       DO UPDATE SET onboarding_completed = TRUE, last_seen = NOW()`,
      [userId]
    );

    logger.info('Onboarding marked as completed', {
      userId: userId.substring(0, 16) + '...',
    });

    res.json({ success: true });
  } catch (error) {
    logger.error(
      'Failed to mark onboarding as complete',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).json({ error: 'Failed to mark onboarding as complete' });
  }
});

export default router;

