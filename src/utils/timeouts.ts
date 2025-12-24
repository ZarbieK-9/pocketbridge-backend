/**
 * Timeout Utilities
 * 
 * Adds timeouts to async operations to prevent hanging
 */

/**
 * Wrap promise with timeout
 */
export function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  errorMessage: string = 'Operation timed out'
): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(errorMessage)), timeoutMs)
    ),
  ]);
}

// Timeout constants
export const TIMEOUTS = {
  DATABASE_QUERY: 5000, // 5 seconds
  REDIS_OPERATION: 2000, // 2 seconds
  HANDSHAKE: 30000, // 30 seconds
  EVENT_PROCESSING: 10000, // 10 seconds
} as const;















