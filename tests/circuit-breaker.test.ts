/**
 * Circuit Breaker Tests
 * 
 * Comprehensive tests for circuit breaker functionality
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { CircuitState, databaseCircuitBreaker } from '../src/services/circuit-breaker.js';

// Since CircuitBreaker is not exported, we'll test the exported instance
// and create a testable wrapper if needed
describe('Circuit Breaker', () => {

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    // Reset the circuit breaker
    databaseCircuitBreaker.reset();
  });

  describe('Database Circuit Breaker', () => {
    it('should start in CLOSED state', () => {
      expect(databaseCircuitBreaker.getState()).toBe(CircuitState.CLOSED);
    });

    it('should allow operations when CLOSED', async () => {
      const result = await databaseCircuitBreaker.execute(
        async () => 'success',
        'database'
      );
      expect(result).toBe('success');
    });

    it('should track failures', async () => {
      try {
        await databaseCircuitBreaker.execute(async () => {
          throw new Error('test error');
        }, 'database');
      } catch (error) {
        expect((error as Error).message).toBe('test error');
      }
      expect(databaseCircuitBreaker.getState()).toBe(CircuitState.CLOSED);
    });

    it('should open circuit after threshold failures', async () => {
      // Cause 5 failures (threshold for database circuit breaker)
      for (let i = 0; i < 5; i++) {
        try {
          await databaseCircuitBreaker.execute(async () => {
            throw new Error('test error');
          }, 'database');
        } catch {
          // Expected
        }
      }

      expect(databaseCircuitBreaker.getState()).toBe(CircuitState.OPEN);
    });

    it('should reject requests when OPEN', async () => {
      // Open the circuit
      for (let i = 0; i < 5; i++) {
        try {
          await databaseCircuitBreaker.execute(async () => {
            throw new Error('test error');
          }, 'database');
        } catch {
          // Expected
        }
      }

      // Try to execute when OPEN
      await expect(
        databaseCircuitBreaker.execute(async () => 'success', 'database')
      ).rejects.toThrow('Circuit breaker is OPEN');
    });

    it('should transition to HALF_OPEN after timeout', async () => {
      // Open the circuit
      for (let i = 0; i < 5; i++) {
        try {
          await databaseCircuitBreaker.execute(async () => {
            throw new Error('test error');
          }, 'database');
        } catch {
          // Expected
        }
      }

      expect(databaseCircuitBreaker.getState()).toBe(CircuitState.OPEN);

      // Advance time past timeout (30 seconds)
      vi.advanceTimersByTime(30001);

      // Next execute should transition to HALF_OPEN
      await databaseCircuitBreaker.execute(async () => 'success', 'database');
      expect(databaseCircuitBreaker.getState()).toBe(CircuitState.HALF_OPEN);
    });

    it('should close circuit after success threshold in HALF_OPEN', async () => {
      // Open then transition to HALF_OPEN
      for (let i = 0; i < 5; i++) {
        try {
          await databaseCircuitBreaker.execute(async () => {
            throw new Error('test error');
          }, 'database');
        } catch {
          // Expected
        }
      }

      vi.advanceTimersByTime(30001);

      // Get 2 successes (threshold)
      // State check happens at start of execute, so we need one more call
      await databaseCircuitBreaker.execute(async () => 'success', 'database');
      await databaseCircuitBreaker.execute(async () => 'success', 'database');
      // One more execute to trigger state transition check
      await databaseCircuitBreaker.execute(async () => 'success', 'database');

      expect(databaseCircuitBreaker.getState()).toBe(CircuitState.CLOSED);
    });
  });
});


