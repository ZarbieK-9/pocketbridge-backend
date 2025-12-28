/**
 * Circuit Breaker Service
 *
 * Implements circuit breaker pattern for external service calls
 * Prevents cascading failures by stopping requests when service is down
 */

import { logger } from '../utils/logger.js';

export interface CircuitBreakerConfig {
  failureThreshold: number; // Number of failures before opening
  successThreshold: number; // Number of successes before closing
  timeout: number; // Time in ms before attempting to close circuit
  resetTimeout: number; // Time in ms before resetting failure count
}

export enum CircuitState {
  CLOSED = 'closed', // Normal operation
  OPEN = 'open', // Failing, reject requests
  HALF_OPEN = 'half_open', // Testing if service recovered
}

class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failureCount: number = 0;
  private successCount: number = 0;
  private lastFailureTime: number = 0;
  private config: CircuitBreakerConfig;

  constructor(config: CircuitBreakerConfig) {
    this.config = config;
  }

  /**
   * Execute function with circuit breaker protection
   */
  async execute<T>(fn: () => Promise<T>, serviceName: string): Promise<T> {
    // Check if circuit should transition
    this.updateState(serviceName);

    // If circuit is open, reject immediately
    if (this.state === CircuitState.OPEN) {
      throw new Error(`Circuit breaker is OPEN for ${serviceName}. Service unavailable.`);
    }

    try {
      // Execute the function
      const result = await fn();

      // On success, increment success count
      this.onSuccess(serviceName);
      return result;
    } catch (error) {
      // On failure, increment failure count
      this.onFailure(serviceName, error);
      throw error;
    }
  }

  /**
   * Update circuit state based on current conditions
   */
  private updateState(serviceName: string): void {
    const now = Date.now();

    // If circuit is open and timeout has passed, move to half-open
    if (this.state === CircuitState.OPEN) {
      if (now - this.lastFailureTime >= this.config.timeout) {
        logger.info(`Circuit breaker transitioning to HALF_OPEN for ${serviceName}`);
        this.state = CircuitState.HALF_OPEN;
        this.successCount = 0;
      }
    }

    // If circuit is half-open and we have enough successes, close it
    if (this.state === CircuitState.HALF_OPEN) {
      if (this.successCount >= this.config.successThreshold) {
        logger.info(`Circuit breaker CLOSED for ${serviceName} after recovery`);
        this.state = CircuitState.CLOSED;
        this.failureCount = 0;
        this.successCount = 0;
      }
    }

    // Reset failure count if enough time has passed
    if (now - this.lastFailureTime >= this.config.resetTimeout) {
      this.failureCount = 0;
    }
  }

  /**
   * Handle successful operation
   */
  private onSuccess(serviceName: string): void {
    if (this.state === CircuitState.HALF_OPEN) {
      this.successCount++;
    } else if (this.state === CircuitState.CLOSED) {
      // Reset failure count on success
      this.failureCount = Math.max(0, this.failureCount - 1);
    }
  }

  /**
   * Handle failed operation
   */
  private onFailure(serviceName: string, error: unknown): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    // If we've exceeded threshold, open the circuit
    if (this.failureCount >= this.config.failureThreshold) {
      if (this.state !== CircuitState.OPEN) {
        logger.warn(
          `Circuit breaker OPENED for ${serviceName} after ${this.failureCount} failures`,
          {
            serviceName,
            failureCount: this.failureCount,
            error: error instanceof Error ? error.message : String(error),
          }
        );
        this.state = CircuitState.OPEN;
      }
    }
  }

  /**
   * Get current state
   */
  getState(): CircuitState {
    return this.state;
  }

  /**
   * Get current failure count
   */
  getFailureCount(): number {
    return this.failureCount;
  }

  /**
   * Manually reset circuit breaker
   */
  reset(): void {
    this.state = CircuitState.CLOSED;
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = 0;
  }
}

// Create circuit breakers for different services
export const databaseCircuitBreaker = new CircuitBreaker({
  failureThreshold: 5,
  successThreshold: 2,
  timeout: 30000, // 30 seconds
  resetTimeout: 60000, // 1 minute
});

export const redisCircuitBreaker = new CircuitBreaker({
  failureThreshold: 5,
  successThreshold: 2,
  timeout: 30000, // 30 seconds
  resetTimeout: 60000, // 1 minute
});
