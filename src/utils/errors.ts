/**
 * Error handling utilities
 *
 * Custom error classes and error response formatting
 */

export class PocketBridgeError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 500,
    public context?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'PocketBridgeError';
  }
}

export class ValidationError extends PocketBridgeError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'VALIDATION_ERROR', 400, context);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends PocketBridgeError {
  constructor(message: string = 'Authentication failed', context?: Record<string, unknown>) {
    super(message, 'AUTH_ERROR', 401, context);
    this.name = 'AuthenticationError';
  }
}

export class NotFoundError extends PocketBridgeError {
  constructor(resource: string, context?: Record<string, unknown>) {
    super(`${resource} not found`, 'NOT_FOUND', 404, context);
    this.name = 'NotFoundError';
  }
}

export class DatabaseError extends PocketBridgeError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'DATABASE_ERROR', 500, context);
    this.name = 'DatabaseError';
  }
}

/**
 * Format error for API response
 * In production, sanitizes error messages to prevent information disclosure
 */
export function formatErrorResponse(error: unknown): {
  error: string;
  code: string;
  statusCode: number;
  context?: Record<string, unknown>;
} {
  const isProduction = process.env.NODE_ENV === 'production';

  if (error instanceof PocketBridgeError) {
    return {
      error: isProduction && error.statusCode >= 500 ? 'An internal error occurred' : error.message,
      code: error.code,
      statusCode: error.statusCode,
      context: isProduction ? undefined : error.context,
    };
  }

  if (error instanceof Error) {
    return {
      error: isProduction ? 'An internal error occurred' : error.message,
      code: 'INTERNAL_ERROR',
      statusCode: 500,
    };
  }

  return {
    error: 'An error occurred',
    code: 'UNKNOWN_ERROR',
    statusCode: 500,
  };
}

/**
 * Error handler middleware for Express
 */
import { Request, Response, NextFunction } from 'express';
import { logger } from './logger.js';
import type { ErrorContext } from './error-context.js';

export function errorHandler(
  error: unknown,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const errorResponse = formatErrorResponse(error);

  // Log full error details (including stack) for debugging, but don't expose in response
  const isProduction = process.env.NODE_ENV === 'production';
  logger.error('Request error', {
    method: req.method,
    path: req.path,
    error: errorResponse.error,
    code: errorResponse.code,
    statusCode: errorResponse.statusCode,
    context: errorResponse.context,
    // Include full error details in logs (not in response)
    fullError: isProduction
      ? undefined
      : error instanceof Error
        ? {
            message: error.message,
            stack: error.stack,
            name: error.name,
          }
        : String(error),
  });

  res.status(errorResponse.statusCode).json(errorResponse);
}
