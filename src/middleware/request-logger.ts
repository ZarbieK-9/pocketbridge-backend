/**
 * Request logging middleware
 *
 * Logs all HTTP requests with structured logging
 */

import { Request, Response, NextFunction } from 'express';
import pinoHttp from 'pino-http';
import { logger } from '../utils/logger.js';

export const requestLogger = pinoHttp({
  logger,
  customLogLevel: (req: Request, res: Response, error?: Error) => {
    if (error) return 'error';
    if (res.statusCode >= 500) return 'error';
    if (res.statusCode >= 400) return 'warn';
    return 'info';
  },
  customSuccessMessage: (req: Request, res: Response) => {
    return `${req.method} ${req.url} completed`;
  },
  customErrorMessage: (req: Request, res: Response, err?: Error) => {
    return `${req.method} ${req.url} errored`;
  },
  customProps: (req: Request) => {
    return {
      ip: req.ip || req.socket.remoteAddress,
      userAgent: req.get('user-agent'),
      requestId: (req as any).requestId,
      apiVersion: (req as any).apiVersion,
      userId: (req as any).userId
        ? ((req as any).userId as string).substring(0, 16) + '...'
        : undefined,
    };
  },
});
