/**
 * Metrics Endpoint
 * 
 * Exposes Prometheus-compatible metrics
 */

import { Request, Response } from 'express';
import { connectionRateLimiter, eventRateLimiter, handshakeRateLimiter } from '../middleware/rate-limit.js';

/**
 * Get metrics in Prometheus format
 */
export function getMetrics(req: Request, res: Response): void {
  // Set content type
  res.setHeader('Content-Type', 'text/plain; version=0.0.4');

  const metrics: string[] = [];

  // Connection metrics (simplified - in production, use proper metrics library like prom-client)
  // Note: Rate limiter store is private, so we can't access it directly
  // In production, use a proper metrics library that tracks these values
  metrics.push('# HELP pocketbridge_info Server information');
  metrics.push('# TYPE pocketbridge_info gauge');
  metrics.push('pocketbridge_info{version="1.0.0"} 1');

  // Rate limit metrics
  metrics.push('# HELP pocketbridge_rate_limit_hits_total Total rate limit hits');
  metrics.push('# TYPE pocketbridge_rate_limit_hits_total counter');
  // Note: In production, track these properly

  // Event metrics
  metrics.push('# HELP pocketbridge_events_total Total events processed');
  metrics.push('# TYPE pocketbridge_events_total counter');
  // Note: In production, track these properly

  res.send(metrics.join('\n') + '\n');
}

