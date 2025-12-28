/**
 * Metrics Endpoint
 *
 * Exposes Prometheus-compatible metrics
 */

import { Request, Response } from 'express';
import { metrics } from '../services/metrics.js';
import { logger } from '../utils/logger.js';

/**
 * Get metrics in Prometheus format
 */
export function getMetrics(req: Request, res: Response): void {
  try {
    // Set content type
    res.setHeader('Content-Type', 'text/plain; version=0.0.4');

    const lines: string[] = [];

    // Add Prometheus format headers
    lines.push('# HELP pocketbridge_info Server information');
    lines.push('# TYPE pocketbridge_info gauge');
    lines.push('pocketbridge_info{version="1.0.0"} 1');
    lines.push('');

    // Export all metrics
    const exported = metrics.exportPrometheus();
    if (exported) {
      lines.push(exported);
    }

    res.send(lines.join('\n'));
  } catch (error) {
    logger.error(
      'Failed to export metrics',
      {},
      error instanceof Error ? error : new Error(String(error))
    );
    res.status(500).send('# Error exporting metrics\n');
  }
}
