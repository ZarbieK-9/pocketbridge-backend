/**
 * Metrics Service
 *
 * Tracks system metrics for monitoring and alerting
 * Uses in-memory counters (can be extended to use prom-client for Prometheus)
 */

interface MetricValue {
  value: number;
  labels?: Record<string, string>;
  timestamp: number;
}

class MetricsService {
  private counters: Map<string, number> = new Map();
  private gauges: Map<string, number> = new Map();
  private histograms: Map<string, number[]> = new Map();
  private labels: Map<string, Record<string, string>> = new Map();

  /**
   * Increment a counter
   */
  incrementCounter(name: string, labels?: Record<string, string>): void {
    const key = this.getKey(name, labels);
    const current = this.counters.get(key) || 0;
    this.counters.set(key, current + 1);
    if (labels) {
      this.labels.set(key, labels);
    }
  }

  /**
   * Set a gauge value
   */
  setGauge(name: string, value: number, labels?: Record<string, string>): void {
    const key = this.getKey(name, labels);
    this.gauges.set(key, value);
    if (labels) {
      this.labels.set(key, labels);
    }
  }

  /**
   * Record a histogram value
   */
  recordHistogram(name: string, value: number, labels?: Record<string, string>): void {
    const key = this.getKey(name, labels);
    const current = this.histograms.get(key) || [];
    current.push(value);
    // Keep only last 1000 values
    if (current.length > 1000) {
      current.shift();
    }
    this.histograms.set(key, current);
    if (labels) {
      this.labels.set(key, labels);
    }
  }

  /**
   * Get counter value
   */
  getCounter(name: string, labels?: Record<string, string>): number {
    const key = this.getKey(name, labels);
    return this.counters.get(key) || 0;
  }

  /**
   * Get gauge value
   */
  getGauge(name: string, labels?: Record<string, string>): number {
    const key = this.getKey(name, labels);
    return this.gauges.get(key) || 0;
  }

  /**
   * Get histogram statistics
   */
  getHistogramStats(
    name: string,
    labels?: Record<string, string>
  ): {
    count: number;
    sum: number;
    min: number;
    max: number;
    avg: number;
    p50: number;
    p95: number;
    p99: number;
  } | null {
    const key = this.getKey(name, labels);
    const values = this.histograms.get(key);
    if (!values || values.length === 0) {
      return null;
    }

    const sorted = [...values].sort((a, b) => a - b);
    const count = sorted.length;
    const sum = sorted.reduce((a, b) => a + b, 0);
    const min = sorted[0];
    const max = sorted[count - 1];
    const avg = sum / count;
    const p50 = sorted[Math.floor(count * 0.5)];
    const p95 = sorted[Math.floor(count * 0.95)];
    const p99 = sorted[Math.floor(count * 0.99)];

    return { count, sum, min, max, avg, p50, p95, p99 };
  }

  /**
   * Reset all metrics (useful for testing)
   */
  reset(): void {
    this.counters.clear();
    this.gauges.clear();
    this.histograms.clear();
    this.labels.clear();
  }

  /**
   * Export metrics in Prometheus format
   */
  exportPrometheus(): string {
    const lines: string[] = [];

    // Export counters
    for (const [key, value] of this.counters.entries()) {
      const [name, ...labelParts] = key.split('|');
      const labels = this.labels.get(key);
      const labelStr = labels ? this.formatLabels(labels) : '';
      lines.push(`pocketbridge_${name}_total${labelStr} ${value}`);
    }

    // Export gauges
    for (const [key, value] of this.gauges.entries()) {
      const [name] = key.split('|');
      const labels = this.labels.get(key);
      const labelStr = labels ? this.formatLabels(labels) : '';
      lines.push(`pocketbridge_${name}${labelStr} ${value}`);
    }

    // Export histogram summaries
    for (const [key] of this.histograms.entries()) {
      const [name] = key.split('|');
      const labels = this.labels.get(key);
      const labelStr = labels ? this.formatLabels(labels) : '';
      const stats = this.getHistogramStats(name, labels);
      if (stats) {
        lines.push(`pocketbridge_${name}_count${labelStr} ${stats.count}`);
        lines.push(`pocketbridge_${name}_sum${labelStr} ${stats.sum}`);
        lines.push(`pocketbridge_${name}_min${labelStr} ${stats.min}`);
        lines.push(`pocketbridge_${name}_max${labelStr} ${stats.max}`);
        lines.push(`pocketbridge_${name}_avg${labelStr} ${stats.avg}`);
        lines.push(`pocketbridge_${name}_p50${labelStr} ${stats.p50}`);
        lines.push(`pocketbridge_${name}_p95${labelStr} ${stats.p95}`);
        lines.push(`pocketbridge_${name}_p99${labelStr} ${stats.p99}`);
      }
    }

    return lines.join('\n') + '\n';
  }

  private getKey(name: string, labels?: Record<string, string>): string {
    if (!labels) return name;
    const labelStr = Object.entries(labels)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join(',');
    return `${name}|${labelStr}`;
  }

  private formatLabels(labels: Record<string, string>): string {
    const entries = Object.entries(labels)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${v}"`);
    return `{${entries.join(',')}}`;
  }
}

// Singleton instance
export const metrics = new MetricsService();

// Convenience functions
export function incrementCounter(name: string, labels?: Record<string, string>): void {
  metrics.incrementCounter(name, labels);
}

export function setGauge(name: string, value: number, labels?: Record<string, string>): void {
  metrics.setGauge(name, value, labels);
}

export function recordHistogram(
  name: string,
  value: number,
  labels?: Record<string, string>
): void {
  metrics.recordHistogram(name, value, labels);
}
