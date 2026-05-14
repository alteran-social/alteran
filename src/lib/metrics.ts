/**
 * Metrics Collection
 * Tracks counters and histograms for monitoring
 */

import type { Env } from '../env';
import { drizzle } from 'drizzle-orm/d1';

export interface MetricCounter {
  name: string;
  value: number;
  labels?: Record<string, string>;
  timestamp: number;
}

export interface MetricHistogram {
  name: string;
  value: number;
  labels?: Record<string, string>;
  timestamp: number;
}

interface HistogramStats {
  count: number;
  sum: number;
  avg: number;
  min: number;
  max: number;
  p50: number;
  p95: number;
  p99: number;
}

/**
 * Simple in-memory metrics aggregator
 * In production, consider using Workers Analytics Engine or D1
 */
class MetricsCollector {
  private counters: Map<string, number> = new Map();
  private histograms: Map<string, number[]> = new Map();

  /**
   * Increment a counter
   */
  increment(name: string, value: number = 1, labels?: Record<string, string>) {
    const key = this.makeKey(name, labels);
    const current = this.counters.get(key) || 0;
    this.counters.set(key, current + value);
  }

  /**
   * Record a histogram value (e.g., duration)
   */
  observe(name: string, value: number, labels?: Record<string, string>) {
    const key = this.makeKey(name, labels);
    const values = this.histograms.get(key) || [];
    values.push(value);
    this.histograms.set(key, values);

    // Keep only last 1000 values to prevent memory growth
    if (values.length > 1000) {
      values.shift();
    }
  }

  /**
   * Get counter value
   */
  getCounter(name: string, labels?: Record<string, string>): number {
    const key = this.makeKey(name, labels);
    return this.counters.get(key) || 0;
  }

  /**
   * Get histogram statistics
   */
  getHistogramStats(name: string, labels?: Record<string, string>): {
    count: number;
    sum: number;
    avg: number;
    min: number;
    max: number;
    p50: number;
    p95: number;
    p99: number;
  } | null {
    const key = this.makeKey(name, labels);
    const values = this.histograms.get(key);

    if (!values || values.length === 0) {
      return null;
    }

    return this.histogramStats(values);
  }

  /**
   * Get all metrics as JSON
   */
  toJSON() {
    const counters: Record<string, number> = {};
    const histograms: Record<string, any> = {};

    for (const [key, value] of this.counters.entries()) {
      counters[key] = value;
    }

    for (const [key, values] of this.histograms.entries()) {
      histograms[key] = this.histogramStats(values);
    }

    return { counters, histograms };
  }

  /**
   * Reset all metrics
   */
  reset() {
    this.counters.clear();
    this.histograms.clear();
  }

  private makeKey(name: string, labels?: Record<string, string>): string {
    if (!labels || Object.keys(labels).length === 0) {
      return name;
    }
    const labelStr = Object.entries(labels)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join(',');
    return `${name}|${labelStr}`;
  }

  private histogramStats(values: number[]): HistogramStats {
    const sorted = [...values].sort((a, b) => a - b);
    const sum = sorted.reduce((a, b) => a + b, 0);

    return {
      count: sorted.length,
      sum,
      avg: sum / sorted.length,
      min: sorted[0],
      max: sorted[sorted.length - 1],
      p50: this.percentile(sorted, 0.50),
      p95: this.percentile(sorted, 0.95),
      p99: this.percentile(sorted, 0.99),
    };
  }

  private percentile(sorted: number[], p: number): number {
    const index = Math.ceil(sorted.length * p) - 1;
    return sorted[Math.max(0, index)];
  }
}

// Global metrics instance
export const metrics = new MetricsCollector();

/**
 * Common metric names
 */
export const METRICS = {
  // Counters
  REQUESTS_TOTAL: 'requests_total',
  WRITES_TOTAL: 'writes_total',
  RATE_LIMIT_HITS: 'rate_limit_hits',
  WS_CLIENTS: 'ws_clients',
  ERRORS_TOTAL: 'errors_total',

  // Histograms
  REQUEST_DURATION_MS: 'request_duration_ms',
  DB_QUERY_DURATION_MS: 'db_query_duration_ms',
  R2_OPERATION_DURATION_MS: 'r2_operation_duration_ms',
} as const;

/**
 * Track request metrics
 */
export function trackRequest(method: string, path: string, status: number, duration: number) {
  metrics.increment(METRICS.REQUESTS_TOTAL, 1, { method, path, status: String(status) });
  metrics.observe(METRICS.REQUEST_DURATION_MS, duration, { method, path });

  if (status >= 400) {
    const category = status >= 500 ? 'server' : 'client';
    metrics.increment(METRICS.ERRORS_TOTAL, 1, { category, status: String(status) });
  }
}

/**
 * Track write operations
 */
export function trackWrite(collection: string) {
  metrics.increment(METRICS.WRITES_TOTAL, 1, { collection });
}

/**
 * Track rate limit hits
 */
export function trackRateLimitHit(ip: string) {
  metrics.increment(METRICS.RATE_LIMIT_HITS, 1, { ip });
}

/**
 * Track WebSocket clients
 */
export function trackWebSocketClient(action: 'connect' | 'disconnect') {
  const delta = action === 'connect' ? 1 : -1;
  metrics.increment(METRICS.WS_CLIENTS, delta);
}
