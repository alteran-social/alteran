/**
 * Performance Tracing
 * Measures time spent in critical paths
 */

import { metrics, METRICS } from './metrics';
import { logger } from './logger';

export interface TraceSpan {
  name: string;
  startTime: number;
  labels?: Record<string, string>;
}

// Tracer is a class because each instance owns a Map of in-flight spans;
// start() and end() are paired stateful calls that need shared access to
// that map. The global `tracer` plus per-request instances both rely on
// this isolation.
export class Tracer {
  private spans: Map<string, TraceSpan> = new Map();

  /**
   * Start a trace span
   */
  start(name: string, labels?: Record<string, string>): string {
    const spanId = `${name}-${Date.now()}-${Math.random()}`;
    this.spans.set(spanId, {
      name,
      startTime: Date.now(),
      labels,
    });
    return spanId;
  }

  /**
   * End a trace span and record metrics
   */
  end(spanId: string): number | null {
    const span = this.spans.get(spanId);
    if (!span) {
      return null;
    }

    const duration = Date.now() - span.startTime;
    this.spans.delete(spanId);

    // Record metric based on span name
    if (span.name.startsWith('db.')) {
      metrics.observe(METRICS.DB_QUERY_DURATION_MS, duration, span.labels);
    } else if (span.name.startsWith('r2.')) {
      metrics.observe(METRICS.R2_OPERATION_DURATION_MS, duration, span.labels);
    }

    // Log slow operations (> 1 second)
    if (duration > 1000) {
      logger.warn(`Slow operation detected: ${span.name}`, {
        duration,
        ...span.labels,
      });
    }

    return duration;
  }

  /**
   * Trace an async function
   */
  async trace<T>(
    name: string,
    fn: () => Promise<T>,
    labels?: Record<string, string>
  ): Promise<T> {
    const spanId = this.start(name, labels);
    try {
      return await fn();
    } finally {
      this.end(spanId);
    }
  }

  /**
   * Trace a synchronous function
   */
  traceSync<T>(
    name: string,
    fn: () => T,
    labels?: Record<string, string>
  ): T {
    const spanId = this.start(name, labels);
    try {
      return fn();
    } finally {
      this.end(spanId);
    }
  }
}

// Global tracer instance
export const tracer = new Tracer();

/**
 * Trace a database query
 */
export async function traceDbQuery<T>(
  operation: string,
  fn: () => Promise<T>
): Promise<T> {
  return tracer.trace(`db.${operation}`, fn, { operation });
}

/**
 * Trace an R2 operation
 */
export async function traceR2Operation<T>(
  operation: string,
  fn: () => Promise<T>
): Promise<T> {
  return tracer.trace(`r2.${operation}`, fn, { operation });
}

/**
 * Trace an auth operation
 */
export async function traceAuthOperation<T>(
  operation: string,
  fn: () => Promise<T>
): Promise<T> {
  return tracer.trace(`auth.${operation}`, fn, { operation });
}

/**
 * Create a request-scoped tracer
 */
export function createRequestTracer(requestId: string): Tracer {
  const requestTracer = new Tracer();
  return requestTracer;
}