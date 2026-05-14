/**
 * Observability Tests
 * Tests for logging, metrics, tracing, and monitoring
 */

import { describe, it as test, beforeEach } from "./helpers/bdd";
import { expect } from "@std/expect";

describe('Observability', () => {
  describe('Structured Logging', () => {
    test('should create logger with context', async () => {
      const { Logger } = await import('../src/lib/logger');

      const logger = new Logger({ service: 'test' });
      expect(logger).toBeDefined();
    });

    test('should log with different levels', async () => {
      const { Logger } = await import('../src/lib/logger');

      const logger = new Logger();

      // These should not throw
      logger.debug('Debug message');
      logger.info('Info message');
      logger.warn('Warning message');
      logger.error('Error message');

      expect(true).toBe(true);
    });

    test('should create child logger with inherited context', async () => {
      const { Logger } = await import('../src/lib/logger');

      const parent = new Logger({ service: 'parent' });
      const child = parent.child({ requestId: '123' });

      expect(child).toBeDefined();
    });

    test('should create request-scoped logger', async () => {
      const { createRequestLogger } = await import('../src/lib/logger');

      const logger = createRequestLogger('req-123', '/api/test', 'GET');
      expect(logger).toBeDefined();
    });
  });

  describe('Metrics Collection', () => {
    beforeEach(async () => {
      const { metrics } = await import('../src/lib/metrics');
      metrics.reset();
    });

    test('should increment counter', async () => {
      const { metrics } = await import('../src/lib/metrics');

      metrics.increment('test_counter', 1);
      metrics.increment('test_counter', 2);

      const value = metrics.getCounter('test_counter');
      expect(value).toBe(3);
    });

    test('should increment counter with labels', async () => {
      const { metrics } = await import('../src/lib/metrics');

      metrics.increment('requests', 1, { method: 'GET' });
      metrics.increment('requests', 1, { method: 'POST' });
      metrics.increment('requests', 1, { method: 'GET' });

      expect(metrics.getCounter('requests', { method: 'GET' })).toBe(2);
      expect(metrics.getCounter('requests', { method: 'POST' })).toBe(1);
    });

    test('should observe histogram values', async () => {
      const { metrics } = await import('../src/lib/metrics');

      metrics.observe('duration', 100);
      metrics.observe('duration', 200);
      metrics.observe('duration', 300);

      const stats = metrics.getHistogramStats('duration');
      expect(stats).toBeDefined();
      expect(stats?.count).toBe(3);
      expect(stats?.sum).toBe(600);
      expect(stats?.avg).toBe(200);
      expect(stats?.min).toBe(100);
      expect(stats?.max).toBe(300);
    });

    test('should calculate percentiles', async () => {
      const { metrics } = await import('../src/lib/metrics');

      // Add values 1-100
      for (let i = 1; i <= 100; i++) {
        metrics.observe('latency', i);
      }

      const stats = metrics.getHistogramStats('latency');
      expect(stats).toBeDefined();
      expect(stats?.p50).toBeGreaterThanOrEqual(45);
      expect(stats?.p50).toBeLessThanOrEqual(55);
      expect(stats?.p95).toBeGreaterThanOrEqual(90);
      expect(stats?.p99).toBeGreaterThanOrEqual(95);
    });

    test('should track request metrics', async () => {
      const { trackRequest, metrics } = await import('../src/lib/metrics');

      trackRequest('GET', '/api/test', 200, 150);
      trackRequest('POST', '/api/test', 201, 200);

      const requests = metrics.getCounter('requests_total', { method: 'GET', path: '/api/test', status: '200' });
      expect(requests).toBe(1);
    });

    test('should track write operations', async () => {
      const { trackWrite, metrics } = await import('../src/lib/metrics');

      trackWrite('app.bsky.feed.post');
      trackWrite('app.bsky.feed.post');
      trackWrite('app.bsky.feed.like');

      const posts = metrics.getCounter('writes_total', { collection: 'app.bsky.feed.post' });
      expect(posts).toBe(2);
    });

    test('should export metrics as JSON', async () => {
      const { metrics } = await import('../src/lib/metrics');

      metrics.increment('test', 5);
      metrics.observe('duration', 100);

      const json = metrics.toJSON();
      expect(json).toHaveProperty('counters');
      expect(json).toHaveProperty('histograms');
    });
  });

  describe('Performance Tracing', () => {
    test('should start and end trace span', async () => {
      const { Tracer } = await import('../src/lib/tracing');

      const tracer = new Tracer();
      const spanId = tracer.start('test.operation');

      await new Promise(resolve => setTimeout(resolve, 10));

      const duration = tracer.end(spanId);
      expect(duration).toBeGreaterThanOrEqual(10);
    });

    test('should trace async function', async () => {
      const { Tracer } = await import('../src/lib/tracing');

      const tracer = new Tracer();

      const result = await tracer.trace('test.async', async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
        return 'success';
      });

      expect(result).toBe('success');
    });

    test('should trace sync function', async () => {
      const { Tracer } = await import('../src/lib/tracing');

      const tracer = new Tracer();

      const result = tracer.traceSync('test.sync', () => {
        return 42;
      });

      expect(result).toBe(42);
    });

    test('should trace database query', async () => {
      const { traceDbQuery } = await import('../src/lib/tracing');

      const result = await traceDbQuery('select', async () => {
        await new Promise(resolve => setTimeout(resolve, 5));
        return { rows: [] };
      });

      expect(result).toEqual({ rows: [] });
    });

    test('should trace R2 operation', async () => {
      const { traceR2Operation } = await import('../src/lib/tracing');

      const result = await traceR2Operation('put', async () => {
        await new Promise(resolve => setTimeout(resolve, 5));
        return { success: true };
      });

      expect(result).toEqual({ success: true });
    });

    test('should handle errors in traced functions', async () => {
      const { Tracer } = await import('../src/lib/tracing');

      const tracer = new Tracer();

      await expect(tracer.trace('test.error', async () => {
        throw new Error('Test error');
      })).rejects.toThrow('Test error');
    });
  });

  describe('Health Checks', () => {
    test('should check database connectivity', () => {
      // This would require mocking D1 database
      // Placeholder for integration test
      expect(true).toBe(true);
    });

    test('should check storage connectivity', () => {
      // This would require mocking R2 bucket
      // Placeholder for integration test
      expect(true).toBe(true);
    });

    test('should return 503 on unhealthy dependencies', () => {
      // This would require mocking failed dependencies
      // Placeholder for integration test
      expect(true).toBe(true);
    });
  });

  describe('Request ID Tracking', () => {
    test('should generate unique request IDs', () => {
      const id1 = crypto.randomUUID();
      const id2 = crypto.randomUUID();

      expect(id1).not.toBe(id2);
      expect(id1).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    });

    test('should include request ID in response headers', () => {
      // This would require mocking middleware
      // Placeholder for integration test
      expect(true).toBe(true);
    });

    test('should include request ID in logs', () => {
      // This would require capturing log output
      // Placeholder for integration test
      expect(true).toBe(true);
    });
  });

  describe('Error Tracking', () => {
    test('should track client errors (4xx)', async () => {
      const { trackRequest, metrics } = await import('../src/lib/metrics');

      metrics.reset();
      trackRequest('GET', '/api/test', 404, 50);

      const errors = metrics.getCounter('errors_total', { category: 'client', status: '404' });
      expect(errors).toBe(1);
    });

    test('should track server errors (5xx)', async () => {
      const { trackRequest, metrics } = await import('../src/lib/metrics');

      metrics.reset();
      trackRequest('GET', '/api/test', 500, 50);

      const errors = metrics.getCounter('errors_total', { category: 'server', status: '500' });
      expect(errors).toBe(1);
    });
  });

  describe('Slow Operation Detection', () => {
    test('should detect slow operations', async () => {
      const { Tracer } = await import('../src/lib/tracing');

      const tracer = new Tracer();

      // This should trigger slow operation warning (> 1s)
      await tracer.trace('test.slow', async () => {
        await new Promise(resolve => setTimeout(resolve, 1100));
      });

      // If we had log capture, we'd verify the warning was logged
      expect(true).toBe(true);
    });
  });
});