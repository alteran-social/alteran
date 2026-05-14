/**
 * Observability Tests
 * Tests for logging, metrics, tracing, and monitoring
 */

import { describe, test, expect, beforeEach } from 'bun:test';
import type { APIContext, MiddlewareNext } from 'astro';
import type { Env } from '../src/env';
import { onRequest } from '../src/middleware';
import { GET as health } from '../src/pages/health';
import { GET as ready } from '../src/pages/ready';
import { makeEnv } from './helpers/env';

function apiContext(env: Env): APIContext {
  return {
    locals: {
      runtime: {
        env,
        ctx: { waitUntil: () => {}, passThroughOnException: () => {} },
        request: new Request('https://pds.example/health'),
      },
    },
  } as unknown as APIContext;
}

async function captureConsoleLogs<T>(fn: () => T | Promise<T>): Promise<{ result: T; logs: string[] }> {
  const original = console.log;
  const logs: string[] = [];
  console.log = (...args: unknown[]) => {
    logs.push(args.map(String).join(' '));
  };

  try {
    return { result: await fn(), logs };
  } finally {
    console.log = original;
  }
}

function parseJsonLogs(logs: string[]): any[] {
  return logs.map(log => JSON.parse(log));
}

function failingDb(message = 'database down'): Env['ALTERAN_DB'] {
  return {
    prepare: () => ({
      first: async () => {
        throw new Error(message);
      },
    }),
  } as unknown as Env['ALTERAN_DB'];
}

function failingBucket(message = 'storage down'): Env['ALTERAN_BLOBS'] {
  return {
    list: async () => {
      throw new Error(message);
    },
  } as unknown as Env['ALTERAN_BLOBS'];
}

async function runMiddleware(request: Request, next: MiddlewareNext): Promise<Response> {
  const env = await makeEnv();
  const result = await onRequest({
    locals: {
      runtime: {
        env,
        ctx: { waitUntil: () => {}, passThroughOnException: () => {} },
        request,
      },
    },
    request,
  } as any, next);

  if (!(result instanceof Response)) {
    throw new Error('middleware did not return a response');
  }

  return result;
}

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

      const { logs } = await captureConsoleLogs(() => {
        logger.debug('Debug message');
        logger.info('Info message');
        logger.warn('Warning message');
        logger.error('Error message', new Error('boom'));
      });

      const entries = parseJsonLogs(logs);
      expect(entries.map(entry => entry.level)).toEqual(['debug', 'info', 'warn', 'error']);
      expect(entries.map(entry => entry.message)).toEqual([
        'Debug message',
        'Info message',
        'Warning message',
        'Error message',
      ]);
      expect(entries[3].error).toBe('boom');
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

      const originalNow = Date.now;
      let now = 1_000;
      Date.now = () => now;
      const tracer = new Tracer();
      try {
        const spanId = tracer.start('test.operation');
        now += 12;

        const duration = tracer.end(spanId);
        expect(duration).toBe(12);
      } finally {
        Date.now = originalNow;
      }
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

      await expect(async () => {
        await tracer.trace('test.error', async () => {
          throw new Error('Test error');
        });
      }).toThrow('Test error');
    });
  });

  describe('Health Checks', () => {
    test('should check database and storage connectivity', async () => {
      const env = await makeEnv();
      const res = await health(apiContext(env));
      const body = await res.json() as any;

      expect(res.status).toBe(200);
      expect(body.status).toBe('healthy');
      expect(body.checks.database.status).toBe('ok');
      expect(body.checks.storage.status).toBe('ok');
    });

    test('should return 503 when the database is missing', async () => {
      const env = await makeEnv({ ALTERAN_DB: undefined as unknown as Env['ALTERAN_DB'] });
      const res = await health(apiContext(env));
      const body = await res.json() as any;

      expect(res.status).toBe(503);
      expect(body.status).toBe('unhealthy');
      expect(body.checks.database).toEqual({
        status: 'error',
        message: 'Database not configured',
      });
      expect(body.checks.storage.status).toBe('ok');
    });

    test('should return 503 on unhealthy dependencies', async () => {
      const env = await makeEnv({ ALTERAN_DB: failingDb(), ALTERAN_BLOBS: failingBucket() });
      const res = await health(apiContext(env));
      const body = await res.json() as any;

      expect(res.status).toBe(503);
      expect(body.status).toBe('unhealthy');
      expect(body.checks.database).toEqual({ status: 'error', message: 'database down' });
      expect(body.checks.storage).toEqual({ status: 'error', message: 'storage down' });
    });

    test('should make readiness fail closed for missing storage', async () => {
      const env = await makeEnv({ ALTERAN_BLOBS: undefined as unknown as Env['ALTERAN_BLOBS'] });
      const res = await ready(apiContext(env));
      const body = await res.json() as any;

      expect(res.status).toBe(503);
      expect(body.status).toBe('unhealthy');
      expect(body.checks.database.status).toBe('ok');
      expect(body.checks.storage).toEqual({
        status: 'error',
        message: 'Storage not configured',
      });
    });

    test('should return ready only when database and storage are reachable', async () => {
      const env = await makeEnv();
      const res = await ready(apiContext(env));

      expect(res.status).toBe(200);
      expect(await res.text()).toBe('ok');
    });
  });

  describe('Request ID Tracking', () => {
    test('should generate unique request IDs', () => {
      const id1 = crypto.randomUUID();
      const id2 = crypto.randomUUID();

      expect(id1).not.toBe(id2);
      expect(id1).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    });

    test('should include request ID in response headers', async () => {
      const { result: res } = await captureConsoleLogs(() => runMiddleware(
        new Request('https://pds.example/xrpc/com.atproto.server.describeServer'),
        async () => new Response('ok'),
      ));

      const requestId = res.headers.get('X-Request-ID');
      expect(requestId).toBeTruthy();
      expect(requestId).toMatch(/^[0-9a-f-]{36}$/);
    });

    test('should include request ID in logs', async () => {
      const { result: res, logs } = await captureConsoleLogs(() => runMiddleware(
        new Request('https://pds.example/xrpc/com.atproto.server.describeServer'),
        async () => new Response('ok', { status: 202 }),
      ));
      const requestId = res.headers.get('X-Request-ID');
      const requestLog = parseJsonLogs(logs).find(entry => entry.type === 'request');

      expect(requestLog).toMatchObject({
        level: 'info',
        type: 'request',
        method: 'GET',
        path: '/xrpc/com.atproto.server.describeServer',
        status: 202,
        requestId,
      });
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

      const originalNow = Date.now;
      let now = 5_000;
      Date.now = () => now;
      const tracer = new Tracer();
      try {
        const { logs } = await captureConsoleLogs(() => {
          const spanId = tracer.start('test.slow', { operation: 'test' });
          now += 1_001;
          expect(tracer.end(spanId)).toBe(1_001);
        });

        expect(parseJsonLogs(logs)).toContainEqual(expect.objectContaining({
          level: 'warn',
          message: 'Slow operation detected: test.slow',
          duration: 1_001,
          operation: 'test',
        }));
      } finally {
        Date.now = originalNow;
      }
    });
  });
});
