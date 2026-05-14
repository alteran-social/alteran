import { describe, expect, beforeEach, it } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';
import type { APIContext } from 'astro';
import type { Env } from '../src/env';
import { metrics, trackRequest, trackWrite } from '../src/lib/metrics';
import { GET as metricsEndpoint } from '../src/pages/metrics';
import { makeEnv } from './helpers/env';

function apiContext(env: Env, request: Request): APIContext {
  return {
    locals: {
      runtime: {
        env,
        ctx: { waitUntil: () => {}, passThroughOnException: () => {} },
        request,
      },
    },
    request,
  } as unknown as APIContext;
}

describe('metrics export endpoint', () => {
  beforeEach(() => {
    metrics.reset();
  });

  it('is injected by the packaged integration', () => {
    const integration = readFileSync(join(process.cwd(), 'index.js'), 'utf8');
    expect(integration).toContain("pattern: '/metrics'");
    expect(integration).toContain("entrypoint: './src/pages/metrics.ts'");
  });

  it('is disabled when no token is configured', async () => {
    const env = await makeEnv();
    const res = await metricsEndpoint(apiContext(
      env,
      new Request('https://pds.example/metrics', {
        headers: { authorization: 'Bearer token' },
      }),
    ));
    const body = await res.json() as any;

    expect(res.status).toBe(404);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(body.error).toBe('NotFound');
  });

  it('rejects missing or wrong bearer tokens', async () => {
    const env = await makeEnv({ PDS_METRICS_TOKEN: 'secret-metrics-token' });

    const missing = await metricsEndpoint(apiContext(
      env,
      new Request('https://pds.example/metrics'),
    ));
    expect(missing.status).toBe(401);
    expect(missing.headers.get('www-authenticate')).toBe('Bearer realm="metrics"');

    const wrong = await metricsEndpoint(apiContext(
      env,
      new Request('https://pds.example/metrics', {
        headers: { authorization: 'Bearer wrong-token' },
      }),
    ));
    expect(wrong.status).toBe(401);
  });

  it('exports counters and labeled histogram stats for authorized operators', async () => {
    const env = await makeEnv({ PDS_METRICS_TOKEN: 'secret-metrics-token' });
    trackRequest('GET', '/xrpc/com.atproto.server.describeServer', 200, 42);
    trackWrite('app.bsky.feed.post');
    metrics.observe('db_query_duration_ms', 7, { operation: 'select' });
    metrics.observe('db_query_duration_ms', 21, { operation: 'select' });

    const res = await metricsEndpoint(apiContext(
      env,
      new Request('https://pds.example/metrics', {
        headers: { authorization: 'Bearer secret-metrics-token' },
      }),
    ));
    const body = await res.json() as any;

    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('application/json');
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(body.counters['requests_total|method=GET,path=/xrpc/com.atproto.server.describeServer,status=200']).toBe(1);
    expect(body.counters['writes_total|collection=app.bsky.feed.post']).toBe(1);
    expect(body.histograms['request_duration_ms|method=GET,path=/xrpc/com.atproto.server.describeServer']).toMatchObject({
      count: 1,
      sum: 42,
      avg: 42,
    });
    expect(body.histograms['db_query_duration_ms|operation=select']).toMatchObject({
      count: 2,
      sum: 28,
      avg: 14,
      min: 7,
      max: 21,
      p50: 7,
      p95: 21,
      p99: 21,
    });
  });
});
