import setup from './spaces-worker-context';
import { onRequest } from '../../src/middleware';
import { normalizePdsRequestForAstro } from '../../src/worker/normalize-request';
import { ALL, GET, HEAD } from '../../src/pages/xrpc/com.atproto.space.getRecord';
import { ALL as listAll, GET as listGet, HEAD as listHead } from '../../src/pages/xrpc/com.atproto.space.listRecords';
import { GET as jwks } from '../../src/pages/oauth/jwks';
import type { Env } from '../../src/env';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (new URL(request.url).pathname === '/setup') return setup.fetch(request, env);
    if (new URL(request.url).pathname === '/synthetic-abort') {
      const controller = new AbortController();
      const original = new Request('https://pds.example/xrpc/com.atproto.space.getRecord', {
        headers: request.headers, signal: controller.signal,
      });
      const normalized = normalizePdsRequestForAstro(original as never) as unknown as Request;
      controller.abort();
      return Response.json({ original: original.signal.aborted, normalized: normalized.signal.aborted });
    }
    const normalized = normalizePdsRequestForAstro(request as never) as unknown as Request;
    const context = { request: normalized, locals: {}, url: new URL(normalized.url) };
    const mode = normalized.headers.get('x-test-mode');
    const run = () => onRequest(context as never, async () => {
      if (mode === 'throw') throw new Error('secret middleware failure');
      if (mode === 'returned-500') return new Response('secret middleware failure', {
        status: 500, headers: { 'x-private': 'secret middleware failure', vary: '*' },
      });
      if (mode === 'jwks-cache') return new Response('{}', { headers: { 'cache-control': 'public, max-age=300' } });
      if (mode === 'jwks-real') return jwks(context as never);
      if (mode === 'merge' || mode === 'wildcard') return new Response(null, { status: 404, headers: {
        'access-control-expose-headers': mode === 'wildcard' ? '*' : 'X-Existing, dPoP-Nonce',
        'dpop-nonce': 'nonce', vary: mode === 'wildcard' ? '*' : 'Origin, accept-signature',
      } });
      const list = new URL(normalized.url).pathname === '/xrpc/com.atproto.space.listRecords';
      if (normalized.method === 'HEAD') return list ? listHead() : HEAD();
      if (normalized.method !== 'GET') return list ? listAll() : ALL();
      return list ? listGet(context as never) : GET(context as never);
    });
    if (mode !== 'throw' && mode !== 'returned-500' && mode !== 'jwks-real') return run();
    const originalLog = console.log;
    let output = '';
    console.log = (...values: unknown[]) => { output += values.map(String).join(' '); };
    try {
      const response = await run();
      const headers = new Headers(response.headers);
      headers.set('x-test-sensitive-log', String(output.includes('secret middleware failure') || output.includes('KEYSECRET')));
      headers.set('x-test-path-log', String(output.includes('private-path-secret')));
      const { metrics } = await import('../../src/lib/metrics');
      headers.set('x-test-path-metric', String(JSON.stringify(metrics.toJSON()).includes('private-path-secret')));
      return new Response(response.body, { status: response.status, headers });
    } finally {
      console.log = originalLog;
    }
  },
};
