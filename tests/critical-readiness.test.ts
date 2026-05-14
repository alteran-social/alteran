import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';
import { checkRate } from '../src/lib/ratelimit';
import { validateConfigOrThrow } from '../src/lib/config';
import { applyCorsHeaders } from '../src/lib/cors';
import { hashPassword, verifyPassword } from '../src/lib/password';
import { isAuthorized } from '../src/lib/auth';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { createPdsFetchHandler, normalizePdsRequestForAstro } from '../src/worker/runtime';
import { onRequest } from '../src/middleware';
import * as CreateRecord from '../src/pages/xrpc/com.atproto.repo.createRecord';
import * as DebugBlob from '../src/pages/debug/blob/[...key]';
import * as DebugBootstrap from '../src/pages/debug/db/bootstrap';
import * as DebugCommits from '../src/pages/debug/db/commits';
import * as DebugGc from '../src/pages/debug/gc/blobs';
import * as DebugRecord from '../src/pages/debug/record';
import * as DebugSequencer from '../src/pages/debug/sequencer';
import * as DebugHandlers from '../src/handlers/debug';
import { ctx, makeEnv } from './helpers/env';
import type { Env } from '../src/env';

function apiContext(env: Env, request: Request, params: Record<string, string> = {}) {
  return {
    locals: { runtime: { env } },
    params,
    request,
  } as any;
}

function rateLimitFailingEnv(env: Env): Env {
  const database = new Proxy(env.ALTERAN_DB as any, {
    get(target, property, receiver) {
      if (property === 'exec') {
        return (sql: string) => {
          if (sql.includes('rate_limit')) {
            return Promise.reject(new Error('rate limit database unavailable'));
          }
          return target.exec(sql);
        };
      }
      const value = Reflect.get(target, property, receiver);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  return { ...env, ALTERAN_DB: database } as Env;
}

async function runMiddleware(env: Env, request: Request, response = new Response('ok')): Promise<Response> {
  return (await (onRequest as any)(
    apiContext(env, request),
    () => Promise.resolve(response),
  )) as Response;
}

describe('critical production-readiness hardening', () => {
  it('denies every debug surface in production, including worker-level metrics', async () => {
    const env = await makeEnv({
      ENVIRONMENT: 'production',
      PDS_HOSTNAME: 'pds.example',
      PDS_CORS_ORIGIN: 'https://pds.example',
    });

    const cases: Array<Promise<Response>> = [
      DebugRecord.GET(apiContext(env, new Request('https://pds.example/debug/record?uri=at://x'))),
      DebugRecord.POST(apiContext(env, new Request('https://pds.example/debug/record', { method: 'POST', body: '{}' }))),
      DebugBlob.GET(apiContext(env, new Request('https://pds.example/debug/blob/key'), { key: 'key' })),
      DebugBlob.PUT(apiContext(env, new Request('https://pds.example/debug/blob/key', { method: 'PUT', body: 'x' }), { key: 'key' })),
      DebugBootstrap.POST(apiContext(env, new Request('https://pds.example/debug/db/bootstrap', { method: 'POST' }))),
      DebugCommits.GET(apiContext(env, new Request('https://pds.example/debug/db/commits'))),
      DebugGc.POST(apiContext(env, new Request('https://pds.example/debug/gc/blobs', { method: 'POST' }))),
      DebugSequencer.GET(apiContext(env, new Request('https://pds.example/debug/sequencer'))),
      DebugHandlers.POST_db_bootstrap(apiContext(env, new Request('https://pds.example/debug/db/bootstrap', { method: 'POST' }))),
      DebugHandlers.POST_record(apiContext(env, new Request('https://pds.example/debug/record', { method: 'POST', body: '{}' }))),
      DebugHandlers.GET_record(apiContext(env, new Request('https://pds.example/debug/record?uri=at://x'))),
    ];

    for (const response of await Promise.all(cases)) {
      expect(response.status).toBe(404);
    }

    const workerResponse = await createPdsFetchHandler()(
      new Request('https://pds.example/debug/sequencer') as any,
      env,
      ctx,
    );
    expect(workerResponse.status).toBe(404);
  });

  it('keeps debug routes available only on local non-production hosts', async () => {
    const env = await makeEnv();
    const local = await DebugRecord.POST(apiContext(env, new Request('http://localhost/debug/record', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ uri: 'at://did:example:test/app.bsky.feed.post/debug', json: { ok: true } }),
    })));
    expect(local.status).toBe(200);

    const denied = await DebugBlob.GET(apiContext(env, new Request('https://public.example/debug/blob/local'), {
      key: 'local',
    }));
    expect(denied.status).toBe(404);
  });

  it('does not honor the old development bearer-token bypass', async () => {
    const env = await makeEnv({ PDS_ALLOW_DEV_TOKEN: '1' } as Partial<Env>);
    const request = new Request('https://pds.example/xrpc/com.atproto.repo.createRecord', {
      headers: { authorization: 'Bearer dev-access-token' },
    });

    expect(await isAuthorized(request, env)).toBe(false);
  });

  it('removes auth/JWT verification debug logging from source', () => {
    const root = join(import.meta.dir, '..');
    const jwtSource = readFileSync(join(root, 'src/lib/jwt.ts'), 'utf8');
    const authSource = readFileSync(join(root, 'src/lib/auth.ts'), 'utf8');

    expect(jwtSource).not.toContain('[verifyJwt]');
    expect(jwtSource).not.toContain('console.error');
    expect(authSource).not.toContain('JWT verification error');
  });

  it('fails closed when rate-limit storage is unavailable and prevents route mutation', async () => {
    const env = await makeEnv();
    const { accessJwt } = await issueSessionTokens(env, env.PDS_DID as string);
    const brokenEnv = rateLimitFailingEnv(env);

    const direct = await checkRate(brokenEnv, new Request('https://pds.example/write'), 'writes');
    expect(direct?.status).toBe(429);

    const response = await CreateRecord.POST(apiContext(brokenEnv, new Request('https://pds.example/xrpc/com.atproto.repo.createRecord', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${accessJwt}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        collection: 'app.bsky.feed.post',
        record: { text: 'blocked', createdAt: new Date(0).toISOString() },
      }),
    })));

    expect(response.status).toBe(429);
    const row = await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM record').first() as { count: number };
    expect(row.count).toBe(0);
  });

  it('verifies password hashes without string equality shortcuts', async () => {
    const hash = await hashPassword('correct horse battery staple');

    expect(await verifyPassword('correct horse battery staple', hash)).toBe(true);
    expect(await verifyPassword('wrong', hash)).toBe(false);
    expect(await verifyPassword('wrong', 'not-a-valid-hash')).toBe(false);

    const source = readFileSync(join(import.meta.dir, '../src/lib/password.ts'), 'utf8');
    expect(source).not.toContain('candidate === hashHex');
  });

  it('does not expose stack details in public XRPC error JSON', async () => {
    const { toXRPCError } = await import('../src/lib/errors');
    const error = toXRPCError(new Error('database exploded'));
    const body = error.toJSON();

    expect(body).toEqual({ error: 'InternalServerError', message: 'database exploded' });
    expect(JSON.stringify(body)).not.toContain('stack');
  });

  it('enforces configured CORS origins in middleware while allowing no-Origin requests', async () => {
    const env = await makeEnv({ PDS_CORS_ORIGIN: 'https://allowed.example' });

    const allowed = await runMiddleware(env, new Request('https://pds.example/xrpc/foo', {
      headers: { origin: 'https://allowed.example' },
    }));
    expect(allowed.headers.get('access-control-allow-origin')).toBe('https://allowed.example');

    const disallowed = await runMiddleware(env, new Request('https://pds.example/xrpc/foo', {
      headers: { origin: 'https://blocked.example' },
    }));
    expect(disallowed.headers.get('access-control-allow-origin')).toBeNull();

    const noOrigin = await runMiddleware(env, new Request('https://pds.example/xrpc/foo'));
    expect(noOrigin.status).toBe(200);
    expect(noOrigin.headers.get('access-control-allow-origin')).toBeNull();

    const preflight = await runMiddleware(env, new Request('https://pds.example/xrpc/foo', {
      method: 'OPTIONS',
      headers: { origin: 'https://blocked.example' },
    }), new Response('should not run'));
    expect(preflight.status).toBe(403);
  });

  it('uses the original browser Origin after Worker origin normalization', async () => {
    const env = await makeEnv({ PDS_CORS_ORIGIN: 'https://allowed.example' });
    const original = new Request('https://pds.example/xrpc/foo', {
      method: 'POST',
      headers: { origin: 'https://allowed.example' },
    });
    const normalized = normalizePdsRequestForAstro(original as any) as unknown as Request;
    expect(normalized.headers.get('origin')).toBe('https://pds.example');

    const astroResponse = await runMiddleware(env, normalized);
    expect(astroResponse.headers.get('access-control-allow-origin')).toBeNull();

    const workerResponse = applyCorsHeaders(new Response('ok', astroResponse), env, original);
    expect(workerResponse.headers.get('access-control-allow-origin')).toBe('https://allowed.example');

    const blockedOriginal = new Request('https://pds.example/xrpc/foo', {
      method: 'POST',
      headers: { origin: 'https://blocked.example' },
    });
    const staleAstroResponse = new Response('ok', {
      headers: { 'Access-Control-Allow-Origin': 'https://pds.example' },
    });
    const blockedWorkerResponse = applyCorsHeaders(staleAstroResponse, env, blockedOriginal);
    expect(blockedWorkerResponse.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('enforces configured CORS origins in worker preflight and rejects production wildcard config', async () => {
    const env = await makeEnv({
      ENVIRONMENT: 'production',
      PDS_CORS_ORIGIN: 'https://allowed.example',
    });
    const handler = createPdsFetchHandler();

    const allowed = await handler(new Request('https://pds.example/xrpc/foo', {
      method: 'OPTIONS',
      headers: { origin: 'https://allowed.example' },
    }) as any, env, ctx);
    expect(allowed.status).toBe(204);
    expect(allowed.headers.get('access-control-allow-origin')).toBe('https://allowed.example');

    const denied = await handler(new Request('https://pds.example/xrpc/foo', {
      method: 'OPTIONS',
      headers: { origin: 'https://blocked.example' },
    }) as any, env, ctx);
    expect(denied.status).toBe(403);
    expect(denied.headers.get('access-control-allow-origin')).toBeNull();

    expect(() => validateConfigOrThrow({
      ...env,
      ENVIRONMENT: 'production',
      PDS_CORS_ORIGIN: '*',
    })).toThrow('PDS_CORS_ORIGIN cannot be wildcard');
  });
});
