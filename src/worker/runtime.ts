import { seed } from '../db/seed';
import { validateConfigOrThrow } from '../lib/config';
import { resolveEnvSecrets } from '../lib/secrets';
import { notifyRelaysIfNeeded } from '../lib/relay';
import type { Env } from '../env';
import type { SSRManifest } from 'astro';
import type {
  ExecutionContext,
  Request as WorkersRequest,
  Response as WorkersResponse,
} from '@cloudflare/workers-types';

export type PdsFetchHandler = (
  request: WorkersRequest,
  env: Env,
  ctx: ExecutionContext
) => Promise<WorkersResponse>;

export interface CreatePdsFetchHandlerOptions {
  /**
   * Optionally pass the host project's manifest when composing the worker manually.
   * When omitted, the integration will load the manifest lazily from the build output.
   */
  manifest?: SSRManifest;
}

/**
 * Returns the Alteran PDS Worker fetch handler so downstream apps can
 * compose it inside their own Cloudflare Worker entrypoint.
 */
export function createPdsFetchHandler(options?: CreatePdsFetchHandlerOptions): PdsFetchHandler {
  return async function fetch(request: WorkersRequest, env: Env, ctx: ExecutionContext) {
    // Resolve any Secret Store bindings to strings so downstream code can
    // treat secrets uniformly regardless of source (Secret or Secret Store).
    const resolvedEnv = await resolveEnvSecrets(env);

    // Cloudflare's Astro adapter expects an ASSETS binding for serving static
    // fallback content. Our worker doesn't ship static assets in production,
    // so provide a no-op stub to prevent adapter crashes (error code 1101).
    if (!resolvedEnv.ASSETS || typeof (resolvedEnv as any).ASSETS.fetch !== 'function') {
      (resolvedEnv as any).ASSETS = {
        async fetch() {
          return new Response('Not Found', {
            status: 404,
            headers: { 'Cache-Control': 'public, max-age=60' },
          });
        },
      };
    }

    try {
      validateConfigOrThrow(resolvedEnv);
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: 'ConfigurationError',
          message: error instanceof Error ? error.message : 'Invalid configuration',
        }),
        {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        }
      ) as unknown as WorkersResponse;
    }

    // Short-circuit CORS preflight at the worker entrypoint to avoid
    // adapter/method routing mismatches causing 500s on OPTIONS.
    if (request.method === 'OPTIONS') {
      const headers = new Headers({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': '*',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Max-Age': '86400',
      });
      return new Response(null, { status: 204, headers }) as unknown as WorkersResponse;
    }

    await seed(resolvedEnv.DB, resolvedEnv.PDS_DID as string);

    // Fire-and-forget: let relays know this PDS exists and is reachable.
    // Throttled per isolate and safe to call frequently.
    // Best-effort: notify relays, but avoid doing so on relay-initiated endpoints
    // to prevent feedback loops (describeServer/subscribeRepos).
    try {
      const pathname = new URL(request.url).pathname;
      const isRelayPath =
        pathname === '/xrpc/com.atproto.server.describeServer' ||
        pathname === '/xrpc/com.atproto.sync.subscribeRepos';
      if (!isRelayPath) {
        ctx.waitUntil(notifyRelaysIfNeeded(resolvedEnv as any, request.url));
      }
    } catch (error) {
      // Never block on relay notification
    }

    const url = new URL(request.url);

    // Lightweight debug endpoint for Sequencer metrics
    if (url.pathname === '/debug/sequencer' && request.method === 'GET') {
      try {
        if (!('SEQUENCER' in resolvedEnv) || !resolvedEnv.SEQUENCER) {
          return new Response('Sequencer not configured', { status: 503 }) as unknown as WorkersResponse;
        }
        const id = (resolvedEnv as any).SEQUENCER.idFromName('default');
        const stub = (resolvedEnv as any).SEQUENCER.get(id);
        const proxyRequest = new Request(new URL('/metrics', request.url).toString(), { method: 'GET' });
        const response = await stub.fetch(proxyRequest as any);
        // Pass through JSON
        const headers = new Headers(response.headers);
        headers.set('Content-Type', 'application/json');
        return new Response(await response.text(), { status: response.status, headers }) as unknown as WorkersResponse;
      } catch (error) {
        return new Response(JSON.stringify({ error: 'InternalError', message: 'Failed to fetch sequencer metrics' }), { status: 500, headers: { 'Content-Type': 'application/json' } }) as unknown as WorkersResponse;
      }
    }
    if (url.pathname === '/xrpc/com.atproto.sync.subscribeRepos') {
      const upgrade = request.headers.get('upgrade');
      if (upgrade !== 'websocket') {
        try {
          console.log(JSON.stringify({
            level: 'warn',
            type: 'ws_expected',
            path: url.pathname,
            method: request.method,
            message: 'subscribeRepos requires WebSocket upgrade',
            timestamp: new Date().toISOString(),
          }));
        } catch {
          // Logging-only path; never block the response on log serialization.
        }
        return new Response('This endpoint requires a WebSocket (wss://) upgrade', { status: 426 }) as unknown as WorkersResponse;
      }
      if (!resolvedEnv.SEQUENCER) {
        return new Response('Sequencer not configured', { status: 503 }) as unknown as WorkersResponse;
      }

      const id = resolvedEnv.SEQUENCER.idFromName('default');
      const stub = resolvedEnv.SEQUENCER.get(id);
      return (await stub.fetch(request as any)) as unknown as WorkersResponse;
    }

    const astroFetch = await getAstroFetch(options);
    const response = await astroFetch(request, resolvedEnv as any, ctx);
    return response as unknown as WorkersResponse;
  };
}

type AstroFetchHandler = (
  request: WorkersRequest,
  env: Env,
  ctx: ExecutionContext
) => Promise<WorkersResponse>;

let cachedFetchPromise: Promise<AstroFetchHandler> | undefined;

async function loadAstroFetchFromManifest(manifest: SSRManifest): Promise<AstroFetchHandler> {
  const { App } = await import('astro/app');
  const { handle } = await import('@astrojs/cloudflare/handler');
  const app = new App(manifest);
  return async (
    request: WorkersRequest,
    env: Env,
    ctx: ExecutionContext,
  ) =>
    (await handle(
      manifest,
      app,
      request as any,
      env as any,
      ctx as any,
    )) as unknown as WorkersResponse;
}

async function getAstroFetch(options?: CreatePdsFetchHandlerOptions): Promise<AstroFetchHandler> {
  if (options?.manifest) {
    return loadAstroFetchFromManifest(options.manifest);
  }

  if (!cachedFetchPromise) {
    cachedFetchPromise = (async () => {
      const moduleSpecifier = '@astrojs-manifest';
      const mod = await import(/* @vite-ignore */ moduleSpecifier);
      const manifest = (mod as any).manifest as SSRManifest;
      return loadAstroFetchFromManifest(manifest);
    })();
  }

  return cachedFetchPromise;
}

export { onRequest } from '../middleware';
export { seed };
export { validateConfigOrThrow };
