import type { APIContext } from 'astro';
import { proxyAppView } from '../../lib/appview';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import {
  isSingleUserUnsupportedRoute,
  unsupportedSingleUserRouteResponse,
} from '../../lib/unsupported-routes';

export const prerender = false;

function shouldProxy(nsid: string): boolean {
  return (
    nsid.startsWith('app.bsky.') ||
    nsid.startsWith('chat.bsky.') ||
    nsid.startsWith('tools.ozone.')
  );
}

function nsidFromParams(params: Record<string, any>): string {
  const p = (params as any).nsid;
  if (Array.isArray(p)) return p.join('');
  return typeof p === 'string' ? p : '';
}

async function handle({ locals, request, params }: APIContext): Promise<Response> {
  const { env } = locals;
  const nsid = nsidFromParams(params).trim();
  console.log('xrpc catchall invoked:', { nsid, url: request.url });
  if (!nsid) {
    return new Response(JSON.stringify({ error: 'NotFound' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (isSingleUserUnsupportedRoute(nsid)) {
    return unsupportedSingleUserRouteResponse(nsid);
  }

  let auth;
  try {
    auth = await authenticateRequest(request, env);
    if (!auth) return unauthorized();
  } catch (error) {
    const handled = await authErrorResponse(env, error);
    if (handled) return handled;
    throw error;
  }

  if (!shouldProxy(nsid)) {
    return new Response(JSON.stringify({ error: 'NotImplemented' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return proxyAppView({ request, env, lxm: nsid, auth });
}

export async function GET(ctx: APIContext) {
  return handle(ctx);
}

export async function HEAD(ctx: APIContext) {
  return handle(ctx);
}

export async function POST(ctx: APIContext) {
  return handle(ctx);
}
