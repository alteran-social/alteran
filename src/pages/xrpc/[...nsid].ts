import type { APIContext } from 'astro';
import { proxyAppView } from '../../lib/appview';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import { isChatMethod } from '../../lib/privileged-method';
import {
  isSingleUserUnsupportedRoute,
  unsupportedSingleUserRouteResponse,
} from '../../lib/unsupported-routes';

export const prerender = false;

function shouldProxy(nsid: string): boolean {
  const normalized = nsid.toLowerCase();
  return isChatMethod(nsid) ||
    normalized.startsWith('app.bsky.') ||
    normalized.startsWith('tools.ozone.');
}

function nsidFromParams(params: Record<string, any>): string {
  const p = (params as any).nsid;
  if (Array.isArray(p)) return p.join('');
  return typeof p === 'string' ? p : '';
}

async function handle({ locals, request, params }: APIContext): Promise<Response> {
  const { env } = locals;
  const nsid = nsidFromParams(params).trim();
  if (!nsid) {
    return new Response(JSON.stringify({ error: 'NotFound' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (isSpaceRoute(nsid)) {
    const body = JSON.stringify({
      error: 'NotImplemented',
      message: 'AT Protocol Spaces are not supported by this PDS',
    });
    return new Response(request.method === 'HEAD' ? null : body, {
      status: 501,
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

function isSpaceRoute(nsid: string): boolean {
  const normalized = nsid.toLowerCase();
  return [
    'com.atproto.space.',
    'com.atproto.personalspace.',
    'com.atproto.memberspace.',
    'com.atproto.managedspace.',
  ].some((prefix) => normalized.startsWith(prefix));
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
