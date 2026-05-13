import type { Env } from '../../env';
import { authErrorResponse, authenticateRequest, unauthorized, type AuthContext } from '../auth';
import { canMakeRpcCall, canUseAppPasswordLevelAccess } from '../auth-scope';
import { InvalidProxyHeader } from '../errors';
import {
  PRIVILEGED_METHODS,
  PRIVILEGED_SCOPES,
  PROTECTED_METHODS,
  resolveAuthScope,
} from './auth-policy';
import { resolveProxyTargetWithRegistry } from './did-resolver';
import {
  defaultServiceForNsid,
  getServiceRegistry,
} from './service-config';
import { createServiceJwt } from './service-jwt';
import type { ProxyTarget, ServiceConfig, ServiceId } from './types';

const FORWARDED_HEADERS = [
  'accept',
  'accept-encoding',
  'accept-language',
  'atproto-accept-labelers',
  'atproto-accept-personalized-feed',
  'cache-control',
  'if-none-match',
  'if-modified-since',
  'pragma',
  'x-bsky-topics',
  'x-bsky-feeds',
  'x-bsky-latest',
  'x-bsky-appview-features',
  'user-agent',
];

// Endpoints where read-after-write freshness matters: dropping conditionals on
// the viewer's own requests avoids 304s that hide content they just wrote.
const RAW_SENSITIVE_METHODS: ReadonlySet<string> = new Set([
  'app.bsky.unspecced.getPostThreadV2',
  'app.bsky.feed.getFeed',
  'app.bsky.feed.getPosts',
  'app.bsky.feed.getTimeline',
  'app.bsky.feed.getAuthorFeed',
]);

export interface ProxyAppViewOptions {
  readonly request: Request;
  readonly env: Env;
  readonly lxm: string;
  readonly auth?: AuthContext;
  readonly fallback?: () => Promise<Response>;
}

export async function proxyAppView({
  request,
  env,
  lxm,
  auth: suppliedAuth,
  fallback,
}: ProxyAppViewOptions): Promise<Response> {
  console.log('proxyAppView called:', { lxm, url: request.url });
  let registry: Record<ServiceId, ServiceConfig>;
  try {
    registry = getServiceRegistry(env);
  } catch {
    console.log('proxyAppView: No service config, using fallback');
    return fallback ? await fallback() : new Response('Services not configured', { status: 501 });
  }
  const defaultService = defaultServiceForNsid(env, lxm);

  if (env.PDS_APPVIEW_FORCE_FALLBACK === '1' && fallback) {
    console.log('proxyAppView: PDS_APPVIEW_FORCE_FALLBACK=1, using fallback');
    return fallback();
  }

  let auth: AuthContext | null | undefined = suppliedAuth;
  if (!auth) {
    try {
      auth = await authenticateRequest(request, env);
    } catch (error) {
      const handled = await authErrorResponse(env, error);
      if (handled) return handled;
      throw error;
    }
  }
  if (!auth) {
    return unauthorized();
  }
  if (!auth.claims.sub) {
    return new Response(JSON.stringify({ error: 'InvalidToken' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (PROTECTED_METHODS.has(lxm)) {
    return new Response(
      JSON.stringify({ error: 'InvalidToken', message: 'method cannot be proxied' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    );
  }

  if (auth.access.accountStatus !== 'active') {
    return new Response(JSON.stringify({ error: 'AccountInactive', message: 'Account is not active' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  const scope = resolveAuthScope(auth.claims.scope);
  if (!auth.access.isOAuth && (!scope || !canUseAppPasswordLevelAccess(auth.access))) {
    return new Response(JSON.stringify({ error: 'InvalidToken', message: 'bad token scope' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  let target: ProxyTarget = { did: defaultService.did, url: defaultService.url };
  let audience = `${defaultService.did}#${defaultService.id}`;
  const proxyHeader = request.headers.get('atproto-proxy');
  if (proxyHeader) {
    try {
      target = await resolveProxyTargetWithRegistry(env, proxyHeader, registry);
      audience = proxyHeader.trim();
    } catch (error) {
      console.error('AppView proxy header error:', error);
      const isHeaderError = error instanceof InvalidProxyHeader;
      return new Response(
        JSON.stringify({ error: isHeaderError ? 'InvalidProxyHeader' : 'ProxyResolutionFailed' }),
        {
          status: isHeaderError ? 400 : 502,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }
  }
  const hasPrivilegedAccess = auth.access.isOAuth
    ? canMakeRpcCall(auth.access, lxm, audience)
    : !!scope && PRIVILEGED_SCOPES.has(scope);
  if (!hasPrivilegedAccess && PRIVILEGED_METHODS.has(lxm)) {
    return new Response(JSON.stringify({ error: 'InvalidToken' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  if (auth.access.isOAuth && !canMakeRpcCall(auth.access, lxm, audience)) {
    return new Response(JSON.stringify({ error: 'InvalidToken', message: 'bad token scope' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const originalUrl = new URL(request.url);
  const upstreamUrl = new URL(target.url);
  upstreamUrl.pathname = originalUrl.pathname;
  upstreamUrl.search = originalUrl.search;
  upstreamUrl.hash = '';

  const headers = new Headers();
  for (const header of FORWARDED_HEADERS) {
    const value = request.headers.get(header);
    if (value) headers.set(header, value);
  }

  if (RAW_SENSITIVE_METHODS.has(lxm)) {
    const viewerDid = auth.claims.sub;
    if (viewerDid && viewerDid.startsWith('did:')) {
      headers.delete('if-none-match');
      headers.delete('if-modified-since');
    }
  }

  let serviceJwt: string;
  try {
    const issuerDid = auth.claims.sub;
    if (!issuerDid || !issuerDid.startsWith('did:')) {
      throw new Error(`Invalid issuer DID: ${issuerDid || '(empty)'}`);
    }
    serviceJwt = await createServiceJwt(env, issuerDid, audience, lxm);
  } catch (error) {
    console.error('AppView service token error:', error);
    return new Response(JSON.stringify({ error: 'ServiceAuthFailed' }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  headers.set('authorization', `Bearer ${serviceJwt}`);

  const method = request.method.toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && method !== 'POST') {
    return new Response(JSON.stringify({ error: 'MethodNotAllowed' }), {
      status: 405,
      headers: {
        'Content-Type': 'application/json',
        Allow: 'GET, HEAD, POST',
      },
    });
  }

  if (!headers.has('accept-encoding')) {
    headers.set('accept-encoding', 'identity');
  }

  if (method === 'POST') {
    const contentType = request.headers.get('content-type');
    if (contentType) headers.set('content-type', contentType);
    const contentEncoding = request.headers.get('content-encoding');
    if (contentEncoding) headers.set('content-encoding', contentEncoding);
  }

  try {
    const init: RequestInit & { duplex?: 'half' } = {
      method,
      headers,
    };

    if (method === 'POST') {
      init.body = request.body;
      init.duplex = 'half';
    }

    const upstream = await fetch(upstreamUrl.toString(), init);
    const responseHeaders = new Headers(upstream.headers);
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    });
  } catch (error) {
    console.error('AppView proxy error:', error);
    if (fallback) {
      return fallback();
    }
    return new Response(JSON.stringify({ error: 'UpstreamUnavailable' }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}
