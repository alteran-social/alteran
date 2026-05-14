import type { Env } from '../env';

export function configuredCorsOrigin(env: Env): string {
  return ((env.PDS_CORS_ORIGIN as string | undefined) ?? '*').trim() || '*';
}

export function isProductionCorsWildcard(env: Env): boolean {
  return (env.ENVIRONMENT as string | undefined) === 'production' && configuredCorsOrigin(env) === '*';
}

export function resolveCorsOrigin(env: Env, request: Request): string | null {
  const origin = request.headers.get('origin');
  if (!origin) return null;

  const configured = configuredCorsOrigin(env);
  if (configured === '*') {
    return isProductionCorsWildcard(env) ? null : '*';
  }

  const allowed = configured
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  return allowed.includes(origin) ? origin : null;
}

export function applyCorsHeaders(response: Response, env: Env, request: Request): Response {
  response.headers.delete('Access-Control-Allow-Origin');

  const origin = resolveCorsOrigin(env, request);
  if (origin) {
    response.headers.set('Access-Control-Allow-Origin', origin);
    if (origin !== '*') {
      response.headers.append('Vary', 'Origin');
    }
  }

  const dpopNonce = response.headers.get('DPoP-Nonce');
  if (dpopNonce) {
    response.headers.set('Access-Control-Expose-Headers', 'DPoP-Nonce');
  }

  return response;
}

export function corsPreflightResponse(env: Env, request: Request): Response {
  const originHeader = request.headers.get('origin');
  const origin = resolveCorsOrigin(env, request);
  if (originHeader && !origin) {
    return new Response(null, { status: 403 });
  }

  const headers = new Headers({
    'Access-Control-Allow-Methods': '*',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Max-Age': '86400',
  });
  if (origin) {
    headers.set('Access-Control-Allow-Origin', origin);
    if (origin !== '*') {
      headers.set('Vary', 'Origin');
    }
  }

  return new Response(null, { status: 204, headers });
}
