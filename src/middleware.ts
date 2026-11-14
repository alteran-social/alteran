import { defineMiddleware, sequence } from 'astro/middleware';
import { env as cloudflareEnv } from 'cloudflare:workers';
import type { Env } from './env';
import { resolveEnvSecrets } from './lib/secrets';
import { mergeHeaderTokens } from './lib/http-headers';
import { isCanonicalJwksGet, isPrivateProtocolPath, privateProtocolMethod } from './lib/private-protocol-path';
import { securePrivateProtocolHeaders, securePrivateProtocolResponse } from './lib/private-protocol-response';

// Response.redirect() (and a few other constructors) returns a Response whose
// headers are immutable. Re-wrap into a fresh Response so downstream middleware
// can attach CORS / X-Request-ID without throwing "Can't modify immutable
// headers" at the Workers runtime.
function ensureMutableResponse(response: Response): Response {
  return new Response(response.body, response);
}

const cors = defineMiddleware(async ({ request }, next) => {
  const privateProtocol = isPrivateProtocolPath(new URL(request.url).pathname);
  const jwksGet = isCanonicalJwksGet(request);
  // Match atproto CORS implementation: use wildcard for public endpoints
  // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
  // For requests without credentials, "*" can be specified as a wildcard
  // This is safer than reflecting the request origin and matches atproto standard

  if (request.method === 'OPTIONS') {
    // CORS preflight - match atproto PDS implementation
    const headers = new Headers({
      'Access-Control-Allow-Origin': '*',
      // Use wildcard for methods (atproto standard)
      'Access-Control-Allow-Methods': '*',
      // Authorization is a non-wildcard request header in the Fetch standard.
      'Access-Control-Allow-Headers': '*, Authorization, DPoP, Content-Type, Accept-Signature',
      // Match atproto: 1 day max-age for CORS preflight cache
      'Access-Control-Max-Age': '86400',
    });
    if (privateProtocol) securePrivateProtocolHeaders(headers);
    return new Response(null, { status: 204, headers });
  }

  // Defense-in-depth: catch any thrown error from downstream so the browser
  // sees a real response (with CORS headers) instead of a bare CF 500 that
  // surfaces as a CORS failure. The error gets logged downstream before it
  // reaches us here.
  let response: Response;
  try {
    const downstream = await next();
    response = privateProtocol ? securePrivateProtocolResponse(downstream, jwksGet) : ensureMutableResponse(downstream);
  } catch (error) {
    response = new Response(
      JSON.stringify({
        error: 'InternalError',
        message: privateProtocol ? 'Internal server error' :
          error instanceof Error ? error.message : 'Internal server error',
      }),
      { status: 500, headers: { 'Content-Type': 'application/json' } },
    );
  }

  // Set CORS headers on all responses (atproto standard)
  response.headers.set('Access-Control-Allow-Origin', '*');
  if (privateProtocol) securePrivateProtocolHeaders(response.headers, jwksGet && response.status === 200);

  // Expose DPoP-Nonce header for OAuth clients (atproto standard)
  // This allows clients to read the DPoP-Nonce header from responses
  const dpopNonce = response.headers.get('DPoP-Nonce');
  if (dpopNonce) {
    mergeHeaderTokens(response.headers, 'Access-Control-Expose-Headers', ['DPoP-Nonce']);
  }
  if (response.headers.has('WWW-Authenticate')) {
    mergeHeaderTokens(response.headers, 'Access-Control-Expose-Headers', ['WWW-Authenticate']);
  }

  return response;
});

// Astro v6 removed `Astro.locals.runtime.env` (the @astrojs/cloudflare getter
// now throws). Resolve any Secret Store bindings up front and expose the
// materialized env on `locals.env` so handlers don't need to import
// `cloudflare:workers` (and re-resolve secrets) themselves.
const resolveEnv = defineMiddleware(async ({ locals }, next) => {
  const resolved = await resolveEnvSecrets(cloudflareEnv as unknown as Env);
  (locals as unknown as { env: Env }).env = resolved;
  return next();
});

const logger = defineMiddleware(async ({ request, locals }, next) => {
  const rid = crypto.randomUUID();
  (locals as any).requestId = rid;

  const start = Date.now();
  const url = new URL(request.url);
  const privateProtocol = isPrivateProtocolPath(url.pathname);
  const path = privateProtocol ? '[private-protocol]' : url.pathname;
  const method = privateProtocol ? privateProtocolMethod(request.method) : request.method;

  try {
    const response = ensureMutableResponse(await next());
    const dur = Date.now() - start;

    // Structured logging
    console.log(JSON.stringify({
      level: 'info',
      type: 'request',
      requestId: rid,
      method,
      path,
      status: response.status,
      duration: dur,
      timestamp: new Date().toISOString(),
    }));

    // Track metrics (import dynamically to avoid circular deps)
    try {
      const { trackRequest } = await import('./lib/metrics');
      trackRequest(method, path, response.status, dur);
    } catch (e) {
      // Metrics are optional, don't fail request
    }

    // Add request ID to response headers
    response.headers.set('X-Request-ID', rid);

    return response;
  } catch (error) {
    const dur = Date.now() - start;
    // Log error
    console.log(JSON.stringify({
      level: 'error',
      type: 'request',
      requestId: rid,
      method,
      path,
      duration: dur,
      error: privateProtocol ? 'Private request failed' : error instanceof Error ? error.message : String(error),
      stack: !privateProtocol && error instanceof Error ? error.stack : undefined,
      timestamp: new Date().toISOString(),
    }));

    // Track error metrics
    try {
      const { trackRequest } = await import('./lib/metrics');
      trackRequest(method, path, 500, dur);
    } catch (e) {
      // Metrics are optional
    }

    throw error;
  }
});

export const onRequest = sequence(cors, resolveEnv, logger);
