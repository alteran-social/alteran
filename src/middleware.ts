import { defineMiddleware, sequence } from 'astro/middleware';

// Response.redirect() (and a few other constructors) returns a Response whose
// headers are immutable. Re-wrap into a fresh Response so downstream middleware
// can attach CORS / X-Request-ID without throwing "Can't modify immutable
// headers" at the Workers runtime.
function ensureMutableResponse(response: Response): Response {
  return new Response(response.body, response);
}

const cors = defineMiddleware(async ({ locals, request }, next) => {
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
      // Use wildcard for headers to allow atproto-accept-labelers and other custom headers
      'Access-Control-Allow-Headers': '*',
      // Match atproto: 1 day max-age for CORS preflight cache
      'Access-Control-Max-Age': '86400',
    });
    return new Response(null, { status: 204, headers });
  }

  const response = ensureMutableResponse(await next());

  // Set CORS headers on all responses (atproto standard)
  response.headers.set('Access-Control-Allow-Origin', '*');

  // Expose DPoP-Nonce header for OAuth clients (atproto standard)
  // This allows clients to read the DPoP-Nonce header from responses
  const dpopNonce = response.headers.get('DPoP-Nonce');
  if (dpopNonce) {
    response.headers.set('Access-Control-Expose-Headers', 'DPoP-Nonce');
  }

  return response;
});

const logger = defineMiddleware(async ({ request, locals }, next) => {
  const rid = crypto.randomUUID();
  (locals as any).requestId = rid;

  const start = Date.now();
  const url = new URL(request.url);

  try {
    const response = ensureMutableResponse(await next());
    const dur = Date.now() - start;

    // Structured logging
    console.log(JSON.stringify({
      level: 'info',
      type: 'request',
      requestId: rid,
      method: request.method,
      path: url.pathname,
      status: response.status,
      duration: dur,
      timestamp: new Date().toISOString(),
    }));

    // Track metrics (import dynamically to avoid circular deps)
    try {
      const { trackRequest } = await import('./lib/metrics');
      trackRequest(request.method, url.pathname, response.status, dur);
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
      method: request.method,
      path: url.pathname,
      duration: dur,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      timestamp: new Date().toISOString(),
    }));

    // Track error metrics
    try {
      const { trackRequest } = await import('./lib/metrics');
      trackRequest(request.method, url.pathname, 500, dur);
    } catch (e) {
      // Metrics are optional
    }

    throw error;
  }
});

export const onRequest = sequence(cors, logger);
