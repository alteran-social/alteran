import { defineMiddleware, sequence } from 'astro/middleware';
import { applyCorsHeaders, corsPreflightResponse } from './lib/cors';

// Response.redirect() (and a few other constructors) returns a Response whose
// headers are immutable. Re-wrap into a fresh Response so downstream middleware
// can attach CORS / X-Request-ID without throwing "Can't modify immutable
// headers" at the Workers runtime.
function ensureMutableResponse(response: Response): Response {
  return new Response(response.body, response);
}

const cors = defineMiddleware(async ({ locals, request }, next) => {
  const env = locals.runtime?.env;

  if (request.method === 'OPTIONS') {
    return corsPreflightResponse(env, request);
  }

  const response = ensureMutableResponse(await next());
  return applyCorsHeaders(response, env, request);
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
