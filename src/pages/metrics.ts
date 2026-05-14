import type { APIContext } from 'astro';
import { metrics } from '../lib/metrics';
import { getRuntimeString } from '../lib/secrets';

export const prerender = false;

const JSON_HEADERS = {
  'Content-Type': 'application/json',
  'Cache-Control': 'no-store',
};

function json(status: number, body: unknown, headers: HeadersInit = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...JSON_HEADERS,
      ...headers,
    },
  });
}

function bearerToken(request: Request): string | null {
  const authorization = request.headers.get('authorization') ?? '';
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

function constantTimeEqual(left: string, right: string): boolean {
  const encoder = new TextEncoder();
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  const maxLength = Math.max(leftBytes.length, rightBytes.length);
  let diff = leftBytes.length ^ rightBytes.length;

  for (let i = 0; i < maxLength; i++) {
    diff |= (leftBytes[i] ?? 0) ^ (rightBytes[i] ?? 0);
  }

  return diff === 0;
}

export async function GET({ locals, request }: APIContext) {
  const env = locals.runtime.env;
  const configuredToken = ((await getRuntimeString(env, 'PDS_METRICS_TOKEN', '')) ?? '').trim();

  if (!configuredToken) {
    return json(404, {
      error: 'NotFound',
      message: 'Metrics export is disabled',
    });
  }

  const providedToken = bearerToken(request);
  if (!providedToken || !constantTimeEqual(providedToken, configuredToken)) {
    return json(401, {
      error: 'AuthRequired',
      message: 'Metrics bearer token required',
    }, {
      'WWW-Authenticate': 'Bearer realm="metrics"',
    });
  }

  return json(200, metrics.toJSON());
}
