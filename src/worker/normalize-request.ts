import type { Request as WorkersRequest } from '@cloudflare/workers-types';

const OAUTH_BACKCHANNEL_PATHS = new Set([
  '/oauth/par',
  '/oauth/token',
  '/oauth/revoke',
]);

export function normalizePdsRequestForAstro(request: WorkersRequest): WorkersRequest {
  const url = new URL(request.url);
  if (!url.pathname.startsWith('/xrpc/') && !OAUTH_BACKCHANNEL_PATHS.has(url.pathname)) {
    return request;
  }

  // Astro's SSR origin-check middleware rejects unsafe requests when Origin is
  // absent or cross-origin. XRPC and OAuth backchannel endpoints are token-bound
  // APIs, not cookie/form auth, and atproto clients legitimately send them from
  // native runtimes or separate origins. Browser consent POSTs stay protected.
  if (request.headers.get('origin') === url.origin) {
    return request;
  }

  const headerRecord: Record<string, string> = {};
  request.headers.forEach((value: string, key: string) => {
    headerRecord[key] = value;
  });
  headerRecord.origin = url.origin;

  return new Request(request as any, { headers: headerRecord }) as unknown as WorkersRequest;
}
