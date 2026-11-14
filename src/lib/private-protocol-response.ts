import { mergeHeaderTokens } from './http-headers';

export function securePrivateProtocolHeaders(headers: Headers, preserveJwksCache = false): void {
  if (!preserveJwksCache || headers.get('cache-control') !== 'public, max-age=300') {
    headers.set('cache-control', 'private, no-store');
  }
  headers.set('access-control-allow-origin', '*');
  mergeHeaderTokens(headers, 'vary', ['Accept-Signature', 'Authorization', 'DPoP']);
  if (headers.has('dpop-nonce')) {
    mergeHeaderTokens(headers, 'access-control-expose-headers', ['DPoP-Nonce']);
  }
  if (headers.has('www-authenticate')) {
    mergeHeaderTokens(headers, 'access-control-expose-headers', ['WWW-Authenticate']);
  }
}

export function privateProtocolFailure(status = 500, varyStar = false): Response {
  const headers = new Headers({ 'content-type': 'application/json' });
  if (varyStar) headers.set('vary', '*');
  securePrivateProtocolHeaders(headers);
  return new Response(JSON.stringify({ error: 'InternalError', message: 'Internal server error' }), { status, headers });
}

/** Apply privacy headers at the Worker boundary, including pre-handler errors. */
export function securePrivateProtocolResponse(response: Response, jwksGet = false): Response {
  if (response.status >= 500) {
    const varyStar = (response.headers.get('vary') ?? '').split(',').some((value) => value.trim() === '*');
    // Failure responses discard arbitrary headers and challenges along with the body.
    try { void response.body?.cancel().catch(() => {}); } catch { /* Stream may already be locked. */ }
    return privateProtocolFailure(response.status, varyStar);
  }
  const headers = new Headers(response.headers);
  securePrivateProtocolHeaders(headers, jwksGet && response.status === 200);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
