const PRIVATE_NAMESPACES = [
  '/xrpc/com.atproto.space.',
  '/xrpc/com.atproto.personalspace.',
  '/xrpc/com.atproto.memberspace.',
  '/xrpc/com.atproto.managedspace.',
];

/** Treat Space and OAuth endpoints as private in middleware. */
export function isPrivateProtocolPath(pathname: string): boolean {
  let path = normalizeSeparators(pathname);
  const encoded = path.includes('%');
  // Astro may remove a configured base path and decode before route matching.
  for (let depth = 0; depth < 4; depth++) {
    if (hasPrivateMarker(path) || hasPrivateMarker(resolveDots(path))) return true;
    if (encoded && (path.includes('xrpc') || path.includes('oauth'))) return true;
    if (!path.includes('%')) return false;
    // Encoded protocol paths can be normalized in a different order by a
    // proxy or router. Keep them private until a canonical path is known.
    let decoded: string;
    try {
      decoded = normalizeSeparators(decodeURIComponent(path));
    } catch {
      return true;
    }
    if (decoded === path) return false;
    path = decoded;
  }
  // Treat deeply encoded paths as private rather than guessing how a later routing layer will normalize them.
  return true;
}

/** A successful, queryless JWKS GET may retain its explicit public cache policy. */
export function isCanonicalJwksGet(request: Request): boolean {
  const url = new URL(request.url);
  const path = url.pathname;
  return request.method === 'GET' && !url.href.includes('?') && !url.hash && path === '/oauth/jwks';
}

export function privateProtocolMethod(method: string): string {
  return ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(method) ? method : 'other';
}

function hasPrivateMarker(path: string): boolean {
  return PRIVATE_NAMESPACES.some((prefix) => path.includes(prefix)) || path.includes('/oauth/') || path.endsWith('/oauth');
}

function normalizeSeparators(pathname: string): string {
  return pathname.replaceAll('\\', '/').replace(/\/+/g, '/').toLowerCase();
}

function resolveDots(pathname: string): string {
  const parts: string[] = [];
  for (const part of pathname.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') parts.pop();
    else parts.push(part);
  }
  return `/${parts.join('/')}`;
}
