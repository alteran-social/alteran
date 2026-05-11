import { decodeProtectedHeader, importJWK, compactVerify, type JWK as JoseJWK } from 'jose';

export function isHttpsUrl(u: string): boolean {
  try {
    const url = new URL(u);
    if (url.protocol !== 'https:') return false;
    const host = url.hostname.toLowerCase();
    if (host === 'localhost' || host.endsWith('.local')) return false;
    if (/^(\d+\.){3}\d+$/.test(host)) return false;
    return true;
  } catch {
    return false;
  }
}

export async function fetchClientMetadata(client_id: string): Promise<any> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 3000);
  try {
    const response = await fetch(client_id, { signal: ctl.signal });
    if (!response.ok) throw new Error(`client metadata fetch failed: ${response.status}`);
    const ctype = response.headers.get('content-type') || '';
    if (!ctype.includes('application/json') && !ctype.includes('json'))
      throw new Error('client metadata must be JSON');
    return await response.json();
  } finally {
    clearTimeout(t);
  }
}

// removed local b64url/DER helpers in favor of jose

export async function verifyClientAssertion(client_id: string, issuerOrigin: string, assertionJwt: string, jwks: any): Promise<boolean> {
  try {
    const [h, p] = assertionJwt.split('.');
    if (!h || !p) return false;
    const header = decodeProtectedHeader(assertionJwt) as any;
    if (header.alg !== 'ES256') return false;
    const keys: any[] = Array.isArray(jwks?.keys) ? jwks.keys : [];
    if (!keys.length) return false;
    const byKid = typeof header.kid === 'string' ? keys.find((k) => k.kid === header.kid) : null;
    const candidates = byKid ? [byKid] : keys;

    let payload: any | null = null;
    for (const jwk of candidates) {
      try {
        const key = await importJWK(jwk as JoseJWK, 'ES256');
        const verified = await compactVerify(assertionJwt, key);
        payload = JSON.parse(new TextDecoder().decode(verified.payload));
        break;
      } catch {}
    }
    if (!payload) return false;

    const now = Math.floor(Date.now() / 1000);
    if (payload.iss !== client_id) return false;
    if (payload.sub !== client_id) return false;
    if (payload.aud !== issuerOrigin) return false;
    if (typeof payload.iat !== 'number' || now - payload.iat > 300) return false;
    if (typeof payload.jti !== 'string' || payload.jti.length < 8) return false;
    return true;
  } catch {
    return false;
  }
}
