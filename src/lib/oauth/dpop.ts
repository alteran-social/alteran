import type { Env } from '../../env';
import { getOrCreateSecret, setSecret, getSecret } from '../../db/account';
import { decodeProtectedHeader, importJWK, compactVerify, type JWK as JoseJWK } from 'jose';

// DPoP nonce management and proof verification utilities

const NONCE_AUTHZ_KEY = 'oauth_dpop_nonce_authz';
const NONCE_TTL_SEC = 120; // rotate roughly every 2 minutes

export interface DpopVerification {
  jkt: string; // JWK thumbprint
  jwk: JsonWebKey;
  payload: any;
}

function b64url(bytes: Uint8Array | ArrayBuffer): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// removed local b64urlToBytes helper

export async function getAuthzNonce(env: Env): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const existingRaw = await getSecret(env, NONCE_AUTHZ_KEY);
  if (existingRaw) {
    try {
      const parsed = JSON.parse(existingRaw) as { v: string; ts: number };
      if (typeof parsed.v === 'string' && typeof parsed.ts === 'number') {
        if (now - parsed.ts < NONCE_TTL_SEC) return parsed.v;
      }
    } catch {}
  }
  const v = crypto.randomUUID().replace(/-/g, '');
  const rec = JSON.stringify({ v, ts: now });
  await setSecret(env, NONCE_AUTHZ_KEY, rec);
  return v;
}

export function setDpopNonceHeader(headers: Headers, nonce: string) {
  headers.set('DPoP-Nonce', nonce);
}

// Compute RFC7638 JWK thumbprint for P-256 JWK
async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
  // Per RFC7638, canonical JSON with these members in lexicographic order
  const obj: Record<string, string> = {
    crv: String(jwk.crv ?? ''),
    kty: String(jwk.kty ?? ''),
    x: String(jwk.x ?? ''),
    y: String(jwk.y ?? ''),
  };
  const json = JSON.stringify(obj);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(json));
  return b64url(digest);
}

function urlWithoutHash(u: string): string {
  try {
    const url = new URL(u);
    url.hash = '';
    return url.toString();
  } catch {
    return u;
  }
}

// removed local DER conversion; jose handles verification

export async function verifyDpop(env: Env, request: Request, opts?: { requireNonce?: boolean }): Promise<DpopVerification> {
  const dpop = request.headers.get('DPoP');
  const nonce = await getAuthzNonce(env);
  if (!dpop) {
    const error: any = new Error('DPoP required');
    (error as any).code = 'use_dpop_nonce';
    (error as any).nonce = nonce;
    throw error;
  }
  const [h, p] = dpop.split('.');
  if (!h || !p) {
    const error: any = new Error('Invalid DPoP');
    (error as any).code = 'use_dpop_nonce';
    (error as any).nonce = nonce;
    throw error;
  }
  const header = decodeProtectedHeader(dpop) as any;

  if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || !header.jwk) {
    const error: any = new Error('Invalid DPoP header');
    (error as any).code = 'use_dpop_nonce';
    (error as any).nonce = nonce;
    throw error;
  }

  // Verify signature using JOSE
  const key = await importJWK(header.jwk as JoseJWK, 'ES256');
  const verified = await compactVerify(dpop, key);
  const payload = JSON.parse(new TextDecoder().decode(verified.payload));

  const method = request.method.toUpperCase();
  const url = urlWithoutHash(request.url);
  if (payload.htm !== method || payload.htu !== url) {
    const error: any = new Error('DPoP htm/htu mismatch');
    (error as any).code = 'use_dpop_nonce';
    (error as any).nonce = nonce;
    throw error;
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.iat !== 'number' || now - payload.iat > 300) {
    const error: any = new Error('DPoP iat too old');
    (error as any).code = 'use_dpop_nonce';
    (error as any).nonce = nonce;
    throw error;
  }

  if (opts?.requireNonce !== false) {
    if (!payload.nonce || payload.nonce !== nonce) {
      const error: any = new Error('use_dpop_nonce');
      (error as any).code = 'use_dpop_nonce';
      (error as any).nonce = nonce;
      throw error;
    }
  }

  const jkt = await jwkThumbprint(header.jwk as JsonWebKey);
  return { jkt, jwk: header.jwk as JsonWebKey, payload };
}

export function dpopErrorResponse(env: Env, error: any): Response {
  const nonce = (error && (error.nonce as string)) || '';
  const body = JSON.stringify({ error: 'use_dpop_nonce', error_description: 'Authorization server requires nonce in DPoP proof' });
  const headers = new Headers({ 'Content-Type': 'application/json' });
  if (nonce) headers.set('DPoP-Nonce', nonce);
  return new Response(body, { status: 401, headers });
}

export async function withDpop<T>(env: Env, request: Request, fn: (ver: DpopVerification) => Promise<T>): Promise<Response> {
  try {
    const ver = await verifyDpop(env, request);
    const result = await fn(ver);
    // Always include current nonce
    const nonce = await getAuthzNonce(env);
    const headers = new Headers({ 'Content-Type': 'application/json' });
    setDpopNonceHeader(headers, nonce);
    if (result instanceof Response) {
      result.headers.set('DPoP-Nonce', nonce);
      return result;
    }
    return new Response(JSON.stringify(result), { status: 200, headers });
  } catch (e: any) {
    if (e && e.code === 'use_dpop_nonce') {
      return dpopErrorResponse(env, e);
    }
    const headers = new Headers({ 'Content-Type': 'application/json' });
    return new Response(JSON.stringify({ error: 'invalid_request', error_description: e?.message ?? 'Unknown error' }), { status: 400, headers });
  }
}

export async function sha256b64url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return b64url(digest);
}
