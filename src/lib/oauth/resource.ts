import type { Env } from '../../env';
import { verifyAccessToken } from '../session-tokens';
import { decodeProtectedHeader, importJWK, compactVerify, type JWK as JoseJWK } from 'jose';

const NONCE_PDS_KEY = 'oauth_dpop_nonce_pds';

type ResourceAuthErrorCode = 'use_dpop_nonce' | 'expired_token' | 'invalid_token';

export class ResourceAuthError extends Error {
  public readonly code: ResourceAuthErrorCode;
  public readonly nonce?: string;

  constructor(code: ResourceAuthErrorCode, opts: { message?: string; nonce?: string } = {}) {
    super(opts.message ?? code);
    this.code = code;
    this.nonce = opts.nonce;
  }
}

function b64url(bytes: Uint8Array | ArrayBuffer): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function urlWithoutHash(u: string): string {
  try { const url = new URL(u); url.hash = ''; return url.toString(); } catch { return u; }
}
// removed local b64urlToBytes and DER helpers; jose handles verification

async function getNonce(env: Env): Promise<string> {
  const { getSecret, setSecret } = await import('../../db/account');
  const now = Math.floor(Date.now() / 1000);
  const raw = await getSecret(env, NONCE_PDS_KEY);
  if (raw) {
    try { const j = JSON.parse(raw) as { v: string, ts: number }; if (now - j.ts < 120) return j.v; } catch {}
  }
  const v = crypto.randomUUID().replace(/-/g, '');
  await setSecret(env, NONCE_PDS_KEY, JSON.stringify({ v, ts: now }));
  return v;
}

export async function verifyResourceRequest(env: Env, request: Request): Promise<{ did: string; token: string } | null> {
  const auth = request.headers.get('authorization');
  if (!auth) return null;

  const match = auth.match(/^(\S+)\s+(.+)$/);
  if (!match) return null;

  const [, schemeRaw, tokenRaw] = match;
  const scheme = schemeRaw?.toLowerCase();
  const token = tokenRaw?.trim();
  if (!scheme || !token) return null;

  if (scheme === 'dpop') {
    return verifyDpopAccess(env, request, token);
  }

  if (scheme === 'bearer') {
    const payload = await verifyAccessTokenOrThrow(env, token);
    return { did: payload.sub as string, token };
  }

  return null;
}

async function verifyDpopAccess(env: Env, request: Request, accessToken: string) {
  const nonce = await getNonce(env);
  const dpop = request.headers.get('DPoP');
  if (!dpop) {
    throw new ResourceAuthError('use_dpop_nonce', { nonce });
  }

  const [h,p] = dpop.split('.');
  if (!h||!p) throw new ResourceAuthError('use_dpop_nonce', { nonce });
  const header = decodeProtectedHeader(dpop) as any;
  if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || !header.jwk) throw new ResourceAuthError('use_dpop_nonce', { nonce });
  const method = request.method.toUpperCase();
  const url = urlWithoutHash(request.url);
  const verified = await compactVerify(dpop, await importJWK(header.jwk as JoseJWK, 'ES256'));
  const payload = JSON.parse(new TextDecoder().decode(verified.payload));
  if (payload.htm !== method || payload.htu !== url) throw new ResourceAuthError('use_dpop_nonce', { nonce });
  const now = Math.floor(Date.now()/1000);
  if (typeof payload.iat !== 'number' || now - payload.iat > 300) throw new ResourceAuthError('use_dpop_nonce', { nonce });
  if (!payload.nonce || payload.nonce !== nonce) throw new ResourceAuthError('use_dpop_nonce', { nonce });
  // Verify ath binding
  const enc = new TextEncoder();
  const accessBytes = enc.encode(accessToken);
  const accessBuf = (() => { const b = new ArrayBuffer(accessBytes.byteLength); new Uint8Array(b).set(accessBytes); return b; })();
  const expectedAth = await crypto.subtle.digest('SHA-256', accessBuf);
  const expectedAthB64 = b64url(expectedAth);
  if (payload.ath !== expectedAthB64) throw new ResourceAuthError('use_dpop_nonce', { nonce });
  // Verify signature with JOSE
  const key = await importJWK(header.jwk as JoseJWK, 'ES256');
  // already verified above, nothing else to do

  const tokenPayload = await verifyAccessTokenOrThrow(env, accessToken);
  return { did: tokenPayload.sub as string, token: accessToken };
}

async function verifyAccessTokenOrThrow(env: Env, token: string) {
  let payloadJwt: Awaited<ReturnType<typeof verifyAccessToken>>;
  try {
    payloadJwt = await verifyAccessToken(env, token);
  } catch (error: any) {
    if (error?.code === 'ERR_JWT_EXPIRED') {
      throw new ResourceAuthError('expired_token');
    }
    if (error?.code) {
      throw new ResourceAuthError('invalid_token');
    }
    throw error;
  }

  if (!payloadJwt || !payloadJwt.sub) {
    throw new ResourceAuthError('invalid_token');
  }
  return payloadJwt;
}

export async function dpopResourceUnauthorized(env: Env, message?: string, nonceOverride?: string): Promise<Response> {
  const nonce = nonceOverride ?? await getNonce(env);
  const headers = new Headers();
  headers.set('WWW-Authenticate', 'DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"');
  headers.set('DPoP-Nonce', nonce);
  headers.set('Content-Type', 'application/json');
  const body = JSON.stringify({ error: 'use_dpop_nonce', error_description: message ?? 'DPoP nonce required' });
  return new Response(body, { status: 401, headers });
}

/**
 * Hybrid authentication that supports both DPoP (OAuth) and Bearer (legacy XRPC) tokens.
 * Tries DPoP first, then falls back to Bearer for backward compatibility with official Bluesky apps.
 */
type VerifyResourceHybridDeps = {
  verifyAccessToken: typeof verifyAccessTokenOrThrow;
};

const defaultVerifyHybridDeps: VerifyResourceHybridDeps = {
  verifyAccessToken: verifyAccessTokenOrThrow,
};

export async function verifyResourceRequestHybrid(
  env: Env,
  request: Request,
  deps: VerifyResourceHybridDeps = defaultVerifyHybridDeps,
): Promise<{ did: string; token: string } | null> {
  const auth = request.headers.get('authorization');
  if (!auth) return null;

  // Try DPoP authentication first (new OAuth flow)
  if (auth.startsWith('DPoP ')) {
    try {
      const result = await verifyResourceRequest(env, request);
      if (result) return result;
    } catch (e: any) {
      // If it's a nonce error, propagate it
      if (e?.code === 'use_dpop_nonce') throw e;
      // Otherwise fall through to Bearer
    }
  }

  // Fall back to Bearer token authentication (legacy XRPC flow)
  if (auth.startsWith('Bearer ')) {
    const token = auth.slice(7).trim();
    const payloadJwt = await deps.verifyAccessToken(env, token);
    return { did: payloadJwt.sub as string, token };
  }

  return null;
}

function jsonError(error: string, message: string, status: number): Response {
  return new Response(JSON.stringify({ error, message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export async function handleResourceAuthError(env: Env, err: unknown): Promise<Response | null> {
  if (!(err instanceof ResourceAuthError)) {
    return null;
  }
  switch (err.code) {
    case 'use_dpop_nonce':
      return dpopResourceUnauthorized(env, undefined, err.nonce);
    case 'expired_token':
      return jsonError('ExpiredToken', 'Access token expired', 400);
    case 'invalid_token':
      return jsonError('InvalidToken', 'Invalid or malformed access token', 400);
    default:
      return null;
  }
}
