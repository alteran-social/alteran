import type { Env } from '../../env';
import { errorCode, errorMessage } from '../errors';
import { verifyAccessToken } from '../session-tokens';
import { decodeProtectedHeader, importJWK, compactVerify, type JWK as JoseJWK } from 'jose';
import { cleanupExpiredOAuthReplaySecrets, createSecretOnce, getOAuthSession, getSecret, setSecret } from '../../db/account';
import { jwkThumbprint } from './dpop';
import {
  bearerAccessContext,
  isBearerAccessScope,
  isOAuthPermissionScope,
  oauthAccessContext,
  type AuthAccessContext,
} from '../auth-scope';

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
  const now = Math.floor(Date.now() / 1000);
  const raw = await getSecret(env, NONCE_PDS_KEY);
  if (raw) {
    try {
      const cached = JSON.parse(raw) as { v: string; ts: number };
      if (now - cached.ts < 120) return cached.v;
    } catch {
      // Corrupt cached nonce: fall through and mint a fresh one.
    }
  }
  const v = crypto.randomUUID().replace(/-/g, '');
  await setSecret(env, NONCE_PDS_KEY, JSON.stringify({ v, ts: now }));
  return v;
}

async function consumeResourceDpopJti(env: Env, jti: unknown, iat: number, nonce: string): Promise<void> {
  if (typeof jti !== 'string' || jti.length < 8) {
    throw new ResourceAuthError('use_dpop_nonce', { nonce, message: 'DPoP jti required' });
  }
  const now = Math.floor(Date.now() / 1000);
  const key = `oauth:dpop:jti:resource:${jti}`;
  await cleanupExpiredOAuthReplaySecrets(env, now);
  const inserted = await createSecretOnce(env, key, JSON.stringify({ iat, exp: now + 300 }));
  if (!inserted) {
    throw new ResourceAuthError('invalid_token', { message: 'DPoP proof replayed' });
  }
}

export type ResourceAuthContext = {
  did: string;
  token: string;
  scope?: string;
  authType: 'bearer' | 'oauth-dpop';
  access: AuthAccessContext;
};

export async function verifyResourceRequest(env: Env, request: Request): Promise<ResourceAuthContext | null> {
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
    const payload = await verifyAccessTokenOrThrow(env, token, { allowOAuth: false });
    if (!isBearerAccessScope(payload.scope)) {
      throw new ResourceAuthError('invalid_token');
    }
    return {
      did: payload.sub as string,
      token,
      scope: typeof payload.scope === 'string' ? payload.scope : undefined,
      authType: 'bearer',
      access: bearerAccessContext(payload.scope),
    };
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
  if (payload.iat - now > 30) throw new ResourceAuthError('use_dpop_nonce', { nonce });
  if (!payload.nonce || payload.nonce !== nonce) throw new ResourceAuthError('use_dpop_nonce', { nonce });
  // Verify ath binding
  const enc = new TextEncoder();
  const accessBytes = enc.encode(accessToken);
  const accessBuf = (() => { const b = new ArrayBuffer(accessBytes.byteLength); new Uint8Array(b).set(accessBytes); return b; })();
  const expectedAth = await crypto.subtle.digest('SHA-256', accessBuf);
  const expectedAthB64 = b64url(expectedAth);
  if (payload.ath !== expectedAthB64) throw new ResourceAuthError('invalid_token', { message: 'DPoP ath mismatch' });
  // Verify signature with JOSE
  await importJWK(header.jwk as JoseJWK, 'ES256');

  const tokenPayload = await verifyAccessTokenOrThrow(env, accessToken, { allowOAuth: true });
  if (!isOAuthPermissionScope(tokenPayload.scope)) {
    throw new ResourceAuthError('invalid_token', { message: 'OAuth token has no PDS resource permissions' });
  }
  const tokenJkt = (tokenPayload.cnf as any)?.jkt;
  if (typeof tokenJkt !== 'string') {
    throw new ResourceAuthError('invalid_token', { message: 'DPoP access token missing cnf.jkt' });
  }
  const proofJkt = await jwkThumbprint(header.jwk as JsonWebKey);
  if (proofJkt !== tokenJkt) {
    throw new ResourceAuthError('invalid_token', { message: 'DPoP key mismatch' });
  }
  await consumeResourceDpopJti(env, payload.jti, payload.iat, nonce);
  return {
    did: tokenPayload.sub as string,
    token: accessToken,
    scope: typeof tokenPayload.scope === 'string' ? tokenPayload.scope : undefined,
    authType: 'oauth-dpop' as const,
    access: oauthAccessContext(String(tokenPayload.scope)),
  };
}

async function verifyAccessTokenOrThrow(env: Env, token: string, opts: { allowOAuth?: boolean } = {}) {
  let payloadJwt: Awaited<ReturnType<typeof verifyAccessToken>>;
  try {
    payloadJwt = await verifyAccessToken(env, token);
  } catch (error) {
    if (errorCode(error) === 'ERR_JWT_EXPIRED') {
      throw new ResourceAuthError('expired_token');
    }
    if (errorCode(error)) {
      throw new ResourceAuthError('invalid_token');
    }
    throw error;
  }

  if (!payloadJwt || !payloadJwt.sub) {
    throw new ResourceAuthError('invalid_token');
  }
  const isOAuthToken = !!(payloadJwt.cnf as any)?.jkt;
  if (isOAuthToken && !opts.allowOAuth) {
    throw new ResourceAuthError('invalid_token');
  }
  if (isOAuthToken) {
    const sessionId = payloadJwt.oauth_session;
    const accessJti = payloadJwt.jti;
    const clientId = payloadJwt.client_id;
    if (typeof sessionId !== 'string' || typeof accessJti !== 'string' || typeof clientId !== 'string') {
      throw new ResourceAuthError('invalid_token');
    }
    const session = await getOAuthSession(env, sessionId);
    const now = Math.floor(Date.now() / 1000);
  if (
      !session ||
      session.revokedAt ||
      session.expiresAt <= now ||
      session.accessJti !== accessJti ||
      session.clientId !== clientId ||
      session.did !== payloadJwt.sub
    ) {
      throw new ResourceAuthError('invalid_token');
    }
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
): Promise<ResourceAuthContext | null> {
  const auth = request.headers.get('authorization');
  if (!auth) return null;

  const match = auth.match(/^(\S+)\s+(.+)$/);
  if (!match) return null;

  const [, schemeRaw, tokenRaw] = match;
  const scheme = schemeRaw?.toLowerCase();
  const token = tokenRaw?.trim();
  if (!scheme || !token) return null;

  if (scheme === 'dpop') {
    try {
      const result = await verifyResourceRequest(env, request);
      if (result) return result;
    } catch (e) {
      throw e;
    }
  }

  if (scheme === 'bearer') {
    const payloadJwt = await deps.verifyAccessToken(env, token, { allowOAuth: false });
    if (!isBearerAccessScope(payloadJwt.scope)) {
      throw new ResourceAuthError('invalid_token');
    }
    return {
      did: payloadJwt.sub as string,
      token,
      scope: typeof payloadJwt.scope === 'string' ? payloadJwt.scope : undefined,
      authType: 'bearer',
      access: bearerAccessContext(payloadJwt.scope),
    };
  }

  return null;
}

function jsonError(error: string, message: string, status: number): Response {
  return new Response(JSON.stringify({ error, message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export function insufficientScopeResponse(): Response {
  return jsonError('InvalidToken', 'token does not grant access to this resource', 401);
}

export async function handleResourceAuthError(env: Env, error: unknown): Promise<Response | null> {
  if (!(error instanceof ResourceAuthError)) {
    return null;
  }
  switch (error.code) {
    case 'use_dpop_nonce':
      return dpopResourceUnauthorized(env, undefined, error.nonce);
    case 'expired_token':
      return jsonError('ExpiredToken', 'Access token expired', 400);
    case 'invalid_token':
      return jsonError('InvalidToken', 'Invalid or malformed access token', 400);
  }
}
