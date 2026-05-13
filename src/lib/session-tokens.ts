import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import type { Env } from '../env';
import { getRuntimeString } from './secrets';
import { getOrCreateSecret } from '../db/account';
import { InvalidToken, ServerMisconfigured } from './errors';
import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import { AuthScope, isBearerAccessScope, isOAuthScope } from './auth-scope';

const SESSION_SECRET_KEY = 'session_jwt_secret';
const GRACE_PERIOD_SECONDS = 2 * 60 * 60;
const ACCESS_TTL_SECONDS = 120 * 60; // 120 minutes
const REFRESH_TTL_SECONDS = 90 * 24 * 60 * 60; // 90 days
const LEGACY_REFRESH_SCOPE = 'refresh';

async function loadSecret(env: Env): Promise<string> {
  const fromEnv = await getRuntimeString(env, 'SESSION_JWT_SECRET' as keyof Env, '');
  if (fromEnv) {
    // Mirror into D1 so Workers without env access can retrieve it
    await getOrCreateSecret(env, SESSION_SECRET_KEY, async () => fromEnv);
    return fromEnv;
  }

  return getOrCreateSecret(env, SESSION_SECRET_KEY, async () => bytesToHex(randomBytes(32)));
}

async function getJwtKey(env: Env): Promise<Uint8Array> {
  const secret = await loadSecret(env);
  return new TextEncoder().encode(secret);
}

async function getServiceDid(env: Env): Promise<string> {
  const did = await getRuntimeString(env, 'PDS_DID', '');
  if (!did) throw new ServerMisconfigured('PDS_DID is not configured');
  return did;
}

export type IssueSessionTokenOptions = {
  jti?: string;
  accessJti?: string;
  scope?: string;
  clientId?: string;
  dpopJkt?: string;
  oauthSessionId?: string;
};

export async function issueSessionTokens(env: Env, did: string, opts: IssueSessionTokenOptions = {}) {
  const jwtKey = await getJwtKey(env);
  const serviceDid = await getServiceDid(env);
  const now = Math.floor(Date.now() / 1000);
  const accessScope = opts.dpopJkt ? (opts.scope ?? 'atproto') : (opts.scope ?? AuthScope.Access);
  if (opts.dpopJkt) {
    if (!isOAuthScope(accessScope)) {
      throw new InvalidToken('Invalid OAuth access token scope');
    }
  } else if (!isBearerAccessScope(accessScope)) {
    throw new InvalidToken('Invalid access token scope');
  }

  const accessExp = now + ACCESS_TTL_SECONDS;
  const accessPayload: TokenPayload = {
    scope: accessScope,
    aud: serviceDid,
    sub: did,
    iat: now,
    exp: accessExp,
  };
  if (opts.dpopJkt) {
    accessPayload.cnf = { jkt: opts.dpopJkt };
    accessPayload.jti = opts.accessJti ?? generateTokenId();
    if (opts.clientId) accessPayload.client_id = opts.clientId;
    if (opts.oauthSessionId) accessPayload.oauth_session = opts.oauthSessionId;
  }
  const accessJwt = await signJwt(jwtKey, 'at+jwt', accessPayload);

  const jti = opts.jti ?? generateTokenId();
  const refreshExp = now + REFRESH_TTL_SECONDS;
  const refreshPayload: RefreshTokenPayload = {
    scope: AuthScope.Refresh,
    aud: serviceDid,
    sub: did,
    iat: now,
    exp: refreshExp,
    jti,
  };
  if (opts.dpopJkt) {
    refreshPayload.cnf = { jkt: opts.dpopJkt };
    if (opts.clientId) refreshPayload.client_id = opts.clientId;
    if (opts.oauthSessionId) refreshPayload.oauth_session = opts.oauthSessionId;
  }
  const refreshJwt = await signJwt(jwtKey, 'refresh+jwt', refreshPayload);

  return {
    accessJwt,
    refreshJwt,
    accessPayload,
    refreshPayload,
    refreshExpiry: refreshPayload.exp,
  } as const;
}

export async function verifyRefreshToken(env: Env, token: string, opts: { ignoreExpiration?: boolean } = {}) {
  const key = await getJwtKey(env);
  const serviceDid = await getServiceDid(env);
  const { header, payload } = await decodeAndVerifyJwt(key, token, 'refresh+jwt', serviceDid, opts);
  if (header.typ !== 'refresh+jwt') {
    throw new InvalidToken('Invalid token type');
  }
  // New refresh tokens use the ATProto scope string. Accept the previous local
  // literal only so already-issued refresh credentials can rotate forward.
  if (payload.scope !== AuthScope.Refresh && payload.scope !== LEGACY_REFRESH_SCOPE) {
    throw new InvalidToken('Invalid refresh token scope');
  }
  return {
    payload,
    decoded: {
      scope: payload.scope,
      sub: payload.sub,
      exp: payload.exp,
      jti: payload.jti,
    } as RefreshTokenPayload,
  } as const;
}

export async function verifyAccessToken(env: Env, token: string) {
  const key = await getJwtKey(env);
  const serviceDid = await getServiceDid(env);
  const { header, payload } = await decodeAndVerifyJwt(key, token, 'at+jwt', serviceDid);
  if (header.typ !== 'at+jwt') {
    throw new InvalidToken('Invalid token type');
  }
  const isOAuthToken = typeof (payload.cnf as { jkt?: unknown } | undefined)?.jkt === 'string';
  if (isOAuthToken) {
    if (!isOAuthScope(payload.scope)) {
      throw new InvalidToken('Invalid OAuth access token scope');
    }
  } else if (!isBearerAccessScope(payload.scope)) {
    throw new InvalidToken('Invalid access token scope');
  }
  return payload;
}

export function computeGraceExpiry(previousExpiry: number, nowSeconds: number): number {
  const candidate = nowSeconds + GRACE_PERIOD_SECONDS;
  return Math.min(previousExpiry, candidate);
}

type TokenPayload = {
  scope: string;
  aud: string;
  sub: string;
  iat: number;
  exp: number;
  jti?: string;
  [key: string]: unknown;
};

type RefreshTokenPayload = TokenPayload & { jti: string };

type TokenHeader = { alg: 'HS256'; typ: 'at+jwt' | 'refresh+jwt' };

async function signJwt(key: Uint8Array, typ: TokenHeader['typ'], payload: TokenPayload): Promise<string> {
  // jose will set standard claims via dedicated methods; we also keep custom claims in payload
  const signer = new SignJWT(payload as JWTPayload)
    .setProtectedHeader({ alg: 'HS256', typ })
    .setSubject(payload.sub)
    .setAudience(payload.aud)
    .setIssuedAt(payload.iat)
    .setExpirationTime(payload.exp);
  return await signer.sign(key);
}

async function decodeAndVerifyJwt(
  key: Uint8Array,
  token: string,
  expectedTyp: TokenHeader['typ'],
  audience: string,
  opts: { ignoreExpiration?: boolean } = {},
) {
  const { payload, protectedHeader } = await jwtVerify(token, key, {
    algorithms: ['HS256'],
    audience,
    ...(opts.ignoreExpiration ? { currentDate: new Date(0) } : {}),
  });
  if (protectedHeader.typ !== expectedTyp) {
    throw new InvalidToken('Unexpected token header');
  }
  if (!payload.sub || typeof payload.sub !== 'string') {
    throw new InvalidToken('Token missing subject');
  }
  if (typeof payload.exp !== 'number') {
    throw new InvalidToken('Token missing expiry');
  }
  return { header: protectedHeader as TokenHeader, payload: payload as unknown as TokenPayload };
}

function generateTokenId(): string {
  return bytesToHex(randomBytes(16));
}
// removed custom HMAC/base64url helpers in favor of jose
