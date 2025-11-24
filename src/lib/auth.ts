import type { APIContext } from 'astro';
import type { Env } from '../env';
import { AuthTokenExpiredError } from './auth-errors';
import { verifyJwt, type JwtClaims } from './jwt';
import { bearerToken } from './util';

export interface AuthContext {
  token: string;
  claims: JwtClaims;
}

export async function isAuthorized(request: Request, env: Env): Promise<boolean> {
  const auth = request.headers.get('authorization');

  console.error('=== AUTH DEBUG START ===');
  console.error('URL:', request.url);
  console.error('Has Auth Header:', !!auth);
  console.error('Auth Prefix:', auth?.substring(0, 30));
  console.error('=== AUTH DEBUG END ===');

  const token = bearerToken(request);
  if (!token) {
    console.error('RESULT: No Bearer or DPoP token found');
    return false;
  }

  console.error('Token Length:', token.length);
  console.error('Token Prefix:', token.substring(0, 30));

  // Prefer JWT
  let ver;
  try {
    ver = await verifyJwt(env, token);
  } catch (err) {
    if (err instanceof AuthTokenExpiredError) {
      throw err;
    }
    console.error('JWT VERIFICATION ERROR:', err instanceof Error ? err.message : String(err));
    return false;
  }

  console.error('JWT Valid:', ver?.valid);
  console.error('JWT Type:', ver?.payload?.t);
  console.error('JWT Sub:', ver?.payload?.sub);

  if (ver && ver.valid && ver.payload.t === 'access') {
    console.error('RESULT: JWT Success');
    return true;
  }

  // Back-compat local escape hatch if explicitly enabled
  const allowDev = (env as any).PDS_ALLOW_DEV_TOKEN === '1';
  console.error('Allow Dev Token:', allowDev);

  if (allowDev && token === 'dev-access-token') {
    console.error('RESULT: Dev token accepted');
    return true;
  }
  if (allowDev && env.USER_PASSWORD && token === env.USER_PASSWORD) {
    console.error('RESULT: User password accepted');
    return true;
  }

  console.error('RESULT: Unauthorized');
  return false;
}

export function unauthorized() {
  return new Response(JSON.stringify({ error: 'AuthRequired' }), { status: 401 });
}

export async function authenticateRequest(request: Request, env: Env): Promise<AuthContext | null> {
  const token = bearerToken(request);
  if (!token) return null;
  let ver;
  try {
    ver = await verifyJwt(env, token);
  } catch (err) {
    if (err instanceof AuthTokenExpiredError) {
      throw err;
    }
    console.error('JWT verification error:', err);
    return null;
  }
  if (!ver || !ver.valid) return null;
  const claims = ver.payload as JwtClaims;
  if (claims.t !== 'access') return null;
  return { token, claims };
}

export { AuthTokenExpiredError, expiredToken } from './auth-errors';
