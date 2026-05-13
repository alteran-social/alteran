import type { Env } from '../env';
import { AuthTokenExpiredError, expiredToken } from './auth-errors';
import { verifyJwt, type JwtClaims } from './jwt';
import { handleResourceAuthError, verifyResourceRequestHybrid } from './oauth/resource';
import { bearerToken } from './util';
import { getAccountState } from '../db/dal';
import {
  bearerAccessContext,
  canAccessFullAccount,
  isBearerAccessScope,
  oauthAccessContext,
  withAccountStatus,
  type AuthAccessContext,
  type AuthAccountStatus,
} from './auth-scope';

export interface AuthContext {
  token: string;
  claims: JwtClaims;
  access: AuthAccessContext;
}

function authScheme(request: Request): string | null {
  const auth = request.headers.get('authorization');
  const match = auth?.match(/^(\S+)\s+(.+)$/);
  return match?.[1]?.toLowerCase() ?? null;
}

export async function isAuthorized(request: Request, env: Env): Promise<boolean> {
  try {
    const auth = await authenticateRequest(request, env);
    if (auth) return canAccessFullAccount(auth.access);
  } catch (error) {
    if (error instanceof AuthTokenExpiredError) {
      throw error;
    }
    throw error;
  }

  const token = bearerToken(request);
  if (!token) {
    return false;
  }

  // Back-compat local escape hatch if explicitly enabled
  const allowDev = (env as any).PDS_ALLOW_DEV_TOKEN === '1';

  if (allowDev && token === 'dev-access-token') {
    return true;
  }
  if (allowDev && env.USER_PASSWORD && token === env.USER_PASSWORD) {
    return true;
  }

  return false;
}

export function unauthorized() {
  return new Response(JSON.stringify({ error: 'AuthRequired' }), { status: 401 });
}

export async function authErrorResponse(env: Env, error: unknown): Promise<Response | null> {
  if (error instanceof AuthTokenExpiredError) {
    return expiredToken();
  }
  return handleResourceAuthError(env, error);
}

export async function authenticateRequest(request: Request, env: Env): Promise<AuthContext | null> {
  if (authScheme(request) === 'dpop') {
    const result = await verifyResourceRequestHybrid(env, request);
    if (!result) return null;
    const access = await withResolvedAccountStatus(
      env,
      result.did,
      oauthAccessContext(result.scope ?? 'atproto'),
    );
    return {
      token: result.token,
      claims: {
        sub: result.did,
        scope: result.scope,
        t: 'access',
      } as JwtClaims,
      access,
    };
  }

  const token = bearerToken(request);
  if (!token) return null;
  let ver;
  try {
    ver = await verifyJwt(env, token);
  } catch (error) {
    if (error instanceof AuthTokenExpiredError) {
      throw error;
    }
    return null;
  }
  if (!ver || !ver.valid) return null;
  const claims = ver.payload as JwtClaims;
  if (claims.t !== 'access') return null;
  if (!isBearerAccessScope(claims.scope)) return null;
  const access = await withResolvedAccountStatus(
    env,
    claims.sub,
    bearerAccessContext(claims.scope),
  );
  return { token, claims, access };
}

export { AuthTokenExpiredError, expiredToken } from './auth-errors';

async function withResolvedAccountStatus(
  env: Env,
  did: string,
  access: AuthAccessContext,
): Promise<AuthAccessContext> {
  const state = await getAccountState(env, did);
  const accountStatus: AuthAccountStatus = state?.tag ?? 'active';
  return withAccountStatus(access, accountStatus);
}
