import type { APIContext } from 'astro';
import { NSID, ensureValidDid } from '@atproto/syntax';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError, insufficientScopeResponse } from '../../lib/oauth/resource';
import { createServiceAuthToken } from '../../lib/appview';
import { canMakeRpcCall, type AuthAccessContext } from '../../lib/auth-scope';
import { PRIVILEGED_METHODS, PROTECTED_METHODS } from '../../lib/appview/auth-policy';

export const prerender = false;

const METHOD_SCOPED_MAX_EXPIRATION_SECONDS = 60 * 60;
const METHODLESS_MAX_EXPIRATION_SECONDS = 60;

const SERVICE_AUTH_PROTECTED_METHODS: ReadonlySet<string> = new Set([
  ...PROTECTED_METHODS,
  'com.atproto.admin.deleteAccount',
  'com.atproto.identity.submitPlcOperation',
  'com.atproto.repo.importRepo',
  'com.atproto.server.deleteAccount',
]);

const APP_PASSWORD_DENIED_SERVICE_AUTH_METHODS: ReadonlySet<string> = new Set([
  'com.atproto.server.createAccount',
]);

export async function GET({ locals, request }: APIContext) {
  const { env } = locals;
  let auth: NonNullable<Awaited<ReturnType<typeof verifyResourceRequestHybrid>>>;
  try {
    const verified = await verifyResourceRequestHybrid(env, request);
    if (!verified) return dpopResourceUnauthorized(env);
    auth = verified;
  } catch (error) {
    const handled = await handleResourceAuthError(env, error);
    if (handled) return handled;
    throw error;
  }

  const url = new URL(request.url);
  const audienceParam = url.searchParams.get('aud');
  const lexParam = url.searchParams.get('lxm');
  const expParam = url.searchParams.get('exp');

  const audience = audienceParam?.trim();
  if (!audience) {
    return jsonError('MissingAudience', undefined, 400);
  }
  if (!isValidServiceAudience(audience)) {
    return jsonError('InvalidRequest', 'aud must be a DID or DID service reference', 400);
  }

  const lexiconMethod = lexParam && lexParam.trim() !== '' ? lexParam.trim() : null;
  if (lexiconMethod !== null && !NSID.isValid(lexiconMethod)) {
    return jsonError('InvalidRequest', 'lxm must be a valid NSID', 400);
  }
  if (!isAccountActiveForServiceAuth(auth.access)) {
    return jsonError('AccountInactive', 'Account is not active', 403);
  }
  if (!canIssueServiceAuth(auth.access, lexiconMethod, audience)) {
    return insufficientScopeResponse();
  }

  let expiresIn = 60;
  const maxExpiresIn = lexiconMethod ? METHOD_SCOPED_MAX_EXPIRATION_SECONDS : METHODLESS_MAX_EXPIRATION_SECONDS;
  const now = Math.floor(Date.now() / 1000);
  if (expParam !== null) {
    if (!/^-?\d+$/.test(expParam)) {
      return jsonError('BadExpiration', 'expiration must be an integer timestamp', 400);
    }
    const exp = Number(expParam);
    if (!Number.isSafeInteger(exp)) {
      return jsonError('BadExpiration', 'expiration must be a safe integer timestamp', 400);
    }
    if (exp <= now) {
      return jsonError('BadExpiration', 'expiration is in the past', 400);
    }
    if (exp - now > maxExpiresIn) {
      return jsonError('BadExpiration', 'expiration too far in future', 400);
    }
    expiresIn = Math.max(1, exp - now);
  }

  try {
    const token = await createServiceAuthToken(env, auth.did, audience, lexiconMethod, expiresIn);
    return new Response(JSON.stringify({ token }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('service auth error:', error);
    return new Response(JSON.stringify({ error: 'InternalServerError' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

function canIssueServiceAuth(
  access: AuthAccessContext,
  lexiconMethod: string | null,
  audience: string,
): boolean {
  if (lexiconMethod === null) {
    return access.isFullAccess || access.isAppPassword;
  }
  if (SERVICE_AUTH_PROTECTED_METHODS.has(lexiconMethod)) return false;
  if (access.isOAuth) return canMakeRpcCall(access, lexiconMethod, audience);
  if (APP_PASSWORD_DENIED_SERVICE_AUTH_METHODS.has(lexiconMethod)) {
    return access.isFullAccess;
  }
  if (PRIVILEGED_METHODS.has(lexiconMethod)) {
    return access.isPrivileged;
  }
  return canMakeRpcCall(access, lexiconMethod, audience);
}

function isAccountActiveForServiceAuth(access: AuthAccessContext): boolean {
  if (access.isTakendown || access.isSignupQueued) return false;
  return access.accountStatus === 'active';
}

function isValidServiceAudience(audience: string): boolean {
  const parts = audience.split('#');
  if (parts.length > 2) return false;
  const [did, fragment] = parts;
  if (!did) return false;
  try {
    ensureValidDid(did);
  } catch {
    return false;
  }
  return fragment === undefined || /^[A-Za-z][A-Za-z0-9._:-]*$/.test(fragment);
}

function jsonError(error: string, message: string | undefined, status: number): Response {
  return new Response(JSON.stringify(message ? { error, message } : { error }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
