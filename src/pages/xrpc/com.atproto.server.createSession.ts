import type { APIContext } from 'astro';
import { readJson } from '../../lib/util';
import { createAccount, getAccountByIdentifier, storeRefreshToken } from '../../db/account';
import { findMatchingAppPassword } from '../../db/app-password';
import { hashPassword, verifyPassword } from '../../lib/password';
import { issueSessionTokens } from '../../lib/session-tokens';
import { AuthScope } from '../../lib/auth-scope';
import { getRuntimeString } from '../../lib/secrets';
import { buildDidDocument } from '../../lib/did-document';
import { clearLoginAttempt, loginLockoutResponse, reserveLoginAttempt } from '../../lib/login-attempts';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals;
  const attempt = await reserveLoginAttempt(env, request);
  if (attempt.tag === 'locked') return loginLockoutResponse(attempt.retryAfter);

  const rawBody = await readJson(request).catch(() => ({}));
  const body = (rawBody ?? {}) as { identifier?: unknown; password?: unknown };
  const identifier: string =
    typeof body.identifier === 'string' && body.identifier
      ? body.identifier
      : (await getRuntimeString(env, 'PDS_HANDLE', 'user.example')) ?? 'user.example';
  const password = typeof body.password === 'string' ? body.password : '';

  let account = await getAccountByIdentifier(env, identifier);
  if (!account) {
    const fallbackPassword = await getRuntimeString(env, 'USER_PASSWORD', '');
    if (fallbackPassword) {
      const fallbackDid =
        (await getRuntimeString(env, 'PDS_DID', 'did:example:single-user')) ?? 'did:example:single-user';
      const fallbackHandle = (await getRuntimeString(env, 'PDS_HANDLE', identifier)) ?? identifier;
      const hashed = await hashPassword(fallbackPassword);
      await createAccount(env, {
        did: fallbackDid,
        handle: fallbackHandle,
        passwordScrypt: hashed,
      });
      account = await getAccountByIdentifier(env, identifier);
    }
  }
  type LoginOutcome =
    | { tag: 'primary' }
    | { tag: 'app-password'; name: string; privileged: boolean }
    | { tag: 'failed' };

  async function authenticate(): Promise<LoginOutcome> {
    if (!password || !account) return { tag: 'failed' };
    if (await verifyPassword(password, account.passwordScrypt ?? null)) {
      return { tag: 'primary' };
    }
    const match = await findMatchingAppPassword(env, account.did, password);
    if (match) {
      return { tag: 'app-password', name: match.name, privileged: match.privileged };
    }
    return { tag: 'failed' };
  }

  const login = await authenticate();
  const ok = login.tag !== 'failed';

  if (!ok) {
    if (attempt.reservation.lockedUntil !== null) return loginLockoutResponse(undefined, true);

    return new Response(
      JSON.stringify({
        error: 'AuthRequired',
        message: 'Invalid credentials'
      }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  await clearLoginAttempt(env, attempt.reservation);

  const did = (account?.did ?? (await getRuntimeString(env, 'PDS_DID', 'did:example:single-user')) ?? 'did:example:single-user');
  const handle = (account?.handle ?? (await getRuntimeString(env, 'PDS_HANDLE', identifier ?? 'user.example')) ?? (identifier ?? 'user.example'));

  const accessScope: string = login.tag === 'app-password'
    ? (login.privileged ? AuthScope.AppPassPrivileged : AuthScope.AppPass)
    : AuthScope.Access;
  const appPasswordName: string | null = login.tag === 'app-password' ? login.name : null;

  const { accessJwt, refreshJwt, refreshPayload, refreshExpiry } = await issueSessionTokens(env, did, {
    accessScope,
  });

  await storeRefreshToken(env, {
    id: refreshPayload.jti,
    did,
    expiresAt: refreshExpiry,
    appPasswordName,
  });

  // Build didDoc for the response (required by official API contract)
  const didDoc = await buildDidDocument(env, did, handle);

  const email = account?.email ?? (env.PDS_EMAIL as string | undefined);

  return new Response(
    JSON.stringify({
      did,
      didDoc,
      handle,
      accessJwt,
      refreshJwt,
      active: true,
      ...(email ? { email, emailConfirmed: true, emailAuthFactor: false } : {}),
    }),
    { headers: { 'Content-Type': 'application/json' } },
  );
}
