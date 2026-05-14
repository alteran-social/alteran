import type { APIContext } from 'astro';
import { readJson } from '../../lib/util';
import { drizzle } from 'drizzle-orm/d1';
import { login_attempts } from '../../db/schema';
import { eq } from 'drizzle-orm';
import { createAccount, getAccountByIdentifier, storeRefreshToken } from '../../db/account';
import { findMatchingAppPassword } from '../../db/app-password';
import { hashPassword, verifyPassword } from '../../lib/password';
import { issueSessionTokens } from '../../lib/session-tokens';
import { AuthScope } from '../../lib/auth-scope';
import { getRuntimeString } from '../../lib/secrets';
import { buildDidDocument } from '../../lib/did-document';

export const prerender = false;

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_SEC = 15 * 60; // 15 minutes

export async function POST({ locals, request }: APIContext) {
  const { env } = locals;
  const clientIp = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';

  const db = drizzle(env.ALTERAN_DB);
  const now = Math.floor(Date.now() / 1000);

  // Check if IP is locked out
  const attempt = await db.select().from(login_attempts).where(eq(login_attempts.ip, clientIp)).get();
  if (attempt && attempt.locked_until && attempt.locked_until > now) {
    const remainingSeconds = attempt.locked_until - now;
    return new Response(
      JSON.stringify({
        error: 'RateLimitExceeded',
        message: `Account locked due to too many failed attempts. Try again in ${Math.ceil(remainingSeconds / 60)} minutes.`
      }),
      { status: 429, headers: { 'Content-Type': 'application/json' } }
    );
  }

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
    // Track failed attempt
    const currentAttempts = (attempt?.attempts || 0) + 1;
    const lockedUntil = currentAttempts >= MAX_LOGIN_ATTEMPTS ? now + LOCKOUT_DURATION_SEC : null;

    if (attempt) {
      await db.update(login_attempts)
        .set({
          attempts: currentAttempts,
          locked_until: lockedUntil,
          last_attempt: now
        })
        .where(eq(login_attempts.ip, clientIp))
        .run();
    } else {
      await db.insert(login_attempts).values({
        ip: clientIp,
        attempts: currentAttempts,
        locked_until: lockedUntil,
        last_attempt: now,
      }).run();
    }

    if (lockedUntil) {
      return new Response(
        JSON.stringify({
          error: 'RateLimitExceeded',
          message: 'Too many failed login attempts. Account locked for 15 minutes.'
        }),
        { status: 429, headers: { 'Content-Type': 'application/json' } }
      );
    }

    return new Response(
      JSON.stringify({
        error: 'AuthRequired',
        message: 'Invalid credentials'
      }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  // Successful login - reset attempts
  if (attempt) {
    await db.delete(login_attempts).where(eq(login_attempts.ip, clientIp)).run();
  }

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
