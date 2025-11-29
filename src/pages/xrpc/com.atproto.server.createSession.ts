import type { APIContext } from 'astro';
import { readJson } from '../../lib/util';
import { drizzle } from 'drizzle-orm/d1';
import { login_attempts } from '../../db/schema';
import { eq } from 'drizzle-orm';
import { createAccount, getAccountByIdentifier, storeRefreshToken } from '../../db/account';
import { hashPassword, verifyPassword } from '../../lib/password';
import { issueSessionTokens } from '../../lib/session-tokens';
import { getRuntimeString } from '../../lib/secrets';
import { buildDidDocument } from '../../lib/did-document';

export const prerender = false;

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_SEC = 15 * 60; // 15 minutes

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const clientIp = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';

  const db = drizzle(env.DB);
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

  const body = await readJson(request).catch(() => ({ identifier: '', password: '' }));
  const identifier = typeof body.identifier === 'string' && body.identifier ? body.identifier : (await getRuntimeString(env, 'PDS_HANDLE', 'user.example'));
  const password = typeof body.password === 'string' ? body.password : '';

  let account = await getAccountByIdentifier(env, identifier ?? '');
  if (!account) {
    const fallbackPassword = await getRuntimeString(env, 'USER_PASSWORD', '');
    if (fallbackPassword) {
      const fallbackDid = (await getRuntimeString(env, 'PDS_DID', 'did:example:single-user')) ?? 'did:example:single-user';
      const fallbackHandle = (await getRuntimeString(env, 'PDS_HANDLE', identifier)) ?? identifier;
      const hashed = await hashPassword(fallbackPassword);
      await createAccount(env, {
        did: fallbackDid,
        handle: fallbackHandle,
        passwordScrypt: hashed,
      });
      account = await getAccountByIdentifier(env, identifier ?? '');
    }
  }
  const passwordHash = account?.passwordScrypt ?? null;
  const ok = !!password && !!account && (await verifyPassword(password, passwordHash));

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

  const { accessJwt, refreshJwt, refreshPayload, refreshExpiry } = await issueSessionTokens(env, did);

  await storeRefreshToken(env, {
    id: refreshPayload.jti,
    did,
    expiresAt: refreshExpiry,
    appPasswordName: null,
  });

  // Build didDoc for the response (required by official API contract)
  const didDoc = await buildDidDocument(env, did, handle);

  return new Response(JSON.stringify({ did, didDoc, handle, accessJwt, refreshJwt, active: true }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
