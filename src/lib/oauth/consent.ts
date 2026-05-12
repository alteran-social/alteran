import type { Env } from '../../env';
import { drizzle } from 'drizzle-orm/d1';
import { eq } from 'drizzle-orm';
import { createAccount, getAccountByIdentifier } from '../../db/account';
import { login_attempts } from '../../db/schema';
import { getRuntimeString } from '../secrets';
import { hashPassword, verifyPassword } from '../password';

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_SEC = 15 * 60;

export function redirectWithOAuthError(
  redirectUri: string,
  error: string,
  state: string | undefined,
  issuer: string,
  description?: string,
): Response {
  const out = new URL(redirectUri);
  out.searchParams.set('error', error);
  if (description) out.searchParams.set('error_description', description);
  if (state) out.searchParams.set('state', state);
  out.searchParams.set('iss', issuer);
  return Response.redirect(out.toString(), 302);
}

export function redirectWithCode(redirectUri: string, code: string, state: string, issuer: string): Response {
  const out = new URL(redirectUri);
  out.searchParams.set('code', code);
  out.searchParams.set('state', state);
  out.searchParams.set('iss', issuer);
  return Response.redirect(out.toString(), 302);
}

export function requestOrigin(request: Request): string {
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
}

export function publicPdsOrigin(env: Env, request: Request): string {
  const hostname = env.PDS_HOSTNAME?.trim();
  if (!hostname) return requestOrigin(request);

  try {
    const configured = hostname.includes('://') ? new URL(hostname) : new URL(`https://${hostname}`);
    configured.pathname = '';
    configured.search = '';
    configured.hash = '';
    return configured.origin;
  } catch {
    return requestOrigin(request);
  }
}

export function isSameOriginPost(request: Request): boolean {
  const origin = requestOrigin(request);
  const secFetchSite = request.headers.get('sec-fetch-site');
  if (secFetchSite && secFetchSite !== 'same-origin' && secFetchSite !== 'none') {
    return false;
  }

  const originHeader = request.headers.get('origin');
  if (originHeader) return originHeader === origin;

  const referer = request.headers.get('referer');
  if (!referer) return false;
  try {
    const ref = new URL(referer);
    return `${ref.protocol}//${ref.host}` === origin;
  } catch {
    return false;
  }
}

export async function authenticateSingleUserPassword(env: Env, password: string): Promise<{ did: string; handle: string } | null> {
  if (!password) return null;
  const did = await getRuntimeString(env, 'PDS_DID', 'did:example:single-user');
  const handle = await getRuntimeString(env, 'PDS_HANDLE', 'user.example');
  if (!did || !handle) return null;

  let account = await getAccountByIdentifier(env, did);
  if (!account) account = await getAccountByIdentifier(env, handle);
  if (!account) {
    const fallbackPassword = await getRuntimeString(env, 'USER_PASSWORD', '');
    if (!fallbackPassword) return null;
    await createAccount(env, {
      did,
      handle,
      passwordScrypt: await hashPassword(fallbackPassword),
    });
    account = await getAccountByIdentifier(env, did);
  }
  if (!account || account.did !== did) return null;
  if (!(await verifyPassword(password, account.passwordScrypt))) return null;
  return { did: account.did, handle: account.handle };
}

function consentClientIp(request: Request): string {
  return request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
}

export async function checkConsentPasswordLockout(env: Env, request: Request): Promise<Response | null> {
  const db = drizzle(env.ALTERAN_DB);
  const now = Math.floor(Date.now() / 1000);
  const ip = consentClientIp(request);
  const attempt = await db.select().from(login_attempts).where(eq(login_attempts.ip, ip)).get();
  if (attempt?.locked_until && attempt.locked_until > now) {
    const remainingSeconds = attempt.locked_until - now;
    return new Response(
      JSON.stringify({
        error: 'RateLimitExceeded',
        message: `Account locked due to too many failed attempts. Try again in ${Math.ceil(remainingSeconds / 60)} minutes.`,
      }),
      { status: 429, headers: { 'Content-Type': 'application/json' } },
    );
  }
  return null;
}

function lockoutResponse(remainingSeconds: number): Response {
  return new Response(
    JSON.stringify({
      error: 'RateLimitExceeded',
      message: `Account locked due to too many failed attempts. Try again in ${Math.ceil(remainingSeconds / 60)} minutes.`,
    }),
    { status: 429, headers: { 'Content-Type': 'application/json' } },
  );
}

export async function reserveConsentPasswordAttempt(env: Env, request: Request): Promise<Response | null> {
  const now = Math.floor(Date.now() / 1000);
  const ip = consentClientIp(request);
  const row = await env.ALTERAN_DB.prepare(`
    INSERT INTO login_attempts (ip, attempts, locked_until, last_attempt)
    VALUES (?, 1, NULL, ?)
    ON CONFLICT(ip) DO UPDATE SET
      attempts = CASE
        WHEN locked_until IS NOT NULL AND locked_until > ? THEN attempts
        ELSE attempts + 1
      END,
      locked_until = CASE
        WHEN locked_until IS NOT NULL AND locked_until > ? THEN locked_until
        WHEN attempts + 1 >= ? THEN ?
        ELSE NULL
      END,
      last_attempt = ?
    RETURNING attempts, locked_until
  `).bind(ip, now, now, now, MAX_LOGIN_ATTEMPTS, now + LOCKOUT_DURATION_SEC, now)
    .first<{ attempts: number; locked_until: number | null }>();

  if (row?.locked_until && row.locked_until > now) {
    return lockoutResponse(row.locked_until - now);
  }
  return null;
}

export async function recordConsentPasswordFailure(env: Env, request: Request): Promise<void> {
  await reserveConsentPasswordAttempt(env, request);
}

export async function clearConsentPasswordFailures(env: Env, request: Request): Promise<void> {
  const db = drizzle(env.ALTERAN_DB);
  await db.delete(login_attempts).where(eq(login_attempts.ip, consentClientIp(request))).run();
}

export async function loginHintMatchesSingleUser(env: Env, loginHint: string | undefined): Promise<boolean> {
  if (!loginHint) return true;
  const did = await getRuntimeString(env, 'PDS_DID', 'did:example:single-user');
  const handle = await getRuntimeString(env, 'PDS_HANDLE', 'user.example');
  return loginHint === did || loginHint === handle;
}

export function htmlEscape(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
