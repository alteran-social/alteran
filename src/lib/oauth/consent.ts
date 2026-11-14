import type { Env } from '../../env';
import { createAccount, getAccountByIdentifier } from '../../db/account';
import { getRuntimeString } from '../secrets';
import { hashPassword, verifyPassword } from '../password';

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
