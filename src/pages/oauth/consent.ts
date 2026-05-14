import type { APIContext } from 'astro';
import { deletePar, loadPar, saveCode, saveConsent, consumeConsent } from '../../lib/oauth/store';
import {
  authenticateSingleUserPassword,
  checkConsentPasswordLockout,
  clearConsentPasswordFailures,
  htmlEscape,
  isSameOriginPost,
  loginHintMatchesSingleUser,
  publicPdsOrigin,
  reserveConsentPasswordAttempt,
  redirectWithCode,
  redirectWithOAuthError,
} from '../../lib/oauth/consent';
import { fetchClientMetadata } from '../../lib/oauth/clients';

export const prerender = false;

function parseRequestUri(v: string | null): string | null {
  const p = 'urn:ietf:params:oauth:request_uri:';
  if (!v || !v.startsWith(p)) return null;
  const id = v.slice(p.length);
  return /^[A-Za-z0-9]+$/.test(id) ? id : null;
}

export async function GET({ locals, request }: APIContext) {
  const { env } = locals;
  const url = new URL(request.url);
  const request_uri = url.searchParams.get('request_uri');
  const id = parseRequestUri(request_uri);
  if (!id) {
    return new Response('Invalid OAuth request', { status: 400 });
  }
  const par = await loadPar(env, id);
  if (!par) {
    return new Response('OAuth request expired', { status: 400 });
  }
  const issuer = publicPdsOrigin(env, request);
  if ((par.prompt || '').split(' ').filter(Boolean).includes('none')) {
    await deletePar(env, id);
    return redirectWithOAuthError(par.redirect_uri, 'login_required', par.state, issuer);
  }
  if (!(await loginHintMatchesSingleUser(env, par.login_hint))) {
    await deletePar(env, id);
    return redirectWithOAuthError(par.redirect_uri, 'login_required', par.state, issuer, 'login_hint does not match this PDS account');
  }

  let clientName = par.client_id;
  try {
    const meta = await fetchClientMetadata(env, par.client_id);
    if (typeof (meta as any).client_name === 'string') clientName = (meta as any).client_name;
  } catch {
    // The PAR step already validated metadata; keep consent rendering available
    // if the client metadata endpoint is temporarily unavailable.
  }

  const csrf = crypto.randomUUID().replace(/-/g, '');
  await saveConsent(env, id, csrf, Math.floor(Date.now() / 1000) + 300);

  const body = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorize ${htmlEscape(clientName)}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 38rem; margin: 4rem auto; padding: 0 1rem; line-height: 1.5; }
    label, input, button { display: block; width: 100%; box-sizing: border-box; }
    input { margin: .4rem 0 1rem; padding: .7rem; }
    button { margin-top: .75rem; padding: .75rem; }
  </style>
</head>
<body>
  <h1>Authorize ${htmlEscape(clientName)}</h1>
  <p>${htmlEscape(clientName)} is requesting access to ${htmlEscape(par.scope)}.</p>
  <form method="post" action="/oauth/consent">
    <input type="hidden" name="request_uri" value="${htmlEscape(request_uri ?? '')}" />
    <input type="hidden" name="client_id" value="${htmlEscape(par.client_id)}" />
    <input type="hidden" name="csrf" value="${csrf}" />
    <label>Password<input name="password" type="password" autocomplete="current-password" required /></label>
    <button name="decision" value="allow" type="submit">Allow</button>
    <button name="decision" value="deny" type="submit" formnovalidate>Deny</button>
  </form>
</body>
</html>`;

  return new Response(body, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

export async function POST({ locals, request }: APIContext) {
  const { env } = locals;
  if (!isSameOriginPost(request)) {
    return new Response(JSON.stringify({ error: 'invalid_request', error_description: 'same-origin POST required' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const form = new URLSearchParams(await request.text());
  const request_uri = form.get('request_uri');
  const id = parseRequestUri(request_uri);
  const csrf = form.get('csrf') || '';
  if (!id || !(await consumeConsent(env, id, csrf))) {
    return new Response(JSON.stringify({ error: 'invalid_request', error_description: 'invalid csrf' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const issuer = publicPdsOrigin(env, request);
  const par = await loadPar(env, id);
  if (!par) {
    return new Response(JSON.stringify({ error: 'invalid_request_uri' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if ((form.get('client_id') || '') !== par.client_id) {
    await deletePar(env, id);
    return redirectWithOAuthError(par.redirect_uri, 'invalid_request', par.state, issuer, 'client_id mismatch');
  }

  if ((par.prompt || '').split(' ').filter(Boolean).includes('none')) {
    await deletePar(env, id);
    return redirectWithOAuthError(par.redirect_uri, 'login_required', par.state, issuer);
  }

  if (!(await loginHintMatchesSingleUser(env, par.login_hint))) {
    await deletePar(env, id);
    return redirectWithOAuthError(par.redirect_uri, 'login_required', par.state, issuer, 'login_hint does not match this PDS account');
  }

  const decision = form.get('decision') || '';
  if (decision !== 'allow') {
    await deletePar(env, id);
    return redirectWithOAuthError(par.redirect_uri, 'access_denied', par.state, issuer);
  }

  const lockout = await checkConsentPasswordLockout(env, request);
  if (lockout) return lockout;
  const reservedAttempt = await reserveConsentPasswordAttempt(env, request);
  if (reservedAttempt) {
    await deletePar(env, id);
    return reservedAttempt;
  }

  const account = await authenticateSingleUserPassword(env, form.get('password') || '');
  if (!account) {
    await deletePar(env, id);
    return redirectWithOAuthError(par.redirect_uri, 'access_denied', par.state, issuer, 'invalid credentials');
  }
  await clearConsentPasswordFailures(env, request);

  const code = crypto.randomUUID().replace(/-/g, '');
  const now = Math.floor(Date.now() / 1000);
  await saveCode(env, code, {
    code,
    client_id: par.client_id,
    redirect_uri: par.redirect_uri,
    code_challenge: par.code_challenge,
    scope: par.scope,
    dpopJkt: par.dpopJkt,
    clientAuthMethod: par.clientAuthMethod,
    clientAuthKeyId: par.clientAuthKeyId ?? null,
    did: account.did,
    createdAt: now,
    expiresAt: now + 300,
  });
  await deletePar(env, id);
  return redirectWithCode(par.redirect_uri, code, par.state, issuer);
}
