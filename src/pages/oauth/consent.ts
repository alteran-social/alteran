import type { APIContext } from 'astro';
import { deleteParSnapshot, loadParSnapshot, saveConsent, consumeConsent } from '../../lib/oauth/store';
import { issueAuthorizationCode } from '../../lib/oauth/issue-code';
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
import { resolveClientMetadata } from '../../lib/oauth/clients';
import { consentPermissions, describeConsentPermission } from '../../lib/oauth/consent-scopes';
import { isLoopbackClientId } from '../../lib/oauth/loopback-client';

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
  const snapshot = await loadParSnapshot(env, id);
  if (!snapshot) {
    return new Response('OAuth request expired', { status: 400 });
  }
  const par = snapshot.record;
  const issuer = publicPdsOrigin(env, request);
  if ((par.prompt || '').split(' ').filter(Boolean).includes('none')) {
    await deleteParSnapshot(env, id, snapshot.value);
    return redirectWithOAuthError(par.redirect_uri, 'login_required', par.state, issuer);
  }
  if (!(await loginHintMatchesSingleUser(env, par.login_hint))) {
    await deleteParSnapshot(env, id, snapshot.value);
    return redirectWithOAuthError(par.redirect_uri, 'login_required', par.state, issuer, 'login_hint does not match this PDS account');
  }

  // A loopback client_id is self-declared: any local program can present it,
  // so it gets a fixed name and nothing it supplies is used as one.
  const isLoopbackClient = isLoopbackClientId(par.client_id);
  let clientName = isLoopbackClient ? 'Local development client' : par.client_id;
  if (!isLoopbackClient) {
    try {
      const metadata = await resolveClientMetadata(env, par.client_id);
      if (metadata.client_name) clientName = metadata.client_name;
    } catch {
      // The PAR step already validated metadata; keep consent rendering available
      // if the client metadata endpoint is temporarily unavailable.
    }
  }

  const permissionItems = consentPermissions(par.scope)
    .map((permission) => `<li>${htmlEscape(describeConsentPermission(permission))}</li>`)
    .join('\n    ');
  const unverifiedClientNotice = isLoopbackClient
    ? '<p class="warning">This is a local development client running on your own computer. Its identity cannot be verified, so only continue if you started this sign-in yourself.</p>'
    : '';

  const csrf = crypto.randomUUID().replace(/-/g, '');
  await saveConsent(env, id, csrf, Math.floor(Date.now() / 1000) + 300, snapshot.value);

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
    code { overflow-wrap: anywhere; }
    .scope { color: #555; font-size: .85rem; }
    .warning { border-left: .25rem solid #b45309; padding: .5rem .75rem; background: #fef3c7; color: #1f2937; }
  </style>
</head>
<body>
  <h1>Authorize ${htmlEscape(clientName)}</h1>
  ${unverifiedClientNotice}
  <p>${htmlEscape(clientName)} (<code>${htmlEscape(par.client_id)}</code>) is asking for permission to:</p>
  <ul>
    ${permissionItems}
  </ul>
  <p class="scope">Requested scope: <code>${htmlEscape(par.scope)}</code></p>
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
  const consent = id ? await consumeConsent(env, id, csrf) : null;
  if (!id || !consent) {
    return new Response(JSON.stringify({ error: 'invalid_request', error_description: 'invalid csrf' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const issuer = publicPdsOrigin(env, request);
  const snapshot = await loadParSnapshot(env, id);
  if (!snapshot || snapshot.value !== consent.parValue) {
    return new Response(JSON.stringify({ error: 'invalid_request_uri' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  const par = snapshot.record;

  if ((form.get('client_id') || '') !== par.client_id) {
    await deleteParSnapshot(env, id, snapshot.value);
    return redirectWithOAuthError(par.redirect_uri, 'invalid_request', par.state, issuer, 'client_id mismatch');
  }

  if ((par.prompt || '').split(' ').filter(Boolean).includes('none')) {
    await deleteParSnapshot(env, id, snapshot.value);
    return redirectWithOAuthError(par.redirect_uri, 'login_required', par.state, issuer);
  }

  if (!(await loginHintMatchesSingleUser(env, par.login_hint))) {
    await deleteParSnapshot(env, id, snapshot.value);
    return redirectWithOAuthError(par.redirect_uri, 'login_required', par.state, issuer, 'login_hint does not match this PDS account');
  }

  const decision = form.get('decision') || '';
  if (decision !== 'allow') {
    await deleteParSnapshot(env, id, snapshot.value);
    return redirectWithOAuthError(par.redirect_uri, 'access_denied', par.state, issuer);
  }

  const lockout = await checkConsentPasswordLockout(env, request);
  if (lockout) return lockout;
  const reservedAttempt = await reserveConsentPasswordAttempt(env, request);
  if (reservedAttempt) {
    await deleteParSnapshot(env, id, snapshot.value);
    return reservedAttempt;
  }

  const account = await authenticateSingleUserPassword(env, form.get('password') || '');
  if (!account) {
    await deleteParSnapshot(env, id, snapshot.value);
    return redirectWithOAuthError(par.redirect_uri, 'access_denied', par.state, issuer, 'invalid credentials');
  }
  await clearConsentPasswordFailures(env, request);

  const code = await issueAuthorizationCode(env, id, snapshot, consent, account.did);
  if (!code) {
    return new Response(JSON.stringify({ error: 'invalid_request_uri' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  return redirectWithCode(par.redirect_uri, code, par.state, issuer);
}
