import type { APIContext } from 'astro';
import { deletePar, loadPar } from '../../lib/oauth/store';
import { loginHintMatchesSingleUser, publicPdsOrigin, redirectWithOAuthError } from '../../lib/oauth/consent';

export const prerender = false;

function parseRequestUri(v: string | null): string | null {
  const p = 'urn:ietf:params:oauth:request_uri:';
  if (!v || !v.startsWith(p)) return null;
  const id = v.slice(p.length);
  return /^[A-Za-z0-9]+$/.test(id) ? id : null;
}

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const url = new URL(request.url);
  const issuer = publicPdsOrigin(env, request);
  const client_id = url.searchParams.get('client_id') || '';
  const request_uri = url.searchParams.get('request_uri');
  const frontChannelPrompt = (url.searchParams.get('prompt') || '').split(' ').filter(Boolean);
  const id = parseRequestUri(request_uri);
  if (!id) {
    return new Response(JSON.stringify({ error: 'invalid_request', error_description: 'invalid request_uri' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const par = await loadPar(env, id);
  if (!par) {
    return new Response(JSON.stringify({ error: 'invalid_request_uri' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (client_id && client_id !== par.client_id) {
    await deletePar(env, id);
    return redirectWithOAuthError(par.redirect_uri, 'invalid_request', par.state, issuer, 'client_id mismatch');
  }

  if (!(await loginHintMatchesSingleUser(env, par.login_hint))) {
    await deletePar(env, id);
    return redirectWithOAuthError(par.redirect_uri, 'login_required', par.state, issuer, 'login_hint does not match this PDS account');
  }

  const parPrompt = (par.prompt || '').split(' ').filter(Boolean);
  if (frontChannelPrompt.includes('none') || parPrompt.includes('none')) {
    await deletePar(env, id);
    return redirectWithOAuthError(par.redirect_uri, 'login_required', par.state, issuer);
  }

  const consentUrl = new URL('/oauth/consent', issuer);
  consentUrl.searchParams.set('request_uri', request_uri ?? '');
  consentUrl.searchParams.set('client_id', par.client_id);
  return Response.redirect(consentUrl.toString(), 302);
}
