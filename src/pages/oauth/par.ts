import type { APIContext } from 'astro';
import { errorMessage } from '../../lib/errors';
import { getAuthzNonce, setDpopNonceHeader, verifyDpop, dpopErrorResponse } from '../../lib/oauth/dpop';
import { DpopNonceError } from '../../lib/oauth/dpop-errors';
import { savePar } from '../../lib/oauth/store';
import { fetchClientMetadata, isHttpsUrl, verifyClientAssertion } from '../../lib/oauth/clients';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;

  // Enforce DPoP with nonce; if missing or stale, return use_dpop_nonce
  try {
    const ver = await verifyDpop(env, request);

    // Parse form-encoded body
    const bodyText = await request.text();
    const form = new URLSearchParams(bodyText);
    const client_id = form.get('client_id') || '';
    const response_type = form.get('response_type') || '';
    const redirect_uri = form.get('redirect_uri') || '';
    const scope = form.get('scope') || '';
    const state = form.get('state') || '';
    const code_challenge = form.get('code_challenge') || '';
    const code_challenge_method = form.get('code_challenge_method') || '';
    const login_hint = form.get('login_hint') || undefined;
    const client_assertion_type = form.get('client_assertion_type') || '';
    const client_assertion = form.get('client_assertion') || '';

    if (!client_id || !isHttpsUrl(client_id)) {
      return new Response(JSON.stringify({ error: 'invalid_client', error_description: 'client_id must be https URL' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    if (response_type !== 'code') {
      return new Response(JSON.stringify({ error: 'unsupported_response_type' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    if (!redirect_uri || !isHttpsUrl(redirect_uri)) {
      return new Response(JSON.stringify({ error: 'invalid_request', error_description: 'redirect_uri must be https URL' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    if (!scope || !scope.split(' ').includes('atproto')) {
      return new Response(JSON.stringify({ error: 'invalid_scope' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    if (!state) {
      return new Response(JSON.stringify({ error: 'invalid_request', error_description: 'state required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    if (!code_challenge || code_challenge_method !== 'S256') {
      return new Response(JSON.stringify({ error: 'invalid_request', error_description: 'PKCE (S256) required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    // Fetch and validate client metadata
    let clientMeta: any = null;
    try {
      clientMeta = await fetchClientMetadata(client_id);
    } catch (e) {
      return new Response(JSON.stringify({ error: 'invalid_client', error_description: errorMessage(e) ?? 'Client metadata fetch failed' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    if (clientMeta?.client_id !== client_id) {
      return new Response(JSON.stringify({ error: 'invalid_client', error_description: 'client_id mismatch' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    const redirects: string[] = Array.isArray(clientMeta?.redirect_uris) ? clientMeta.redirect_uris : [];
    if (!redirects.includes(redirect_uri)) {
      return new Response(JSON.stringify({ error: 'invalid_request', error_description: 'redirect_uri not registered' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    if (clientMeta?.dpop_bound_access_tokens !== true) {
      return new Response(JSON.stringify({ error: 'invalid_client', error_description: 'client must require DPoP' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    const url = new URL(request.url);
    const issuerOrigin = `${url.protocol}//${url.host}`;
    const authMethod = clientMeta?.token_endpoint_auth_method;
    if (authMethod === 'private_key_jwt') {
      // Load JWKS (inline or via URI)
      let jwks = clientMeta?.jwks;
      if (!jwks && typeof clientMeta?.jwks_uri === 'string') {
        try {
          const response = await fetch(clientMeta.jwks_uri);
          jwks = await response.json();
        } catch (e) {
          return new Response(JSON.stringify({ error: 'invalid_client', error_description: 'Failed to fetch jwks_uri' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }
      }
      if (!jwks) {
        return new Response(JSON.stringify({ error: 'invalid_client', error_description: 'Missing JWKS' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      }
      if (client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' || !client_assertion) {
        return new Response(JSON.stringify({ error: 'invalid_client', error_description: 'Missing client assertion' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      }
      const ok = await verifyClientAssertion(client_id, issuerOrigin, client_assertion, jwks);
      if (!ok) {
        return new Response(JSON.stringify({ error: 'invalid_client', error_description: 'Invalid client assertion' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      }
    }

    const id = crypto.randomUUID().replace(/-/g, '');
    const now = Math.floor(Date.now() / 1000);
    const rec = {
      client_id,
      redirect_uri,
      code_challenge,
      code_challenge_method: 'S256' as const,
      scope,
      state,
      login_hint,
      dpopJkt: ver.jkt,
      createdAt: now,
      expiresAt: now + 300, // 5 minutes
    };
    await savePar(env, id, rec);

    const request_uri = `urn:ietf:params:oauth:request_uri:${id}`;
    const headers = new Headers({ 'Content-Type': 'application/json' });
    setDpopNonceHeader(headers, await getAuthzNonce(env));
    return new Response(JSON.stringify({ request_uri }), { status: 201, headers });
  } catch (e) {
    if (e instanceof DpopNonceError) {
      return dpopErrorResponse(env, e);
    }
    const headers = new Headers({ 'Content-Type': 'application/json' });
    return new Response(JSON.stringify({ error: 'invalid_request', error_description: errorMessage(e) ?? 'Unknown error' }), { status: 400, headers });
  }
}
