import type { APIContext } from 'astro';
import { errorMessage } from '../../lib/errors';
import { consumeDpopVerificationJti, getAuthzNonce, setDpopNonceHeader, verifyDpop, dpopErrorResponse } from '../../lib/oauth/dpop';
import { DpopNonceError } from '../../lib/oauth/dpop-errors';
import { publicPdsOrigin } from '../../lib/oauth/consent';
import { savePar } from '../../lib/oauth/store';
import {
  fetchClientMetadata,
  isSafeFetchUrl,
  validateParRequest,
  verifyClientAuthentication,
} from '../../lib/oauth/clients';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;

  // Enforce DPoP with nonce; if missing or stale, return use_dpop_nonce
  try {
    const ver = await verifyDpop(env, request, { consumeJti: false });

    // Parse form-encoded body
    const bodyText = await request.text();
    const form = new URLSearchParams(bodyText);
    const client_id = form.get('client_id') || '';
    const response_type = form.get('response_type') || '';
    const grant_type = form.get('grant_type') || undefined;
    const redirect_uri = form.get('redirect_uri') || '';
    const scope = form.get('scope') || '';
    const state = form.get('state') || '';
    const code_challenge = form.get('code_challenge') || '';
    const code_challenge_method = form.get('code_challenge_method') || '';
    const login_hint = form.get('login_hint') || undefined;
    const prompt = form.get('prompt') || undefined;

    if (!client_id || !isSafeFetchUrl(client_id)) {
      return new Response(JSON.stringify({ error: 'invalid_client', error_description: 'client_id must be a safe https metadata URL' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    if (!state) {
      return new Response(JSON.stringify({ error: 'invalid_request', error_description: 'state required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    // Fetch and validate client metadata
    let clientMeta;
    try {
      clientMeta = await fetchClientMetadata(env, client_id);
      validateParRequest(clientMeta, {
        response_type,
        grant_type,
        redirect_uri,
        scope,
        code_challenge,
        code_challenge_method,
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: 'invalid_client', error_description: errorMessage(e) ?? 'Client metadata fetch failed' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    const issuerOrigin = publicPdsOrigin(env, request);
    let clientAuth;
    try {
      clientAuth = await verifyClientAuthentication(env, client_id, issuerOrigin, clientMeta, form);
    } catch (e) {
      return new Response(JSON.stringify({ error: 'invalid_client', error_description: errorMessage(e) ?? 'Client authentication failed' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
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
      prompt,
      dpopJkt: ver.jkt,
      clientAuthMethod: clientAuth.method,
      clientAuthKeyId: clientAuth.keyId,
      createdAt: now,
      expiresAt: now + 300, // 5 minutes
    };
    await consumeDpopVerificationJti(env, ver);
    await savePar(env, id, rec);

    const request_uri = `urn:ietf:params:oauth:request_uri:${id}`;
    const headers = new Headers({ 'Content-Type': 'application/json' });
    setDpopNonceHeader(headers, await getAuthzNonce(env));
    return new Response(JSON.stringify({ request_uri, expires_in: 300 }), { status: 201, headers });
  } catch (e) {
    if (e instanceof DpopNonceError) {
      return dpopErrorResponse(env, e);
    }
    const headers = new Headers({ 'Content-Type': 'application/json' });
    return new Response(JSON.stringify({ error: 'invalid_request', error_description: errorMessage(e) ?? 'Unknown error' }), { status: 400, headers });
  }
}
