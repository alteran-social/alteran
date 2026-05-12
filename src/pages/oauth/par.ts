import type { APIContext } from 'astro';
import { errorMessage } from '../../lib/errors';
import { consumeDpopVerificationJti, getAuthzNonce, setDpopNonceHeader, verifyDpop, dpopErrorResponse } from '../../lib/oauth/dpop';
import { DpopNonceError } from '../../lib/oauth/dpop-errors';
import { publicPdsOrigin } from '../../lib/oauth/consent';
import { savePar } from '../../lib/oauth/store';
import {
  safeFetchJson,
  isSafeFetchUrl,
  validateClientMetadataShape,
  validateParRequest,
  verifyClientAuthentication,
  type OAuthClientMetadata,
} from '../../lib/oauth/clients';
import {
  logOauthPar,
  readFetchContext,
  summarizeParForm,
  type OauthParFormSummary,
  type OauthParStage,
} from '../../lib/oauth/observability';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const requestId = (locals as { requestId?: string }).requestId ?? null;

  let client_id = '';
  let formSummary: OauthParFormSummary | null = null;

  const log = (
    stage: OauthParStage,
    extra: { error?: unknown; outcome?: 'ok' | 'error'; metadataStatus?: number | null; metadataContentType?: string | null; metadataRedirected?: boolean | null } = {},
  ) =>
    logOauthPar(stage, request, {
      outcome: extra.outcome ?? (extra.error !== undefined ? 'error' : 'ok'),
      requestId,
      error: extra.error,
      clientId: client_id || null,
      form: formSummary,
      metadataStatus: extra.metadataStatus,
      metadataContentType: extra.metadataContentType,
      metadataRedirected: extra.metadataRedirected,
    });

  try {
    const ver = await verifyDpop(env, request, { consumeJti: false, requireNonce: false });

    const bodyText = await request.text();
    const form = new URLSearchParams(bodyText);
    client_id = form.get('client_id') || '';
    const response_type = form.get('response_type') || '';
    const grant_type = form.get('grant_type') || undefined;
    const redirect_uri = form.get('redirect_uri') || '';
    const scope = form.get('scope') || '';
    const state = form.get('state') || '';
    const code_challenge = form.get('code_challenge') || '';
    const code_challenge_method = form.get('code_challenge_method') || '';
    const login_hint = form.get('login_hint') || undefined;
    const prompt = form.get('prompt') || undefined;
    formSummary = summarizeParForm(form);

    if (!client_id || !isSafeFetchUrl(client_id)) {
      const error = new Error('client_id must be a safe https metadata URL');
      log('metadata_fetch', { error });
      return new Response(JSON.stringify({ error: 'invalid_client', error_description: error.message }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    if (!state) {
      const error = new Error('state required');
      log('par_validate', { error });
      return new Response(JSON.stringify({ error: 'invalid_request', error_description: error.message }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    let rawMetadata: unknown;
    try {
      rawMetadata = await safeFetchJson(env, client_id, 'client metadata');
    } catch (e) {
      const ctx = readFetchContext(e);
      log('metadata_fetch', { error: e, ...ctx });
      return new Response(JSON.stringify({ error: 'invalid_client', error_description: errorMessage(e) ?? 'Client metadata fetch failed' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    let clientMeta: OAuthClientMetadata;
    try {
      clientMeta = validateClientMetadataShape(rawMetadata, client_id);
    } catch (e) {
      log('metadata_shape', { error: e });
      return new Response(JSON.stringify({ error: 'invalid_client', error_description: errorMessage(e) ?? 'Client metadata invalid' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    try {
      validateParRequest(clientMeta, {
        response_type,
        grant_type,
        redirect_uri,
        scope,
        code_challenge,
        code_challenge_method,
      });
    } catch (e) {
      log('par_validate', { error: e });
      return new Response(JSON.stringify({ error: 'invalid_client', error_description: errorMessage(e) ?? 'PAR request invalid' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    const issuerOrigin = publicPdsOrigin(env, request);
    let clientAuth;
    try {
      clientAuth = await verifyClientAuthentication(env, client_id, issuerOrigin, clientMeta, form);
    } catch (e) {
      log('client_auth', { error: e });
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
      expiresAt: now + 300,
    };
    await consumeDpopVerificationJti(env, ver);
    await savePar(env, id, rec);

    const request_uri = `urn:ietf:params:oauth:request_uri:${id}`;
    const headers = new Headers({ 'Content-Type': 'application/json' });
    setDpopNonceHeader(headers, await getAuthzNonce(env));
    log('success', { outcome: 'ok' });
    return new Response(JSON.stringify({ request_uri, expires_in: 300 }), { status: 201, headers });
  } catch (e) {
    if (e instanceof DpopNonceError) {
      log('dpop', { error: e });
      return dpopErrorResponse(env, e);
    }
    log('outer', { error: e });
    const headers = new Headers({ 'Content-Type': 'application/json' });
    return new Response(JSON.stringify({ error: 'invalid_request', error_description: errorMessage(e) ?? 'Unknown error' }), { status: 400, headers });
  }
}
