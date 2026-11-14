import type { APIContext } from 'astro';
import { readOAuthForm } from '../../lib/oauth/form';
import { dpopErrorResponse, verifyDpop } from '../../lib/oauth/dpop';
import { DpopNonceError } from '../../lib/oauth/dpop-errors';
import { publicPdsOrigin } from '../../lib/oauth/consent';
import { exchangeAuthorizationCode, exchangeRefreshToken } from '../../lib/oauth/token-grants';
import {
  logOauth,
  summarizeTokenForm,
  type OauthTokenFormSummary,
  type OauthTokenStage,
} from '../../lib/oauth/observability';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals;
  const requestId = (locals as { requestId?: string }).requestId ?? null;
  let formSummary: OauthTokenFormSummary | null = null;
  let clientId: string | null = null;

  const log = (stage: OauthTokenStage, extra: { error?: unknown; outcome?: 'ok' | 'error' } = {}) =>
    logOauth(request, {
      endpoint: 'token', stage, outcome: extra.outcome ?? (extra.error !== undefined ? 'error' : 'ok'),
      requestId, error: extra.error, clientId, form: formSummary as Record<string, unknown> | null,
    });
  const fail = (stage: OauthTokenStage, code: string, description: string): Response => {
    log(stage, { error: new Error(description) });
    return jsonError(code, description);
  };

  try {
    const proof = await verifyDpop(env, request, { consumeJti: false, requireNonce: false });
    const form = await readOAuthForm(request);
    formSummary = summarizeTokenForm(form);
    clientId = form.get('client_id') || null;
    const grant = form.get('grant_type') || '';
    if (grant !== 'authorization_code' && grant !== 'refresh_token') {
      return fail('unsupported_grant', 'unsupported_grant_type', 'grant_type must be authorization_code or refresh_token');
    }
    const context = { env, form, proof, issuer: publicPdsOrigin(env, request) };
    const result = grant === 'authorization_code'
      ? await exchangeAuthorizationCode(context)
      : await exchangeRefreshToken(context);
    if (result.tag === 'error') return fail(result.stage, result.code, result.description);
    log('success', { outcome: 'ok' });
    return new Response(JSON.stringify(result.body), {
      status: 200, headers: { 'Content-Type': 'application/json', 'DPoP-Nonce': result.nonce,
        'Cache-Control': 'no-store', Pragma: 'no-cache' },
    });
  } catch (error) {
    if (error instanceof DpopNonceError) {
      log('dpop', { error });
      return dpopErrorResponse(env, error);
    }
    log('outer', { error });
    return jsonError('invalid_request', 'OAuth request failed');
  }
}

function jsonError(code: string, description?: string): Response {
  return new Response(JSON.stringify({ error: code, error_description: description }), {
    status: 400, headers: { 'Content-Type': 'application/json' },
  });
}
