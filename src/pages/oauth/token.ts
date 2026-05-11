import type { APIContext } from 'astro';
import { verifyDpop, dpopErrorResponse, getAuthzNonce } from '../../lib/oauth/dpop';
import { consumeCode } from '../../lib/oauth/store';
import { sha256b64url } from '../../lib/oauth/dpop';
import { issueSessionTokens, verifyRefreshToken, verifyAccessToken, computeGraceExpiry } from '../../lib/session-tokens';
import { fetchClientMetadata, verifyClientAssertion } from '../../lib/oauth/clients';
import { storeRefreshToken, getRefreshToken, markRefreshTokenRotated } from '../../db/account';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;

  try {
    const ver = await verifyDpop(env, request);

    const form = new URLSearchParams(await request.text());
    const grant_type = form.get('grant_type') || '';

    if (grant_type === 'authorization_code') {
      const code = form.get('code') || '';
      const client_id = form.get('client_id') || '';
      const redirect_uri = form.get('redirect_uri') || '';
      const code_verifier = form.get('code_verifier') || '';
      const client_assertion_type = form.get('client_assertion_type') || '';
      const client_assertion = form.get('client_assertion') || '';

      if (!code || !client_id || !redirect_uri || !code_verifier) {
        return jsonError('invalid_request', 'Missing parameters');
      }

      const rec = await consumeCode(env, code);
      if (!rec) return jsonError('invalid_grant', 'Invalid or used code');
      if (rec.client_id !== client_id) return jsonError('invalid_grant', 'client_id mismatch');
      if (rec.redirect_uri !== redirect_uri) return jsonError('invalid_grant', 'redirect_uri mismatch');

      const expected = await sha256b64url(code_verifier);
      if (expected !== rec.code_challenge) return jsonError('invalid_grant', 'PKCE verification failed');

      if (ver.jkt !== rec.dpopJkt) return jsonError('invalid_dpop', 'DPoP key mismatch');

      // If confidential client, verify assertion
      let clientMeta: any = null;
      try {
        clientMeta = await fetchClientMetadata(client_id);
      } catch {
        // Public clients have no fetchable metadata; only confidential clients gate on it below.
      }
      if (clientMeta?.token_endpoint_auth_method === 'private_key_jwt') {
        let jwks = clientMeta?.jwks;
        if (!jwks && typeof clientMeta?.jwks_uri === 'string') {
          const response = await fetch(clientMeta.jwks_uri);
          jwks = await response.json();
        }
        const origin = `${new URL(request.url).protocol}//${new URL(request.url).host}`;
        if (!client_assertion || client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
          return jsonError('invalid_client', 'Missing client assertion');
        const ok = await verifyClientAssertion(client_id, origin, client_assertion, jwks);
        if (!ok) return jsonError('invalid_client', 'Invalid client assertion');
      }

      // Issue tokens bound to this DID and include DPoP cnf in access token
      const { accessJwt, refreshJwt, refreshPayload, refreshExpiry } = await issueSessionTokens(env, rec.did);
      await storeRefreshToken(env, { id: refreshPayload.jti, did: rec.did, expiresAt: refreshExpiry, appPasswordName: null });

      // Derive expires_in from access token
      const payload = await verifyAccessToken(env, accessJwt).catch(() => null);
      const now = Math.floor(Date.now() / 1000);
      const expires_in = payload && typeof payload.exp === 'number' ? Math.max(0, payload.exp - now) : 7200;

      const out = {
        access_token: accessJwt,
        token_type: 'DPoP',
        expires_in,
        refresh_token: refreshJwt,
        scope: rec.scope,
        sub: rec.did,
      } as const;
      const headers = new Headers({ 'Content-Type': 'application/json' });
      headers.set('DPoP-Nonce', await getAuthzNonce(env));
      return new Response(JSON.stringify(out), { status: 200, headers });
    }

    if (grant_type === 'refresh_token') {
      const refresh_token = form.get('refresh_token') || '';
      const client_id = form.get('client_id') || '';
      const client_assertion_type = form.get('client_assertion_type') || '';
      const client_assertion = form.get('client_assertion') || '';
      if (!refresh_token) return jsonError('invalid_request', 'Missing refresh_token');

      // If confidential client, verify assertion
      if (client_id) {
        let clientMeta: any = null;
        try {
          clientMeta = await fetchClientMetadata(client_id);
        } catch {
          // Public clients have no fetchable metadata; only confidential clients gate on it below.
        }
        if (clientMeta?.token_endpoint_auth_method === 'private_key_jwt') {
          let jwks = clientMeta?.jwks;
          if (!jwks && typeof clientMeta?.jwks_uri === 'string') {
            const response = await fetch(clientMeta.jwks_uri);
            jwks = await response.json();
          }
          const origin = `${new URL(request.url).protocol}//${new URL(request.url).host}`;
          if (!client_assertion || client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
            return jsonError('invalid_client', 'Missing client assertion');
          const ok = await verifyClientAssertion(client_id, origin, client_assertion, jwks);
          if (!ok) return jsonError('invalid_client', 'Invalid client assertion');
        }
      }

      const verification = await verifyRefreshToken(env, refresh_token).catch(() => null);
      if (!verification || !verification.decoded) return jsonError('invalid_grant', 'Invalid refresh token');
      const nowSec = Math.floor(Date.now() / 1000);
      if (verification.decoded.exp <= nowSec) return jsonError('invalid_grant', 'Expired refresh token');

      const stored = await getRefreshToken(env, verification.decoded.jti);
      if (!stored) return jsonError('invalid_grant', 'Refresh token revoked');
      if (stored.expiresAt <= nowSec) return jsonError('invalid_grant', 'Expired refresh token');
      if (stored.did !== verification.decoded.sub) return jsonError('invalid_grant', 'Subject mismatch');

      const did = stored.did;
      // Rotate refresh, issue new pair
      const { accessJwt, refreshJwt, refreshPayload, refreshExpiry } = await issueSessionTokens(env, did, { jti: stored.nextId ?? undefined });
      await storeRefreshToken(env, { id: refreshPayload.jti, did, expiresAt: refreshExpiry, appPasswordName: stored.appPasswordName ?? null });
      const graceExpiry = computeGraceExpiry(stored.expiresAt, nowSec);
      await markRefreshTokenRotated(env, verification.decoded.jti, refreshPayload.jti, graceExpiry);

      const payload = await verifyAccessToken(env, accessJwt).catch(() => null);
      const expires_in = payload && typeof payload.exp === 'number' ? Math.max(0, payload.exp - nowSec) : 7200;

      const out = {
        access_token: accessJwt,
        token_type: 'DPoP',
        expires_in,
        refresh_token: refreshJwt,
        scope: 'atproto',
        sub: did,
      } as const;
      const headers = new Headers({ 'Content-Type': 'application/json' });
      headers.set('DPoP-Nonce', await getAuthzNonce(env));
      return new Response(JSON.stringify(out), { status: 200, headers });
    }

    return jsonError('unsupported_grant_type', 'grant_type must be authorization_code or refresh_token');
  } catch (e: any) {
    if (e && e.code === 'use_dpop_nonce') return dpopErrorResponse(env, e);
    return jsonError('invalid_request', e?.message ?? 'Unknown error');
  }
}

function jsonError(code: string, desc?: string): Response {
  const headers = new Headers({ 'Content-Type': 'application/json' });
  return new Response(JSON.stringify({ error: code, error_description: desc }), { status: 400, headers });
}
