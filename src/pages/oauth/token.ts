import type { APIContext } from 'astro';
import { errorMessage } from '../../lib/errors';
import { consumeDpopVerificationJti, verifyDpop, dpopErrorResponse, getAuthzNonce, sha256b64url } from '../../lib/oauth/dpop';
import { DpopNonceError } from '../../lib/oauth/dpop-errors';
import { publicPdsOrigin } from '../../lib/oauth/consent';
import { consumeCode } from '../../lib/oauth/store';
import { issueSessionTokens, verifyRefreshToken, verifyAccessToken } from '../../lib/session-tokens';
import {
  fetchClientMetadata,
  requireSameClientAuth,
} from '../../lib/oauth/clients';
import {
  createOAuthSession,
  getOAuthSession,
  getRefreshToken,
  markOAuthRefreshUsed,
  revokeOAuthSession,
  storeRefreshToken,
  updateOAuthSessionCurrent,
} from '../../db/account';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;

  try {
    const ver = await verifyDpop(env, request, { consumeJti: false, requireNonce: false });
    const form = new URLSearchParams(await request.text());
    const grant_type = form.get('grant_type') || '';
    const issuer = publicPdsOrigin(env, request);

    if (grant_type === 'authorization_code') {
      const code = form.get('code') || '';
      const client_id = form.get('client_id') || '';
      const redirect_uri = form.get('redirect_uri') || '';
      const code_verifier = form.get('code_verifier') || '';
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

      const clientMeta = await fetchClientMetadata(env, client_id).catch((error) => {
        throw new Error(`Client metadata fetch failed: ${errorMessage(error) ?? error}`);
      });
      await requireSameClientAuth(env, client_id, issuer, clientMeta, form, {
        method: rec.clientAuthMethod,
        keyId: rec.clientAuthKeyId ?? null,
      });
      await consumeDpopVerificationJti(env, ver);

      const sessionId = crypto.randomUUID().replace(/-/g, '');
      const accessJti = crypto.randomUUID().replace(/-/g, '');
      const { accessJwt, refreshJwt, accessPayload, refreshPayload, refreshExpiry } = await issueSessionTokens(env, rec.did, {
        scope: rec.scope,
        clientId: rec.client_id,
        dpopJkt: rec.dpopJkt,
        oauthSessionId: sessionId,
        accessJti,
      });

      await createOAuthSession(env, {
        id: sessionId,
        did: rec.did,
        clientId: rec.client_id,
        clientAuthMethod: rec.clientAuthMethod,
        clientAuthKeyId: rec.clientAuthKeyId ?? null,
        dpopJkt: rec.dpopJkt,
        scope: rec.scope,
        currentRefreshTokenId: refreshPayload.jti,
        accessJti: String(accessPayload.jti),
        expiresAt: refreshExpiry,
      });
      await storeRefreshToken(env, {
        id: refreshPayload.jti,
        did: rec.did,
        expiresAt: refreshExpiry,
        appPasswordName: null,
        tokenKind: 'oauth',
        oauthSessionId: sessionId,
        clientId: rec.client_id,
        clientAuthMethod: rec.clientAuthMethod,
        clientAuthKeyId: rec.clientAuthKeyId ?? null,
        dpopJkt: rec.dpopJkt,
        oauthScope: rec.scope,
        accessJti: String(accessPayload.jti),
      });

      const expires_in = accessExpiresIn(accessPayload);
      return tokenResponse({
        access_token: accessJwt,
        token_type: 'DPoP',
        expires_in,
        refresh_token: refreshJwt,
        scope: rec.scope,
        sub: rec.did,
      }, await getAuthzNonce(env));
    }

    if (grant_type === 'refresh_token') {
      const refresh_token = form.get('refresh_token') || '';
      const client_id = form.get('client_id') || '';
      if (!refresh_token || !client_id) {
        return jsonError('invalid_request', 'Missing refresh_token or client_id');
      }

      const verification = await verifyRefreshToken(env, refresh_token).catch(() => null);
      if (!verification || !verification.decoded) return jsonError('invalid_grant', 'Invalid refresh token');
      const nowSec = Math.floor(Date.now() / 1000);
      if (verification.decoded.exp <= nowSec) return jsonError('invalid_grant', 'Expired refresh token');

      const stored = await getRefreshToken(env, verification.decoded.jti);
      if (!stored || stored.tokenKind !== 'oauth' || !stored.oauthSessionId) {
        return jsonError('invalid_grant', 'Refresh token revoked');
      }
      const session = await getOAuthSession(env, stored.oauthSessionId);
      if (!session || session.revokedAt || session.expiresAt <= nowSec) {
        return jsonError('invalid_grant', 'OAuth session revoked');
      }

      if (stored.revokedAt || stored.nextId || stored.id !== session.currentRefreshTokenId) {
        await revokeOAuthSession(env, session.id, nowSec);
        return jsonError('invalid_grant', 'Refresh token replayed');
      }
      if (stored.expiresAt <= nowSec) return jsonError('invalid_grant', 'Expired refresh token');
      if (stored.did !== verification.decoded.sub || stored.did !== session.did) {
        await revokeOAuthSession(env, session.id, nowSec);
        return jsonError('invalid_grant', 'Subject mismatch');
      }
      if (client_id !== session.clientId) return jsonError('invalid_grant', 'client_id mismatch');
      if (ver.jkt !== session.dpopJkt) return jsonError('invalid_dpop', 'DPoP key mismatch');

      const clientMeta = await fetchClientMetadata(env, client_id).catch((error) => {
        throw new Error(`Client metadata fetch failed: ${errorMessage(error) ?? error}`);
      });
      await requireSameClientAuth(env, client_id, issuer, clientMeta, form, {
        method: session.clientAuthMethod,
        keyId: session.clientAuthKeyId,
      });
      await consumeDpopVerificationJti(env, ver);

      const accessJti = crypto.randomUUID().replace(/-/g, '');
      const { accessJwt, refreshJwt, accessPayload, refreshPayload, refreshExpiry } = await issueSessionTokens(env, session.did, {
        scope: session.scope,
        clientId: session.clientId,
        dpopJkt: session.dpopJkt,
        oauthSessionId: session.id,
        accessJti,
      });
      await storeRefreshToken(env, {
        id: refreshPayload.jti,
        did: session.did,
        expiresAt: refreshExpiry,
        appPasswordName: null,
        tokenKind: 'oauth',
        oauthSessionId: session.id,
        clientId: session.clientId,
        clientAuthMethod: session.clientAuthMethod as any,
        clientAuthKeyId: session.clientAuthKeyId,
        dpopJkt: session.dpopJkt,
        oauthScope: session.scope,
        accessJti: String(accessPayload.jti),
      });
      try {
        await markOAuthRefreshUsed(env, stored.id, refreshPayload.jti, nowSec);
        await updateOAuthSessionCurrent(env, session.id, {
          currentRefreshTokenId: refreshPayload.jti,
          previousRefreshTokenId: stored.id,
          accessJti: String(accessPayload.jti),
          expiresAt: refreshExpiry,
          now: nowSec,
        });
      } catch {
        await revokeOAuthSession(env, session.id, nowSec);
        return jsonError('invalid_grant', 'Refresh token replayed');
      }

      return tokenResponse({
        access_token: accessJwt,
        token_type: 'DPoP',
        expires_in: accessExpiresIn(accessPayload),
        refresh_token: refreshJwt,
        scope: session.scope,
        sub: session.did,
      }, await getAuthzNonce(env));
    }

    return jsonError('unsupported_grant_type', 'grant_type must be authorization_code or refresh_token');
  } catch (e) {
    if (e instanceof DpopNonceError) return dpopErrorResponse(env, e);
    return jsonError('invalid_request', errorMessage(e) ?? 'Unknown error');
  }
}

function accessExpiresIn(payload: Awaited<ReturnType<typeof verifyAccessToken>> | Record<string, unknown>): number {
  const now = Math.floor(Date.now() / 1000);
  return typeof payload.exp === 'number' ? Math.max(0, payload.exp - now) : 7200;
}

function tokenResponse(body: Record<string, unknown>, nonce: string): Response {
  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.set('DPoP-Nonce', nonce);
  return new Response(JSON.stringify(body), { status: 200, headers });
}

function jsonError(code: string, desc?: string): Response {
  const headers = new Headers({ 'Content-Type': 'application/json' });
  return new Response(JSON.stringify({ error: code, error_description: desc }), { status: 400, headers });
}
