import type { APIContext } from 'astro';
import { errorMessage } from '../../lib/errors';
import { consumeDpopVerificationJti, verifyDpop, dpopErrorResponse } from '../../lib/oauth/dpop';
import { DpopNonceError } from '../../lib/oauth/dpop-errors';
import { publicPdsOrigin } from '../../lib/oauth/consent';
import { verifyAccessToken, verifyRefreshToken } from '../../lib/session-tokens';
import { requireStoredClientAuthentication } from '../../lib/oauth/clients';
import { getOAuthSession, getRefreshToken, revokeOAuthSession, revokeRefreshToken } from '../../db/account';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  try {
    const dpop = await verifyDpop(env, request, { consumeJti: false, requireNonce: false });
    const form = new URLSearchParams(await request.text());
    const token = form.get('token') || '';
    const client_id = form.get('client_id') || '';
    if (!token || !client_id) {
      return jsonError('invalid_request', 'Missing token or client_id', 400);
    }

    const issuer = publicPdsOrigin(env, request);

    const refresh = await verifyRefreshToken(env, token, { ignoreExpiration: true }).catch(() => null);
    if (refresh?.decoded?.jti) {
      const stored = await getRefreshToken(env, refresh.decoded.jti);
      if (stored?.tokenKind === 'oauth' && stored.oauthSessionId) {
        const session = await getOAuthSession(env, stored.oauthSessionId);
        if (session && session.clientId === client_id && session.dpopJkt === dpop.jkt) {
          await requireStoredClientAuthentication(env, client_id, issuer, form, {
            method: session.clientAuthMethod,
            keyId: session.clientAuthKeyId,
          });
          await consumeDpopVerificationJti(env, dpop);
          await revokeOAuthSession(env, session.id);
          await revokeRefreshToken(env, stored.id);
        }
      }
      return emptyOk();
    }

    const access = await verifyAccessToken(env, token).catch(() => null);
    const sessionId = access?.oauth_session;
    if (typeof sessionId === 'string') {
      const session = await getOAuthSession(env, sessionId);
      if (session && session.clientId === client_id && session.dpopJkt === dpop.jkt) {
        await requireStoredClientAuthentication(env, client_id, issuer, form, {
          method: session.clientAuthMethod,
          keyId: session.clientAuthKeyId,
        });
        await consumeDpopVerificationJti(env, dpop);
        await revokeOAuthSession(env, session.id);
        await revokeRefreshToken(env, session.currentRefreshTokenId);
      }
    }

    return emptyOk();
  } catch (error) {
    if (error instanceof DpopNonceError) return dpopErrorResponse(env, error);
    return jsonError('invalid_request', errorMessage(error) ?? 'Unknown error', 400);
  }
}

function emptyOk(): Response {
  return new Response('', { status: 200 });
}

function jsonError(code: string, desc: string, status: number): Response {
  return new Response(JSON.stringify({ error: code, error_description: desc }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
