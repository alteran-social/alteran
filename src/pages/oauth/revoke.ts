import type { APIContext } from 'astro';
import { errorMessage } from '../../lib/errors';
import { verifyDpop, dpopErrorResponse } from '../../lib/oauth/dpop';
import { DpopNonceError } from '../../lib/oauth/dpop-errors';
import { publicPdsOrigin } from '../../lib/oauth/consent';
import { readOAuthForm } from '../../lib/oauth/form';
import { verifyAccessToken, verifyRefreshToken } from '../../lib/session-tokens';
import { loadOAuthRefreshSnapshot, loadOAuthSessionSnapshot } from '../../db/oauth-exchange-read';
import { revokeAuthenticatedSession } from '../../lib/oauth/revoke-session';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals;
  try {
    const dpop = await verifyDpop(env, request, { consumeJti: false, requireNonce: false });
    const form = await readOAuthForm(request);
    const token = form.get('token') || '';
    const client_id = form.get('client_id') || '';
    if (!token || !client_id) {
      return jsonError('invalid_request', 'Missing token or client_id', 400);
    }

    const issuer = publicPdsOrigin(env, request);

    const refresh = await verifyRefreshToken(env, token, { ignoreExpiration: true }).catch(() => null);
    if (typeof refresh?.payload.jti === 'string') {
      const snapshot = await loadOAuthRefreshSnapshot(env, refresh.payload.jti);
      if (snapshot) {
        const { refresh: stored, session } = snapshot;
        const confirmation = refresh.payload.cnf as { jkt?: unknown } | undefined;
        if (stored.tokenKind === 'oauth' && stored.did === session.did && refresh.payload.sub === session.did &&
          stored.clientId === session.clientId && refresh.payload.client_id === session.clientId &&
          stored.oauthSessionId === session.id && refresh.payload.oauth_session === session.id &&
          stored.dpopJkt === session.dpopJkt && confirmation?.jkt === session.dpopJkt &&
          stored.clientAuthMethod === session.clientAuthMethod && stored.clientAuthKeyId === session.clientAuthKeyId &&
          stored.oauthScope === session.scope && session.clientId === client_id && session.dpopJkt === dpop.jkt) {
          await revokeAuthenticatedSession(env, session, dpop, issuer, form, undefined, stored);
        }
      }
      return emptyOk();
    }

    const access = await verifyAccessToken(env, token).catch(() => null);
    const sessionId = access?.oauth_session;
    if (typeof sessionId === 'string') {
      const session = await loadOAuthSessionSnapshot(env, sessionId);
      const confirmation = access?.cnf as { jkt?: unknown } | undefined;
      if (session && access?.sub === session.did && access.client_id === session.clientId &&
        access.jti === session.accessJti && access.scope === session.scope &&
        confirmation?.jkt === session.dpopJkt && session.clientId === client_id && session.dpopJkt === dpop.jkt) {
        if (typeof access.exp !== 'number' || !Number.isFinite(access.exp)) return emptyOk();
        await revokeAuthenticatedSession(env, session, dpop, issuer, form, access.exp);
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
