import type { APIContext } from 'astro';
import { bearerToken } from '../../lib/util';
import { verifyRefreshToken } from '../../lib/session-tokens';
import { getRefreshToken, revokeOAuthSession, deleteRefreshToken } from '../../db/account';

export const prerender = false;

/**
 * com.atproto.server.deleteSession
 * Delete the current refresh credential. OAuth refresh rows also revoke the
 * owning OAuth session, which invalidates the current DPoP-bound access token.
 */
export async function POST({ locals, request }: APIContext) {
  const { env } = locals;
  const token = bearerToken(request);
  if (!token) {
    return new Response(JSON.stringify({ error: 'AuthRequired', message: 'No authorization token provided' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const verification = await verifyRefreshToken(env, token, { ignoreExpiration: true }).catch(() => null);
  const jti = verification?.decoded?.jti;
  if (!jti) {
    return new Response(JSON.stringify({ error: 'InvalidToken', message: 'Invalid refresh token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const stored = await getRefreshToken(env, jti);
  if (stored?.tokenKind === 'oauth' && stored.oauthSessionId) {
    await revokeOAuthSession(env, stored.oauthSessionId);
  }
  await deleteRefreshToken(env, jti);

  return new Response(JSON.stringify({}), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
    },
  });
}
