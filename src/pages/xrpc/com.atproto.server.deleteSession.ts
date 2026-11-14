import type { APIContext } from 'astro';
import { bearerToken } from '../../lib/util';
import { isOAuthBoundRefresh, verifyRefreshToken } from '../../lib/session-tokens';

export const prerender = false;

/**
 * com.atproto.server.deleteSession
 * Delete a legacy bearer refresh credential.
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
  const payload = verification?.payload;
  const jti = payload?.jti;
  if (typeof jti !== 'string' || !jti || jti.length > 8192 || typeof payload?.sub !== 'string' ||
    isOAuthBoundRefresh(payload)) {
    return new Response(JSON.stringify({ error: 'InvalidToken', message: 'Invalid refresh token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const deleted = await env.ALTERAN_DB.prepare(`DELETE FROM refresh_token
    WHERE id = ? AND did = ? AND token_kind = 'legacy' AND oauth_session_id IS NULL RETURNING id`)
    .bind(jti, payload.sub).first<{ id: string }>();
  if (!deleted) {
    const existing = await env.ALTERAN_DB.prepare('SELECT EXISTS (SELECT 1 FROM refresh_token WHERE id = ?) AS present')
      .bind(jti).first<{ present: number }>();
    if (!existing || existing.present !== 0) {
      return new Response(JSON.stringify({ error: 'InvalidToken', message: 'Invalid refresh token' }), {
        status: 401, headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  return new Response(JSON.stringify({}), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
    },
  });
}
