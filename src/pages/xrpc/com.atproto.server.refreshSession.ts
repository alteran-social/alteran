import type { APIContext } from 'astro';
import { bearerToken } from '../../lib/util';
import { lazyCleanupExpiredTokens } from '../../lib/token-cleanup';
import { getRuntimeString } from '../../lib/secrets';
import { getAccountByIdentifier, getRefreshToken, markRefreshTokenRotated, storeRefreshToken } from '../../db/account';
import { verifyRefreshToken, issueSessionTokens, computeGraceExpiry } from '../../lib/session-tokens';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;

  const token = bearerToken(request);
  if (!token) {
    return new Response(
      JSON.stringify({ error: 'AuthRequired', message: 'No authorization token provided' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const verification = await verifyRefreshToken(env, token).catch(() => {
    return null;
  });

  if (!verification) {
    return new Response(
      JSON.stringify({ error: 'InvalidToken', message: 'Invalid or expired refresh token' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const { decoded } = verification;

  if (!decoded || typeof decoded.jti !== 'string') {
    return new Response(
      JSON.stringify({ error: 'InvalidToken', message: 'Malformed refresh token' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (typeof decoded.exp !== 'number' || decoded.exp <= nowSec) {
    return new Response(
      JSON.stringify({ error: 'ExpiredToken', message: 'Refresh token expired' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const stored = await getRefreshToken(env, decoded.jti);
  if (!stored) {
    return new Response(
      JSON.stringify({ error: 'InvalidToken', message: 'Refresh token has been revoked' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  // THIS IS THE FIX: Check if the token has already been used for rotation.
  if (stored.nextId) {
    return new Response(
      JSON.stringify({ error: 'InvalidToken', message: 'Refresh token has been revoked' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (stored.expiresAt <= nowSec) {
    return new Response(
      JSON.stringify({ error: 'ExpiredToken', message: 'Refresh token expired' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (stored.did !== decoded.sub) {
    return new Response(
      JSON.stringify({ error: 'InvalidToken', message: 'Token subject mismatch' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const account = await getAccountByIdentifier(env, stored.did);
  const did = stored.did;
  const handle = account?.handle ?? (await getRuntimeString(env, 'PDS_HANDLE', 'user.example'));

  // Rotate: generate new token pair with new JTI
  const { accessJwt, refreshJwt, refreshPayload, refreshExpiry } = await issueSessionTokens(env, did, { jti: stored.nextId ?? undefined });

  await storeRefreshToken(env, {
    id: refreshPayload.jti,
    did,
    expiresAt: refreshExpiry,
    appPasswordName: stored.appPasswordName ?? null,
  });

  const graceExpiry = computeGraceExpiry(stored.expiresAt, nowSec);
  await markRefreshTokenRotated(env, decoded.jti, refreshPayload.jti, graceExpiry);

  // Lazy cleanup of expired tokens (runs 1% of the time)
  lazyCleanupExpiredTokens(env).catch(console.error);

  return new Response(JSON.stringify({ did, handle, accessJwt, refreshJwt }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
