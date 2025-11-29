import type { APIContext } from 'astro';
import { bearerToken } from '../../lib/util';
import { lazyCleanupExpiredTokens } from '../../lib/token-cleanup';
import { getRuntimeString } from '../../lib/secrets';
import { getAccountByIdentifier, getRefreshToken, markRefreshTokenRotated, storeRefreshToken } from '../../db/account';
import { verifyRefreshToken, issueSessionTokens, computeGraceExpiry } from '../../lib/session-tokens';
import { buildDidDocument } from '../../lib/did-document';

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

  // Determine the next refresh token id: upon refresh token reuse during grace period,
  // you always receive a refresh token with the same id (matching official PDS behavior)
  const nextId = stored.nextId ?? undefined;

  // Rotate: generate new token pair with the expected JTI
  const { accessJwt, refreshJwt, refreshPayload, refreshExpiry } = await issueSessionTokens(env, did, { jti: nextId });

  // Check if token was already rotated to a DIFFERENT token (reuse attack detection)
  // Allow reuse during grace period if nextId matches what we're about to issue
  if (stored.nextId && stored.nextId !== refreshPayload.jti) {
    return new Response(
      JSON.stringify({ error: 'InvalidToken', message: 'Refresh token has been revoked' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  // Only store and rotate if this is a fresh rotation (not a reuse during grace period)
  if (!stored.nextId) {
    await storeRefreshToken(env, {
      id: refreshPayload.jti,
      did,
      expiresAt: refreshExpiry,
      appPasswordName: stored.appPasswordName ?? null,
    });

    const graceExpiry = computeGraceExpiry(stored.expiresAt, nowSec);
    await markRefreshTokenRotated(env, decoded.jti, refreshPayload.jti, graceExpiry);
  }

  // Lazy cleanup of expired tokens (runs 1% of the time)
  lazyCleanupExpiredTokens(env).catch(console.error);

  // Build didDoc for the response (required by official API contract)
  const didDoc = await buildDidDocument(env, did, handle);

  return new Response(JSON.stringify({ did, didDoc, handle, accessJwt, refreshJwt, active: true }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
