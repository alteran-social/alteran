import type { APIContext } from 'astro';
import { expect } from '@std/expect';
import { SignJWT } from 'jose';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { makeDpopKey, signDpopProof } from './helpers/oauth';
import { createOAuthSession, getOAuthSession } from './helpers/oauth-store';
import { getRefreshToken, storeRefreshToken } from '../src/db/account';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { POST as deletePost } from '../src/pages/xrpc/com.atproto.server.deleteSession';
import { POST as tokenPost } from '../src/pages/oauth/token';
import type { Env } from '../src/env';

const DID = 'did:example:test';
const CLIENT = 'https://client.example/metadata';
const SECRET = 'delete-session-binding-test-secret';
const TOKEN_URL = 'https://pds.example/oauth/token';
const DELETE_URL = 'https://pds.example/xrpc/com.atproto.server.deleteSession';

function remove(env: Env, token: string) {
  const request = new Request(DELETE_URL, { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
  return deletePost({ locals: { env }, request } as unknown as APIContext);
}

describe('legacy deleteSession token binding', () => {
  it('deletes an ordinary legacy refresh credential idempotently', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const tokens = await issueSessionTokens(env, DID);
    await storeRefreshToken(env, { id: tokens.refreshPayload.jti, did: DID, expiresAt: tokens.refreshExpiry });
    expect((await remove(env, tokens.refreshJwt)).status).toBe(200);
    expect(await getRefreshToken(env, tokens.refreshPayload.jti)).toBeNull();
    expect((await remove(env, tokens.refreshJwt)).status).toBe(200);
  });

  it('cannot revoke a current or rotated OAuth refresh token as Bearer', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const key = await makeDpopKey();
    const session = crypto.randomUUID();
    const accessJti = crypto.randomUUID();
    const tokens = await issueSessionTokens(env, DID, { accessScope: 'atproto', clientId: CLIENT,
      dpopJkt: key.jkt, oauthSessionId: session, accessJti });
    await createOAuthSession(env, { id: session, did: DID, clientId: CLIENT, clientAuthMethod: 'none', dpopJkt: key.jkt,
      scope: 'atproto', currentRefreshTokenId: tokens.refreshPayload.jti, accessJti, expiresAt: tokens.refreshExpiry });
    await storeRefreshToken(env, { id: tokens.refreshPayload.jti, did: DID, expiresAt: tokens.refreshExpiry, tokenKind: 'oauth',
      oauthSessionId: session, clientId: CLIENT, clientAuthMethod: 'none', dpopJkt: key.jkt, oauthScope: 'atproto', accessJti });
    expect((await remove(env, tokens.refreshJwt)).status).toBe(401);
    expect((await getOAuthSession(env, session))?.revokedAt).toBeNull();
    const proof = await signDpopProof({ key, method: 'POST', url: TOKEN_URL });
    const rotation = await tokenPost({ locals: { env }, request: new Request(TOKEN_URL, { method: 'POST',
      headers: { DPoP: proof }, body: new URLSearchParams({ grant_type: 'refresh_token', client_id: CLIENT,
        refresh_token: tokens.refreshJwt }) }) } as unknown as APIContext);
    expect(rotation.status).toBe(200);
    const successor = (await rotation.json() as { refresh_token: string }).refresh_token;
    const current = await getOAuthSession(env, session);
    expect((await remove(env, tokens.refreshJwt)).status).toBe(401);
    expect((await remove(env, successor)).status).toBe(401);
    expect((await getOAuthSession(env, session))?.revokedAt).toBeNull();
    expect(await getRefreshToken(env, tokens.refreshPayload.jti)).not.toBeNull();
    expect(await getRefreshToken(env, current!.currentRefreshTokenId)).not.toBeNull();
  });

  it('rejects signed binding claims and inconsistent legacy rows without deletion', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const tokens = await issueSessionTokens(env, DID);
    await storeRefreshToken(env, { id: tokens.refreshPayload.jti, did: DID, expiresAt: tokens.refreshExpiry });
    const now = Math.floor(Date.now() / 1000);
    for (const claims of [{ cnf: null }, { client_id: null }, { oauth_session: null }]) {
      const token = await new SignJWT({ scope: 'com.atproto.refresh', jti: tokens.refreshPayload.jti, ...claims })
        .setProtectedHeader({ alg: 'HS256', typ: 'refresh+jwt' }).setSubject(DID).setAudience(DID)
        .setIssuedAt(now).setExpirationTime(now + 600).sign(new TextEncoder().encode(SECRET));
      expect((await remove(env, token)).status).toBe(401);
      expect(await getRefreshToken(env, tokens.refreshPayload.jti)).not.toBeNull();
    }
    await env.ALTERAN_DB.prepare('UPDATE refresh_token SET oauth_session_id = ? WHERE id = ?')
      .bind('inconsistent-session', tokens.refreshPayload.jti).run();
    expect((await remove(env, tokens.refreshJwt)).status).toBe(401);
    expect(await getRefreshToken(env, tokens.refreshPayload.jti)).not.toBeNull();
  });
});
