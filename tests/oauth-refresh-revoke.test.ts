import { describe, expect, it } from 'bun:test';
import { makeEnv } from './helpers/env';
import { makeDpopKey, mockClientMetadata, signAuthzDpop, signDpopProof, signResourceDpop } from './helpers/oauth';
import { createOAuthSession, getOAuthSession, getRefreshToken, storeRefreshToken } from '../src/db/account';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { saveCode } from '../src/lib/oauth/store';
import { sha256b64url } from '../src/lib/oauth/dpop';
import { POST as tokenPost } from '../src/pages/oauth/token';
import { POST as revokePost } from '../src/pages/oauth/revoke';
import { POST as deleteSessionPost } from '../src/pages/xrpc/com.atproto.server.deleteSession';
import { verifyResourceRequestHybrid } from '../src/lib/oauth/resource';
import { attemptRefresh } from '../src/lib/refresh-session';

const clientId = 'https://client.example/metadata';

async function issueOauthRefresh(env: any, key: Awaited<ReturnType<typeof makeDpopKey>>) {
  const sessionId = crypto.randomUUID().replace(/-/g, '');
  const accessJti = crypto.randomUUID().replace(/-/g, '');
  const { accessJwt, refreshJwt, accessPayload, refreshPayload, refreshExpiry } = await issueSessionTokens(env, 'did:example:test', {
    scope: 'atproto',
    clientId,
    dpopJkt: key.jkt,
    oauthSessionId: sessionId,
    accessJti,
  });
  await createOAuthSession(env, {
    id: sessionId,
    did: 'did:example:test',
    clientId,
    clientAuthMethod: 'none',
    clientAuthKeyId: null,
    dpopJkt: key.jkt,
    scope: 'atproto',
    currentRefreshTokenId: refreshPayload.jti,
    accessJti: String(accessPayload.jti),
    expiresAt: refreshExpiry,
  });
  await storeRefreshToken(env, {
    id: refreshPayload.jti,
    did: 'did:example:test',
    expiresAt: refreshExpiry,
    tokenKind: 'oauth',
    oauthSessionId: sessionId,
    clientId,
    clientAuthMethod: 'none',
    dpopJkt: key.jkt,
    oauthScope: 'atproto',
    accessJti: String(accessPayload.jti),
  });
  return { sessionId, accessJwt, refreshJwt, refreshJti: refreshPayload.jti };
}

function apiContext(env: any, request: Request) {
  return { locals: { runtime: { env } }, request } as any;
}

describe('OAuth refresh and revocation state', () => {
  it('exchanges authorization codes with a DPoP proof that has no nonce', async () => {
    const restore = mockClientMetadata(clientId);
    try {
      const env = await makeEnv();
      const key = await makeDpopKey();
      const url = 'https://pds.example/oauth/token';
      const code = 'code-without-dpop-nonce';
      const codeVerifier = 'correct horse battery staple';
      const now = Math.floor(Date.now() / 1000);
      await saveCode(env, code, {
        code,
        client_id: clientId,
        redirect_uri: 'https://client.example/callback',
        code_challenge: await sha256b64url(codeVerifier),
        scope: 'atproto',
        dpopJkt: key.jkt,
        clientAuthMethod: 'none',
        clientAuthKeyId: null,
        did: 'did:example:test',
        createdAt: now,
        expiresAt: now + 300,
      });

      const proof = await signDpopProof({ key, method: 'POST', url });
      const res = await tokenPost(apiContext(env, new Request(url, {
        method: 'POST',
        headers: { dpop: proof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          redirect_uri: 'https://client.example/callback',
          code_verifier: codeVerifier,
        }).toString(),
      })));
      expect(res.status).toBe(200);
      expect(res.headers.get('DPoP-Nonce')).toBeTruthy();
      const body = await res.json() as any;
      expect(body.token_type).toBe('DPoP');
      expect(typeof body.refresh_token).toBe('string');
    } finally {
      restore();
    }
  });

  it('binds refresh to client and DPoP key, then fails closed on replay', async () => {
    const restore = mockClientMetadata(clientId);
    try {
      const env = await makeEnv();
      const key = await makeDpopKey();
      const issued = await issueOauthRefresh(env, key);
      const url = 'https://pds.example/oauth/token';

      const proof = await signAuthzDpop(env, key, 'POST', url);
      const ok = await tokenPost(apiContext(env, new Request(url, {
        method: 'POST',
        headers: { dpop: proof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: issued.refreshJwt, client_id: clientId }).toString(),
      })));
      expect(ok.status).toBe(200);
      const okBody = await ok.json() as any;
      expect(okBody.token_type).toBe('DPoP');
      expect(typeof okBody.refresh_token).toBe('string');

      const replayProof = await signAuthzDpop(env, key, 'POST', url);
      const replay = await tokenPost(apiContext(env, new Request(url, {
        method: 'POST',
        headers: { dpop: replayProof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: issued.refreshJwt, client_id: clientId }).toString(),
      })));
      expect(replay.status).toBe(400);
      expect(((await replay.json()) as any).error_description).toContain('replay');
      expect((await getOAuthSession(env, issued.sessionId))?.revokedAt).toBeTruthy();

      const successorProof = await signAuthzDpop(env, key, 'POST', url);
      const successor = await tokenPost(apiContext(env, new Request(url, {
        method: 'POST',
        headers: { dpop: successorProof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: okBody.refresh_token, client_id: clientId }).toString(),
      })));
      expect(successor.status).toBe(400);
    } finally {
      restore();
    }
  });

  it('refreshes with a DPoP proof that has no nonce', async () => {
    const restore = mockClientMetadata(clientId);
    try {
      const env = await makeEnv();
      const key = await makeDpopKey();
      const issued = await issueOauthRefresh(env, key);
      const url = 'https://pds.example/oauth/token';
      const proof = await signDpopProof({ key, method: 'POST', url });

      const res = await tokenPost(apiContext(env, new Request(url, {
        method: 'POST',
        headers: { dpop: proof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: issued.refreshJwt, client_id: clientId }).toString(),
      })));
      expect(res.status).toBe(200);
      expect(res.headers.get('DPoP-Nonce')).toBeTruthy();
      const body = await res.json() as any;
      expect(body.token_type).toBe('DPoP');
      expect(typeof body.refresh_token).toBe('string');
    } finally {
      restore();
    }
  });

  it('rejects refresh with wrong client or wrong DPoP key', async () => {
    const restore = mockClientMetadata(clientId);
    try {
      const env = await makeEnv();
      const key = await makeDpopKey();
      const wrong = await makeDpopKey();
      const issued = await issueOauthRefresh(env, key);
      const url = 'https://pds.example/oauth/token';

      const wrongClientProof = await signAuthzDpop(env, key, 'POST', url);
      const wrongClient = await tokenPost(apiContext(env, new Request(url, {
        method: 'POST',
        headers: { dpop: wrongClientProof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: issued.refreshJwt, client_id: 'https://other.example/metadata' }).toString(),
      })));
      expect(wrongClient.status).toBe(400);

      const wrongKeyProof = await signAuthzDpop(env, wrong, 'POST', url);
      const wrongKey = await tokenPost(apiContext(env, new Request(url, {
        method: 'POST',
        headers: { dpop: wrongKeyProof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: issued.refreshJwt, client_id: clientId }).toString(),
      })));
      expect(wrongKey.status).toBe(400);
      expect(((await wrongKey.json()) as any).error).toBe('invalid_dpop');
    } finally {
      restore();
    }
  });

  it('does not downgrade cnf-bound OAuth refresh tokens through legacy refresh', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const { refreshJwt, refreshPayload, refreshExpiry } = await issueSessionTokens(env, 'did:example:test', {
      clientId,
      dpopJkt: key.jkt,
      oauthSessionId: 'pre-migration-session',
    });
    await storeRefreshToken(env, {
      id: refreshPayload.jti,
      did: 'did:example:test',
      expiresAt: refreshExpiry,
      tokenKind: 'legacy',
    });

    const result = await attemptRefresh({
      env,
      token: refreshJwt,
      nowSec: Math.floor(Date.now() / 1000),
    });
    expect(result).toMatchObject({
      tag: 'failure',
      code: 'InvalidToken',
      message: 'OAuth refresh token must use /oauth/token',
    });
  });

  it('revokes OAuth sessions from revoke and deleteSession', async () => {
    const restore = mockClientMetadata(clientId);
    try {
      const env = await makeEnv();
      const key = await makeDpopKey();
      const issued = await issueOauthRefresh(env, key);
      const revokeUrl = 'https://pds.example/oauth/revoke';
      const revokeProof = await signAuthzDpop(env, key, 'POST', revokeUrl);
      const revoked = await revokePost(apiContext(env, new Request(revokeUrl, {
        method: 'POST',
        headers: { dpop: revokeProof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: issued.accessJwt, client_id: clientId }).toString(),
      })));
      expect(revoked.status).toBe(200);
      expect((await getOAuthSession(env, issued.sessionId))?.revokedAt).toBeTruthy();
      const resourceUrl = 'https://pds.example/xrpc/com.atproto.repo.createRecord';
      const resourceProof = await signResourceDpop(env, key, 'POST', resourceUrl, issued.accessJwt);
      await expect(verifyResourceRequestHybrid(env, new Request(resourceUrl, {
        method: 'POST',
        headers: { authorization: `DPoP ${issued.accessJwt}`, dpop: resourceProof },
      }))).rejects.toMatchObject({ code: 'invalid_token' });

      const env2 = await makeEnv();
      const key2 = await makeDpopKey();
      const issued2 = await issueOauthRefresh(env2, key2);
      const deleted = await deleteSessionPost(apiContext(env2, new Request('https://pds.example/xrpc/com.atproto.server.deleteSession', {
        method: 'POST',
        headers: { authorization: `Bearer ${issued2.refreshJwt}` },
      })));
      expect(deleted.status).toBe(200);
      expect(await getRefreshToken(env2, issued2.refreshJti)).toBeNull();
      expect((await getOAuthSession(env2, issued2.sessionId))?.revokedAt).toBeTruthy();
      const refreshProof = await signAuthzDpop(env2, key2, 'POST', 'https://pds.example/oauth/token');
      const refresh = await tokenPost(apiContext(env2, new Request('https://pds.example/oauth/token', {
        method: 'POST',
        headers: { dpop: refreshProof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: issued2.refreshJwt, client_id: clientId }).toString(),
      })));
      expect(refresh.status).toBe(400);
    } finally {
      restore();
    }
  });

  it('revokes with a DPoP proof that has no nonce', async () => {
    const restore = mockClientMetadata(clientId);
    try {
      const env = await makeEnv();
      const key = await makeDpopKey();
      const issued = await issueOauthRefresh(env, key);
      const revokeUrl = 'https://pds.example/oauth/revoke';
      const revokeProof = await signDpopProof({ key, method: 'POST', url: revokeUrl });
      const revoked = await revokePost(apiContext(env, new Request(revokeUrl, {
        method: 'POST',
        headers: { dpop: revokeProof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: issued.refreshJwt, client_id: clientId }).toString(),
      })));
      expect(revoked.status).toBe(200);
      expect((await getOAuthSession(env, issued.sessionId))?.revokedAt).toBeTruthy();
    } finally {
      restore();
    }
  });
});
