import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from './helpers/env';
import { makeDpopKey, signDpopProof, signResourceDpop } from './helpers/oauth';
import { createOAuthSession, getSecret, storeRefreshToken } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { verifyJwt } from '../src/lib/jwt';
import { dpopResourceUnauthorized, ResourceAuthError, verifyResourceRequestHybrid } from '../src/lib/oauth/resource';
import { authenticateRequest, isAuthorized } from '../src/lib/auth';
import { GET as getSession } from '../src/pages/xrpc/com.atproto.server.getSession';
import { GET as getPreferences } from '../src/pages/xrpc/app.bsky.actor.getPreferences';
import { GET as catchallGet } from '../src/pages/xrpc/[...nsid]';

const testRepoSigningKey = '8b5e3d226b44c4c88fbd3d4529f6283fb2b20f6deee8a0b34e7f0a9b12d3e4f1';

async function issueOAuthAccess(
  env: any,
  key: Awaited<ReturnType<typeof makeDpopKey>>,
  scope = 'atproto transition:generic',
) {
  const sessionId = crypto.randomUUID().replace(/-/g, '');
  const accessJti = crypto.randomUUID().replace(/-/g, '');
  const { accessJwt, refreshPayload, refreshExpiry, accessPayload } = await issueSessionTokens(env, 'did:example:test', {
    scope,
    clientId: 'https://client.example/metadata',
    dpopJkt: key.jkt,
    oauthSessionId: sessionId,
    accessJti,
  });
  await createOAuthSession(env, {
    id: sessionId,
    did: 'did:example:test',
    clientId: 'https://client.example/metadata',
    clientAuthMethod: 'none',
    clientAuthKeyId: null,
    dpopJkt: key.jkt,
    scope,
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
    clientId: 'https://client.example/metadata',
    clientAuthMethod: 'none',
    dpopJkt: key.jkt,
    oauthScope: scope,
    accessJti: String(accessPayload.jti),
  });
  return accessJwt;
}

describe('OAuth resource DPoP binding', () => {
  it('accepts cnf-bound DPoP tokens with matching proof', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const access = await issueOAuthAccess(env, key);
    const url = 'https://pds.example/xrpc/com.atproto.repo.createRecord';
    const proof = await signResourceDpop(env, key, 'POST', url, access);
    const result = await verifyResourceRequestHybrid(env, new Request(url, {
      method: 'POST',
      headers: { authorization: `DPoP ${access}`, dpop: proof },
    }));
    expect(result?.did).toBe('did:example:test');
    expect(result?.authType).toBe('oauth-dpop');
    expect(result?.scope).toBe('atproto transition:generic');
  });

  it('rejects login-only OAuth tokens on PDS resource routes', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const access = await issueOAuthAccess(env, key, 'atproto');
    const url = 'https://pds.example/xrpc/com.atproto.repo.createRecord';
    const proof = await signResourceDpop(env, key, 'POST', url, access);

    await expect(verifyResourceRequestHybrid(env, new Request(url, {
      method: 'POST',
      headers: { authorization: `DPoP ${access}`, dpop: proof },
    }))).rejects.toMatchObject({ code: 'invalid_token' });
  });

  it('accepts case-insensitive DPoP authorization schemes', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const access = await issueOAuthAccess(env, key);
    const url = 'https://pds.example/xrpc/com.atproto.repo.createRecord';
    const proof = await signResourceDpop(env, key, 'POST', url, access);
    const result = await verifyResourceRequestHybrid(env, new Request(url, {
      method: 'POST',
      headers: { authorization: `dpop ${access}`, dpop: proof },
    }));
    expect(result?.did).toBe('did:example:test');
    expect(result?.authType).toBe('oauth-dpop');
  });

  it('accepts DPoP tokens through shared authenticated XRPC routes', async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: testRepoSigningKey });
    const key = await makeDpopKey();
    const access = await issueOAuthAccess(env, key);

    const sessionUrl = 'https://pds.example/xrpc/com.atproto.server.getSession';
    const authorizedProof = await signResourceDpop(env, key, 'GET', sessionUrl, access);
    expect(await isAuthorized(new Request(sessionUrl, {
      headers: { authorization: `DPoP ${access}`, dpop: authorizedProof },
    }), env)).toBe(false);

    const authProof = await signResourceDpop(env, key, 'GET', sessionUrl, access);
    const authContext = await authenticateRequest(new Request(sessionUrl, {
      headers: { authorization: `DPoP ${access}`, dpop: authProof },
    }), env);
    expect(authContext?.claims.sub).toBe('did:example:test');
    expect(authContext?.claims.scope).toBe('atproto transition:generic');

    const sessionProof = await signResourceDpop(env, key, 'GET', sessionUrl, access);
    const sessionRequest = new Request(sessionUrl, {
      headers: { authorization: `DPoP ${access}`, dpop: sessionProof },
    });
    const session = await getSession({ locals: { runtime: { env } }, request: sessionRequest } as any);
    expect(session.status).toBe(200);
    expect(((await session.json()) as any).did).toBe('did:example:test');

    const preferencesUrl = 'https://pds.example/xrpc/app.bsky.actor.getPreferences';
    const preferencesProof = await signResourceDpop(env, key, 'GET', preferencesUrl, access);
    const preferences = await getPreferences({ locals: { runtime: { env } }, request: new Request(preferencesUrl, {
      headers: { authorization: `DPoP ${access}`, dpop: preferencesProof },
    }) } as any);
    expect(preferences.status).toBe(200);
    expect(((await preferences.json()) as any).preferences).toEqual([]);

    const catchallUrl = 'https://pds.example/xrpc/app.bsky.feed.getTimeline';
    const catchallProof = await signResourceDpop(env, key, 'GET', catchallUrl, access);
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () => new Response(JSON.stringify({ ok: true }), {
        headers: { 'Content-Type': 'application/json' },
      })) as unknown as typeof fetch;
      const proxied = await catchallGet({
        locals: { runtime: { env } },
        params: { nsid: 'app.bsky.feed.getTimeline' },
        request: new Request(catchallUrl, {
          headers: { authorization: `DPoP ${access}`, dpop: catchallProof },
        }),
      } as any);
      expect(proxied.status).toBe(200);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('resolves account state in resource auth contexts', async () => {
    const env = await makeEnv();
    await setAccountState(env, 'did:example:test', { tag: 'takendown' });

    const { accessJwt } = await issueSessionTokens(env, 'did:example:test');
    const bearerUrl = 'https://pds.example/xrpc/com.atproto.repo.createRecord';
    const bearer = await verifyResourceRequestHybrid(env, new Request(bearerUrl, {
      method: 'POST',
      headers: { authorization: `Bearer ${accessJwt}` },
    }));
    expect(bearer?.access).toMatchObject({
      accountStatus: 'takendown',
      isTakendown: true,
    });

    const key = await makeDpopKey();
    const oauthAccess = await issueOAuthAccess(env, key);
    const proof = await signResourceDpop(env, key, 'POST', bearerUrl, oauthAccess);
    const oauth = await verifyResourceRequestHybrid(env, new Request(bearerUrl, {
      method: 'POST',
      headers: { authorization: `DPoP ${oauthAccess}`, dpop: proof },
    }));
    expect(oauth?.access).toMatchObject({
      accountStatus: 'takendown',
      isTakendown: true,
    });
  });

  it('returns DPoP nonce challenges from shared authenticated routes', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const access = await issueOAuthAccess(env, key);

    const sessionUrl = 'https://pds.example/xrpc/com.atproto.server.getSession';
    const session = await getSession({ locals: { runtime: { env } }, request: new Request(sessionUrl, {
      headers: { authorization: `DPoP ${access}` },
    }) } as any);
    expect(session.status).toBe(401);
    expect(session.headers.get('DPoP-Nonce')).toBeTruthy();

    const catchallUrl = 'https://pds.example/xrpc/app.bsky.feed.getTimeline';
    const proxied = await catchallGet({
      locals: { runtime: { env } },
      params: { nsid: 'app.bsky.feed.getTimeline' },
      request: new Request(catchallUrl, {
        headers: { authorization: `DPoP ${access}` },
      }),
    } as any);
    expect(proxied.status).toBe(401);
    expect(proxied.headers.get('DPoP-Nonce')).toBeTruthy();
  });

  it('rejects wrong DPoP keys, replayed proofs, and Bearer replay', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const wrong = await makeDpopKey();
    const access = await issueOAuthAccess(env, key);
    const url = 'https://pds.example/xrpc/com.atproto.repo.createRecord';

    const wrongProof = await signResourceDpop(env, wrong, 'POST', url, access);
    await expect(verifyResourceRequestHybrid(env, new Request(url, {
      method: 'POST',
      headers: { authorization: `DPoP ${access}`, dpop: wrongProof },
    }))).rejects.toBeInstanceOf(ResourceAuthError);

    const proof = await signResourceDpop(env, key, 'POST', url, access);
    await verifyResourceRequestHybrid(env, new Request(url, {
      method: 'POST',
      headers: { authorization: `DPoP ${access}`, dpop: proof },
    }));
    await expect(verifyResourceRequestHybrid(env, new Request(url, {
      method: 'POST',
      headers: { authorization: `DPoP ${access}`, dpop: proof },
    }))).rejects.toMatchObject({ code: 'invalid_token' });

    await expect(verifyResourceRequestHybrid(env, new Request(url, {
      method: 'POST',
      headers: { authorization: `Bearer ${access}` },
    }))).rejects.toMatchObject({ code: 'invalid_token' });
    expect(await verifyJwt(env, access)).toBeNull();
  });

  it('rejects missing proofs and bad ath values', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const access = await issueOAuthAccess(env, key);
    const url = 'https://pds.example/xrpc/com.atproto.repo.createRecord';

    await expect(verifyResourceRequestHybrid(env, new Request(url, {
      method: 'POST',
      headers: { authorization: `DPoP ${access}` },
    }))).rejects.toMatchObject({ code: 'use_dpop_nonce' });

    const badAthJti = 'bad-ath-resource-jti';
    const nonceResponse = await dpopResourceUnauthorized(env);
    const badAthProof = await signDpopProof({
      key,
      method: 'POST',
      url,
      nonce: nonceResponse.headers.get('DPoP-Nonce') ?? '',
      accessToken: `${access}.different`,
      jti: badAthJti,
    });
    await expect(verifyResourceRequestHybrid(env, new Request(url, {
      method: 'POST',
      headers: { authorization: `DPoP ${access}`, dpop: badAthProof },
    }))).rejects.toMatchObject({ code: 'invalid_token' });
    expect(await getSecret(env, `oauth:dpop:jti:resource:${badAthJti}`)).toBeNull();
  });

  it('preserves legacy createSession Bearer tokens', async () => {
    const env = await makeEnv();
    const { accessJwt } = await issueSessionTokens(env, 'did:example:test');
    const url = 'https://pds.example/xrpc/com.atproto.repo.createRecord';
    const result = await verifyResourceRequestHybrid(env, new Request(url, {
      method: 'POST',
      headers: { authorization: `Bearer ${accessJwt}` },
    }));
    expect(result?.did).toBe('did:example:test');
  });
});
