import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from './helpers/env';
import { makeDpopKey, signResourceDpop } from './helpers/oauth';
import { createOAuthSession, storeRefreshToken } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { AuthScope } from '../src/lib/auth-scope';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { GET as getServiceAuth } from '../src/pages/xrpc/com.atproto.server.getServiceAuth';

const did = 'did:example:test';
const clientId = 'https://client.example/metadata';
const signingKey = '8b5e3d226b44c4c88fbd3d4529f6283fb2b20f6deee8a0b34e7f0a9b12d3e4f1';

function apiContext(env: any, request: Request) {
  return { locals: { runtime: { env } }, request } as any;
}

function serviceAuthEnv(overrides: Record<string, unknown> = {}) {
  return makeEnv({ REPO_SIGNING_KEY: signingKey, ...overrides } as any);
}

function decodeJwtPayload(token: string): Record<string, any> {
  const [, payload] = token.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString());
}

async function bearerToken(env: any, scope: string = AuthScope.Access): Promise<string> {
  return (await issueSessionTokens(env, did, { accessScope: scope })).accessJwt;
}

async function oauthToken(
  env: any,
  key: Awaited<ReturnType<typeof makeDpopKey>>,
  scope: string,
): Promise<string> {
  const sessionId = crypto.randomUUID().replace(/-/g, '');
  const accessJti = crypto.randomUUID().replace(/-/g, '');
  const { accessJwt, accessPayload, refreshPayload, refreshExpiry } = await issueSessionTokens(
    env,
    did,
    {
      accessScope: scope,
      clientId,
      dpopJkt: key.jkt,
      oauthSessionId: sessionId,
      accessJti,
    },
  );
  await createOAuthSession(env, {
    id: sessionId,
    did,
    clientId,
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
    did,
    expiresAt: refreshExpiry,
    tokenKind: 'oauth',
    oauthSessionId: sessionId,
    clientId,
    clientAuthMethod: 'none',
    dpopJkt: key.jkt,
    oauthScope: scope,
    accessJti: String(accessPayload.jti),
  });
  return accessJwt;
}

async function callBearer(env: any, token: string, params: URLSearchParams): Promise<Response> {
  const url = `https://pds.example/xrpc/com.atproto.server.getServiceAuth?${params.toString()}`;
  return getServiceAuth(apiContext(env, new Request(url, {
    headers: { authorization: `Bearer ${token}` },
  })));
}

async function callDpop(
  env: any,
  token: string,
  key: Awaited<ReturnType<typeof makeDpopKey>>,
  params: URLSearchParams,
): Promise<Response> {
  const url = `https://pds.example/xrpc/com.atproto.server.getServiceAuth?${params.toString()}`;
  const proof = await signResourceDpop(env, key, 'GET', url, token);
  return getServiceAuth(apiContext(env, new Request(url, {
    headers: { authorization: `DPoP ${token}`, dpop: proof },
  })));
}

describe('com.atproto.server.getServiceAuth policy', () => {
  it('allows full bearer access to mint account migration service auth within the one-hour cap', async () => {
    const env = await serviceAuthEnv();
    const token = await bearerToken(env);
    const requestedLifetime = 1800;
    const now = Math.floor(Date.now() / 1000);
    const response = await callBearer(env, token, new URLSearchParams({
      aud: 'did:web:bsky.social',
      lxm: 'com.atproto.server.createAccount',
      exp: String(now + requestedLifetime),
    }));

    expect(response.status).toBe(200);
    const { token: serviceToken } = await response.json() as { token: string };
    const payload = decodeJwtPayload(serviceToken);
    expect(payload.iss).toBe(did);
    expect(payload.aud).toBe('did:web:bsky.social');
    expect(payload.lxm).toBe('com.atproto.server.createAccount');
    expect(payload.exp - payload.iat).toBeGreaterThan(0);
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(requestedLifetime);
  });

  it('blocks protected methods for all credentials before minting', async () => {
    const env = await serviceAuthEnv();
    const token = await bearerToken(env);
    const response = await callBearer(env, token, new URLSearchParams({
      aud: 'did:web:bsky.social',
      lxm: 'com.atproto.identity.updateHandle',
    }));

    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: 'InvalidToken' });
  });

  it('blocks destructive account-management and migration service auth even when generic scopes would otherwise match', async () => {
    const env = await serviceAuthEnv();
    const blockedMethods = [
      'com.atproto.server.deleteAccount',
      'com.atproto.repo.importRepo',
    ];

    for (const lxm of blockedMethods) {
      const params = new URLSearchParams({ aud: 'did:web:bsky.social', lxm });
      const appPass = await bearerToken(env, AuthScope.AppPass);
      const appPassResponse = await callBearer(env, appPass, params);
      expect(appPassResponse.status).toBe(401);

      const key = await makeDpopKey();
      const oauth = await oauthToken(env, key, 'atproto transition:generic');
      const oauthResponse = await callDpop(env, oauth, key, params);
      expect(oauthResponse.status).toBe(401);
    }
  });

  it('does not let privileged app passwords mint account-management service auth', async () => {
    const env = await serviceAuthEnv();
    const token = await bearerToken(env, AuthScope.AppPassPrivileged);
    const response = await callBearer(env, token, new URLSearchParams({
      aud: 'did:web:bsky.social',
      lxm: 'com.atproto.server.createAccount',
    }));

    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: 'InvalidToken' });
  });

  it('requires privileged app-password or OAuth chat permission for chat service auth', async () => {
    const env = await serviceAuthEnv();
    const chatParams = new URLSearchParams({
      aud: 'did:web:api.bsky.chat#bsky_chat',
      lxm: 'chat.bsky.convo.sendMessage',
    });

    const appPass = await bearerToken(env, AuthScope.AppPass);
    const appPassResponse = await callBearer(env, appPass, chatParams);
    expect(appPassResponse.status).toBe(401);

    const privileged = await bearerToken(env, AuthScope.AppPassPrivileged);
    const privilegedResponse = await callBearer(env, privileged, chatParams);
    expect(privilegedResponse.status).toBe(200);

    const key = await makeDpopKey();
    const oauth = await oauthToken(env, key, 'atproto transition:generic transition:chat.bsky');
    const oauthResponse = await callDpop(env, oauth, key, chatParams);
    expect(oauthResponse.status).toBe(200);
  });

  it('applies exact OAuth rpc permissions and still denies protected methods', async () => {
    const env = await serviceAuthEnv();
    const key = await makeDpopKey();
    const scoped = await oauthToken(
      env,
      key,
      'atproto rpc:app.bsky.feed.getTimeline?aud=did%3Aweb%3Aapi.bsky.app%23bsky_appview',
    );

    const allowed = await callDpop(env, scoped, key, new URLSearchParams({
      aud: 'did:web:api.bsky.app#bsky_appview',
      lxm: 'app.bsky.feed.getTimeline',
    }));
    expect(allowed.status).toBe(200);

    const otherKey = await makeDpopKey();
    const generic = await oauthToken(env, otherKey, 'atproto transition:generic');
    const protectedResponse = await callDpop(env, generic, otherKey, new URLSearchParams({
      aud: 'did:web:bsky.social',
      lxm: 'com.atproto.identity.updateHandle',
    }));
    expect(protectedResponse.status).toBe(401);
  });

  it('blocks service auth for inactive account states', async () => {
    for (const state of ['takendown', 'deactivated'] as const) {
      const env = await serviceAuthEnv();
      await setAccountState(env, did, { tag: state });
      const token = await bearerToken(env);
      const response = await callBearer(env, token, new URLSearchParams({
        aud: 'did:web:api.bsky.app#bsky_appview',
        lxm: 'app.bsky.feed.getTimeline',
      }));

      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ error: 'AccountInactive' });
    }
  });

  it('validates lxm and audience syntax before minting', async () => {
    const env = await serviceAuthEnv();
    const token = await bearerToken(env);

    const invalidAudience = await callBearer(env, token, new URLSearchParams({
      aud: 'not-a-did',
      lxm: 'app.bsky.feed.getTimeline',
    }));
    expect(invalidAudience.status).toBe(400);
    expect(await invalidAudience.json()).toMatchObject({ error: 'InvalidRequest' });

    const invalidMethod = await callBearer(env, token, new URLSearchParams({
      aud: 'did:web:api.bsky.app#bsky_appview',
      lxm: 'bad',
    }));
    expect(invalidMethod.status).toBe(400);
    expect(await invalidMethod.json()).toMatchObject({ error: 'InvalidRequest' });
  });

  it('caps method-less service auth at sixty seconds', async () => {
    const env = await serviceAuthEnv();
    const token = await bearerToken(env);
    const tooLong = await callBearer(env, token, new URLSearchParams({
      aud: 'did:web:api.bsky.app#bsky_appview',
      exp: String(Math.floor(Date.now() / 1000) + 120),
    }));
    expect(tooLong.status).toBe(400);
    expect(await tooLong.json()).toMatchObject({ error: 'BadExpiration' });

    const ok = await callBearer(env, token, new URLSearchParams({
      aud: 'did:web:api.bsky.app#bsky_appview',
    }));
    expect(ok.status).toBe(200);
    const { token: serviceToken } = await ok.json() as { token: string };
    const payload = decodeJwtPayload(serviceToken);
    expect(payload.lxm).toBeUndefined();
    expect(payload.exp - payload.iat).toBe(60);
  });
});
