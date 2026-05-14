import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { SignJWT } from 'jose';
import { makeEnv } from './helpers/env';
import { makeDpopKey, signResourceDpop } from './helpers/oauth';
import { createOAuthSession, getSecret, storeRefreshToken } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { AuthScope } from '../src/lib/auth-scope';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { GET as catchallGet } from '../src/pages/xrpc/[...nsid]';

const did = 'did:example:test';
const clientId = 'https://client.example/metadata';
const testRepoSigningKey = '8b5e3d226b44c4c88fbd3d4529f6283fb2b20f6deee8a0b34e7f0a9b12d3e4f1';

function apiContext(env: any, request: Request, nsid: string) {
  return {
    locals: { runtime: { env } },
    params: { nsid },
    request,
  } as any;
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const [, payload] = token.split('.');
  const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

async function issueOauthAccess(
  env: any,
  key: Awaited<ReturnType<typeof makeDpopKey>>,
  scope = 'atproto transition:generic',
) {
  const sessionId = crypto.randomUUID().replace(/-/g, '');
  const accessJti = crypto.randomUUID().replace(/-/g, '');
  const { accessJwt, accessPayload, refreshPayload, refreshExpiry } = await issueSessionTokens(
    env,
    did,
    {
      scope,
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

async function signAccessWithScope(env: any, scope: string): Promise<string> {
  await issueSessionTokens(env, did);
  const secret = await getSecret(env, 'session_jwt_secret');
  if (!secret) throw new Error('missing test session secret');
  const now = Math.floor(Date.now() / 1000);
  const key = new TextEncoder().encode(secret);
  return new SignJWT({
    scope,
    aud: env.PDS_DID,
    sub: did,
    iat: now,
    exp: now + 7200,
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
    .setSubject(did)
    .setAudience(env.PDS_DID)
    .setIssuedAt(now)
    .setExpirationTime(now + 7200)
    .sign(key);
}

type TestFetch = (
  input: Parameters<typeof fetch>[0],
  init?: Parameters<typeof fetch>[1],
) => Promise<Response>;

async function withFetch<T>(handler: TestFetch, run: () => Promise<T>): Promise<T> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = handler as unknown as typeof fetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

describe('AppView proxy authentication', () => {
  it('proxies legacy Bearer auth with a deployed AppView-compatible service JWT audience', async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: testRepoSigningKey });
    const { accessJwt } = await issueSessionTokens(env, did);
    const nsid = 'app.bsky.feed.getTimeline';
    const url = `https://pds.example/xrpc/${nsid}`;
    let upstreamAuthorization: string | null = null;

    const response = await withFetch(async (input, init) => {
      const headers = input instanceof Request
        ? input.headers
        : new Headers(init?.headers);
      upstreamAuthorization = headers.get('authorization');
      return new Response(JSON.stringify({ ok: true }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }, () =>
      catchallGet(apiContext(
        env,
        new Request(url, { headers: { authorization: `Bearer ${accessJwt}` } }),
        nsid,
      ))
    );

    expect(response.status).toBe(200);
    expect((upstreamAuthorization ?? '').startsWith('Bearer ')).toBe(true);
    const serviceToken = (upstreamAuthorization ?? '').slice('Bearer '.length);
    expect(decodeJwtPayload(serviceToken)).toMatchObject({
      iss: did,
      aud: 'did:web:api.bsky.app',
      lxm: nsid,
    });
  });

  it('proxies valid OAuth DPoP auth through the verifier before minting service auth', async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: testRepoSigningKey });
    const key = await makeDpopKey();
    const access = await issueOauthAccess(env, key);
    const nsid = 'app.bsky.feed.getTimeline';
    const url = `https://pds.example/xrpc/${nsid}`;
    const proof = await signResourceDpop(env, key, 'GET', url, access);
    let fetchCalls = 0;

    const response = await withFetch(async () => {
      fetchCalls++;
      return new Response(JSON.stringify({ ok: true }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }, () =>
      catchallGet(apiContext(
        env,
        new Request(url, { headers: { authorization: `DPoP ${access}`, dpop: proof } }),
        nsid,
      ))
    );

    expect(response.status).toBe(200);
    expect(fetchCalls).toBe(1);
  });

  it('authorizes exact OAuth RPC scopes against the full AppView service reference', async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: testRepoSigningKey });
    const key = await makeDpopKey();
    const nsid = 'app.bsky.actor.getProfile';
    const permissionAudience = 'did:web:api.bsky.app#bsky_appview';
    const access = await issueOauthAccess(
      env,
      key,
      `atproto rpc:${nsid}?aud=${encodeURIComponent(permissionAudience)}`,
    );
    const requestUrl = `https://pds.example/xrpc/${nsid}?actor=${encodeURIComponent(did)}`;
    const proof = await signResourceDpop(env, key, 'GET', requestUrl, access);
    let upstreamAuthorization: string | null = null;

    const response = await withFetch(async (input, init) => {
      const headers = input instanceof Request
        ? input.headers
        : new Headers(init?.headers);
      upstreamAuthorization = headers.get('authorization');
      return new Response(JSON.stringify({ did }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }, () =>
      catchallGet(apiContext(
        env,
        new Request(requestUrl, {
          headers: { authorization: `DPoP ${access}`, dpop: proof },
        }),
        nsid,
      ))
    );

    expect(response.status).toBe(200);
    expect((upstreamAuthorization ?? '').startsWith('Bearer ')).toBe(true);
    const serviceToken = (upstreamAuthorization ?? '').slice('Bearer '.length);
    expect(decodeJwtPayload(serviceToken)).toMatchObject({
      iss: did,
      aud: 'did:web:api.bsky.app',
      lxm: nsid,
    });
  });

  it('does not authorize exact OAuth RPC scopes for a different service reference', async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: testRepoSigningKey });
    const key = await makeDpopKey();
    const nsid = 'app.bsky.actor.getProfile';
    const access = await issueOauthAccess(
      env,
      key,
      `atproto rpc:${nsid}?aud=${encodeURIComponent('did:web:api.bsky.app#other_service')}`,
    );
    const requestUrl = `https://pds.example/xrpc/${nsid}?actor=${encodeURIComponent(did)}`;
    const proof = await signResourceDpop(env, key, 'GET', requestUrl, access);
    let fetchCalls = 0;

    const response = await withFetch(async () => {
      fetchCalls++;
      return new Response(JSON.stringify({ ok: true }));
    }, () =>
      catchallGet(apiContext(
        env,
        new Request(requestUrl, {
          headers: { authorization: `DPoP ${access}`, dpop: proof },
        }),
        nsid,
      ))
    );

    expect(response.status).toBe(401);
    expect(fetchCalls).toBe(0);
  });

  it('keeps proxy authorization on the full service reference while minting a bare-DID service JWT', async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: testRepoSigningKey });
    const key = await makeDpopKey();
    const nsid = 'chat.bsky.convo.getLog';
    const permissionAudience = 'did:web:api.bsky.chat#bsky_chat';
    const access = await issueOauthAccess(
      env,
      key,
      `atproto rpc:${nsid}?aud=${encodeURIComponent(permissionAudience)}`,
    );
    const requestUrl = `https://pds.example/xrpc/${nsid}`;
    const proof = await signResourceDpop(env, key, 'GET', requestUrl, access);
    let upstreamAuthorization: string | null = null;
    let upstreamUrl: string | null = null;

    const response = await withFetch(async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      upstreamUrl = request.url;
      upstreamAuthorization = request.headers.get('authorization');
      return new Response(JSON.stringify({ logs: [] }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }, () =>
      catchallGet(apiContext(
        env,
        new Request(requestUrl, {
          headers: {
            authorization: `DPoP ${access}`,
            dpop: proof,
            'atproto-proxy': permissionAudience,
          },
        }),
        nsid,
      ))
    );

    expect(response.status).toBe(200);
    expect(upstreamUrl).toBe(`https://api.bsky.chat/xrpc/${nsid}`);
    const serviceToken = (upstreamAuthorization ?? '').slice('Bearer '.length);
    expect(decodeJwtPayload(serviceToken)).toMatchObject({
      iss: did,
      aud: 'did:web:api.bsky.chat',
      lxm: nsid,
    });
  });

  it('rejects OAuth RPC scopes for a different proxied service before calling upstream', async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: testRepoSigningKey });
    const key = await makeDpopKey();
    const nsid = 'app.bsky.actor.getProfile';
    const access = await issueOauthAccess(
      env,
      key,
      `atproto rpc:${nsid}?aud=${encodeURIComponent('did:web:api.bsky.app#bsky_appview')}`,
    );
    const requestUrl = `https://pds.example/xrpc/${nsid}?actor=${encodeURIComponent(did)}`;
    const proof = await signResourceDpop(env, key, 'GET', requestUrl, access);
    let fetchCalls = 0;

    const response = await withFetch(async () => {
      fetchCalls++;
      return new Response(JSON.stringify({ ok: true }));
    }, () =>
      catchallGet(apiContext(
        env,
        new Request(requestUrl, {
          headers: {
            authorization: `DPoP ${access}`,
            dpop: proof,
            'atproto-proxy': 'did:web:api.bsky.chat#bsky_chat',
          },
        }),
        nsid,
      ))
    );

    expect(response.status).toBe(401);
    expect(fetchCalls).toBe(0);
  });

  it('rejects DPoP-bound OAuth access tokens replayed as Bearer on proxy paths', async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: testRepoSigningKey });
    const key = await makeDpopKey();
    const access = await issueOauthAccess(env, key);
    const nsid = 'app.bsky.feed.getTimeline';
    const url = `https://pds.example/xrpc/${nsid}`;
    let fetchCalls = 0;

    const response = await withFetch(async () => {
      fetchCalls++;
      return new Response(JSON.stringify({ ok: true }));
    }, () =>
      catchallGet(apiContext(
        env,
        new Request(url, { headers: { authorization: `Bearer ${access}` } }),
        nsid,
      ))
    );

    expect(response.status).toBe(401);
    expect(fetchCalls).toBe(0);
  });

  it('rejects missing DPoP proofs on proxy paths without calling upstream', async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: testRepoSigningKey });
    const key = await makeDpopKey();
    const access = await issueOauthAccess(env, key);
    const nsid = 'app.bsky.feed.getTimeline';
    const url = `https://pds.example/xrpc/${nsid}`;
    let fetchCalls = 0;

    const response = await withFetch(async () => {
      fetchCalls++;
      return new Response(JSON.stringify({ ok: true }));
    }, () =>
      catchallGet(apiContext(
        env,
        new Request(url, { headers: { authorization: `DPoP ${access}` } }),
        nsid,
      ))
    );

    expect(response.status).toBe(401);
    expect(response.headers.get('DPoP-Nonce')).toBeTruthy();
    expect(fetchCalls).toBe(0);
  });

  it('fails closed when service JWT minting fails', async () => {
    const env = await makeEnv();
    const { accessJwt } = await issueSessionTokens(env, did);
    const nsid = 'app.bsky.feed.getTimeline';
    const url = `https://pds.example/xrpc/${nsid}`;
    let fetchCalls = 0;

    const response = await withFetch(async () => {
      fetchCalls++;
      return new Response(JSON.stringify({ ok: true }));
    }, () =>
      catchallGet(apiContext(
        env,
        new Request(url, { headers: { authorization: `Bearer ${accessJwt}` } }),
        nsid,
      ))
    );

    expect(response.status).toBe(502);
    expect(await response.json()).toMatchObject({ error: 'ServiceAuthFailed' });
    expect(fetchCalls).toBe(0);
  });

  it('rejects unknown bearer scopes on proxy paths', async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: testRepoSigningKey });
    const token = await signAccessWithScope(env, 'mystery.scope');
    const nsid = 'app.bsky.feed.getTimeline';
    const url = `https://pds.example/xrpc/${nsid}`;
    let fetchCalls = 0;

    const response = await withFetch(async () => {
      fetchCalls++;
      return new Response(JSON.stringify({ ok: true }));
    }, () =>
      catchallGet(apiContext(
        env,
        new Request(url, { headers: { authorization: `Bearer ${token}` } }),
        nsid,
      ))
    );

    expect(response.status).toBe(401);
    expect(fetchCalls).toBe(0);
  });

  it('rejects inactive accounts before proxying', async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: testRepoSigningKey });
    await setAccountState(env, did, { tag: 'deactivated' });
    const { accessJwt } = await issueSessionTokens(env, did);
    const nsid = 'app.bsky.feed.getTimeline';
    const url = `https://pds.example/xrpc/${nsid}`;
    let fetchCalls = 0;

    const response = await withFetch(async () => {
      fetchCalls++;
      return new Response(JSON.stringify({ ok: true }));
    }, () =>
      catchallGet(apiContext(
        env,
        new Request(url, { headers: { authorization: `Bearer ${accessJwt}` } }),
        nsid,
      ))
    );

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: 'AccountInactive' });
    expect(fetchCalls).toBe(0);

    const takendownEnv = await makeEnv({ REPO_SIGNING_KEY: testRepoSigningKey });
    await setAccountState(takendownEnv, did, { tag: 'takendown' });
    const { accessJwt: takendownJwt } = await issueSessionTokens(takendownEnv, did);
    let takendownFetchCalls = 0;
    const takendown = await withFetch(async () => {
      takendownFetchCalls++;
      return new Response(JSON.stringify({ ok: true }));
    }, () =>
      catchallGet(apiContext(
        takendownEnv,
        new Request(url, { headers: { authorization: `Bearer ${takendownJwt}` } }),
        nsid,
      ))
    );

    expect(takendown.status).toBe(403);
    expect(await takendown.json()).toMatchObject({ error: 'AccountInactive' });
    expect(takendownFetchCalls).toBe(0);
  });
});
