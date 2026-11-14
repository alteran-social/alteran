import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from './helpers/env';
import { makeDpopKey, signAuthzDpop, signResourceDpop } from './helpers/oauth';
import { getOAuthSession } from './helpers/oauth-store';
import { sha256b64url } from '../src/lib/oauth/dpop';
import { verifyAccessToken } from '../src/lib/session-tokens';
import { POST as parPost } from '../src/pages/oauth/par';
import { GET as consentGet, POST as consentPost } from '../src/pages/oauth/consent';
import { POST as tokenPost } from '../src/pages/oauth/token';
import { POST as applyWrites } from '../src/pages/xrpc/com.atproto.repo.applyWrites';
import { POST as putRecord } from '../src/pages/xrpc/com.atproto.repo.putRecord';
import { GET as getSession } from '../src/pages/xrpc/com.atproto.server.getSession';

const ORIGIN = 'https://pds.example';
const COLLECTION = 'academy.rawkode.tartan.signature';
const SCOPE = `atproto repo:${COLLECTION}?action=create repo:${COLLECTION}?action=delete`;
const CLIENT_ID = `http://localhost?${new URLSearchParams({
  redirect_uri: 'http://127.0.0.1/callback',
  scope: SCOPE,
})}`;
const REDIRECT_URI = 'http://127.0.0.1:51789/callback';
const CODE_VERIFIER = 'loopback-flow-code-verifier-0123456789';

type TestEnv = Awaited<ReturnType<typeof makeEnv>>;
type DpopKey = Awaited<ReturnType<typeof makeDpopKey>>;

function context(env: TestEnv, request: Request) {
  return { locals: { env }, request, url: new URL(request.url) } as any;
}

async function pushAuthorizationRequest(
  env: TestEnv,
  key: DpopKey,
  overrides: Record<string, string> = {},
) {
  const url = `${ORIGIN}/oauth/par`;
  return parPost(context(env, new Request(url, {
    method: 'POST',
    headers: {
      dpop: await signAuthzDpop(env, key, 'POST', url),
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      response_type: 'code',
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
      state: 'state123',
      code_challenge: await sha256b64url(CODE_VERIFIER),
      code_challenge_method: 'S256',
      ...overrides,
    }).toString(),
  })));
}

async function consentPage(env: TestEnv, requestUri: string) {
  const res = await consentGet(context(env, new Request(
    `${ORIGIN}/oauth/consent?request_uri=${encodeURIComponent(requestUri)}`,
  )));
  return res.text();
}

async function authorize(env: TestEnv, key: DpopKey) {
  const par = await pushAuthorizationRequest(env, key);
  expect(par.status).toBe(201);
  const requestUri = String((await par.json() as { request_uri: string }).request_uri);
  const html = await consentPage(env, requestUri);
  const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1] ?? '';
  const consent = await consentPost(context(env, new Request(`${ORIGIN}/oauth/consent`, {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      request_uri: requestUri,
      client_id: CLIENT_ID,
      csrf,
      password: 'pwd',
      decision: 'allow',
    }).toString(),
  })));
  expect(consent.status).toBe(302);
  const redirect = new URL(consent.headers.get('location') ?? '');
  return { html, redirect };
}

async function exchange(env: TestEnv, key: DpopKey, form: Record<string, string>) {
  const url = `${ORIGIN}/oauth/token`;
  const res = await tokenPost(context(env, new Request(url, {
    method: 'POST',
    headers: {
      dpop: await signAuthzDpop(env, key, 'POST', url),
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ client_id: CLIENT_ID, ...form }).toString(),
  })));
  return { status: res.status, body: await res.json() as Record<string, any> };
}

async function signIn(env: TestEnv, key: DpopKey) {
  const { redirect } = await authorize(env, key);
  const tokens = await exchange(env, key, {
    grant_type: 'authorization_code',
    code: redirect.searchParams.get('code') ?? '',
    redirect_uri: REDIRECT_URI,
    code_verifier: CODE_VERIFIER,
  });
  expect(tokens.status).toBe(200);
  return tokens.body;
}

async function resourceRequest(
  env: TestEnv,
  key: DpopKey,
  accessToken: string,
  method: string,
  url: string,
  body?: unknown,
) {
  return new Request(url, {
    method,
    headers: {
      authorization: `DPoP ${accessToken}`,
      dpop: await signResourceDpop(env, key, method, url, accessToken),
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function signatureWrite(seed: number) {
  return {
    $type: 'com.atproto.repo.applyWrites#create',
    collection: COLLECTION,
    value: {
      $type: COLLECTION,
      namespace: 'git',
      algorithm: 'sha256',
      digest: { $bytes: btoa(String.fromCharCode(...new Uint8Array(32).fill(seed))) },
      createdAt: '2026-05-13T00:00:00.000Z',
    },
  };
}

describe('native sign-in with the http://localhost development client', () => {
  it('redirects the authorization code to the ephemeral loopback port', async () => {
    const env = await makeEnv();
    const { redirect } = await authorize(env, await makeDpopKey());
    expect(redirect.origin + redirect.pathname).toBe(REDIRECT_URI);
    expect(redirect.searchParams.get('code')).toBeTruthy();
    expect(redirect.searchParams.get('iss')).toBe(ORIGIN);
  });

  it('names the collection and actions on the consent screen', async () => {
    const env = await makeEnv();
    const { html } = await authorize(env, await makeDpopKey());
    expect(html).toContain(`Create and delete records in the collection ${COLLECTION}`);
  });

  it('warns on the consent screen that the client is unverified', async () => {
    const env = await makeEnv();
    const { html } = await authorize(env, await makeDpopKey());
    expect(html).toContain('Its identity cannot be verified');
  });

  it('returns the granted repo scopes in the token response', async () => {
    const env = await makeEnv();
    const tokens = await signIn(env, await makeDpopKey());
    expect(tokens.scope).toBe(SCOPE);
    expect(tokens.token_type).toBe('DPoP');
    expect(tokens.sub).toBe('did:example:test');
  });

  it('lets the granted token create signature records', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const tokens = await signIn(env, key);
    const url = `${ORIGIN}/xrpc/com.atproto.repo.applyWrites`;
    const res = await applyWrites(context(env, await resourceRequest(env, key, tokens.access_token, 'POST', url, {
      repo: 'did:example:test',
      writes: [signatureWrite(1), signatureWrite(2)],
    })));
    expect(res.status).toBe(200);
  });

  it('refuses the granted token an update with 403', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const tokens = await signIn(env, key);
    const url = `${ORIGIN}/xrpc/com.atproto.repo.putRecord`;
    const res = await putRecord(context(env, await resourceRequest(env, key, tokens.access_token, 'POST', url, {
      repo: 'did:example:test',
      collection: COLLECTION,
      rkey: 'self',
      record: signatureWrite(3).value,
    })));
    expect(res.status).toBe(403);
    expect((await res.json() as { error: string }).error).toBe('ScopeMissingError');
  });

  it('does not reveal the account email to the granted token', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const tokens = await signIn(env, key);
    const url = `${ORIGIN}/xrpc/com.atproto.server.getSession`;
    const res = await getSession(context(env, await resourceRequest(env, key, tokens.access_token, 'GET', url)));
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.did).toBe('did:example:test');
    expect(body.email).toBeUndefined();
  });

  it('keeps the same scope when the token is refreshed', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const tokens = await signIn(env, key);
    const refreshed = await exchange(env, key, {
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
    });
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.scope).toBe(SCOPE);
  });

  it('does not extend a public client session when the token is refreshed', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const tokens = await signIn(env, key);
    const sessionId = String((await verifyAccessToken(env, tokens.access_token)).oauth_session);
    const before = (await getOAuthSession(env, sessionId))?.expiresAt ?? 0;
    const twoWeeks = 14 * 24 * 60 * 60;
    expect(before).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + twoWeeks);
    await exchange(env, key, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token });
    expect((await getOAuthSession(env, sessionId))?.expiresAt).toBe(before);
  });
});

describe('identity-only sign-in with the bare http://localhost client', () => {
  const bare = { client_id: 'http://localhost', scope: 'atproto', redirect_uri: 'http://127.0.0.1:51789/' };

  async function identityOnlyToken(env: TestEnv, key: DpopKey) {
    const par = await pushAuthorizationRequest(env, key, bare);
    const requestUri = String((await par.json() as { request_uri: string }).request_uri);
    const csrf = (await consentPage(env, requestUri)).match(/name="csrf" value="([^"]+)"/)?.[1] ?? '';
    const consent = await consentPost(context(env, new Request(`${ORIGIN}/oauth/consent`, {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        request_uri: requestUri,
        client_id: bare.client_id,
        csrf,
        password: 'pwd',
        decision: 'allow',
      }).toString(),
    })));
    const code = new URL(consent.headers.get('location') ?? '').searchParams.get('code') ?? '';
    const tokens = await exchange(env, key, {
      client_id: bare.client_id,
      grant_type: 'authorization_code',
      code,
      redirect_uri: bare.redirect_uri,
      code_verifier: CODE_VERIFIER,
    });
    return String(tokens.body.access_token);
  }

  it('can read its own session', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const accessToken = await identityOnlyToken(env, key);
    const url = `${ORIGIN}/xrpc/com.atproto.server.getSession`;
    const res = await getSession(context(env, await resourceRequest(env, key, accessToken, 'GET', url)));
    expect(res.status).toBe(200);
  });

  it('cannot write to the repository', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const accessToken = await identityOnlyToken(env, key);
    const url = `${ORIGIN}/xrpc/com.atproto.repo.applyWrites`;
    const res = await applyWrites(context(env, await resourceRequest(env, key, accessToken, 'POST', url, {
      repo: 'did:example:test',
      writes: [signatureWrite(1)],
    })));
    expect(res.status).toBe(403);
  });
});

describe('pushed authorization requests from the development client', () => {
  it('answers invalid_scope for a scope the client_id does not declare', async () => {
    const env = await makeEnv();
    const res = await pushAuthorizationRequest(env, await makeDpopKey(), {
      scope: 'atproto transition:generic',
    });
    expect(res.status).toBe(400);
    expect((await res.json() as { error: string }).error).toBe('invalid_scope');
  });

  it('refuses a redirect to a path the client_id does not declare', async () => {
    const env = await makeEnv();
    const res = await pushAuthorizationRequest(env, await makeDpopKey(), {
      redirect_uri: 'http://127.0.0.1:51789/other',
    });
    expect(res.status).toBe(400);
  });

  it('refuses a malformed development client_id', async () => {
    const env = await makeEnv();
    const res = await pushAuthorizationRequest(env, await makeDpopKey(), {
      client_id: 'http://localhost?client_name=Trusted',
    });
    expect(res.status).toBe(400);
    expect((await res.json() as { error: string }).error).toBe('invalid_client');
  });
});
