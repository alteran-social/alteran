import { describe, expect, it } from 'bun:test';
import { lexicons } from '@atproto/api';
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { makeEnv } from './helpers/env';
import { makeDpopKey, mockClientMetadata, signDpopProof, signResourceDpop } from './helpers/oauth';
import { issueSessionTokens, verifyAccessToken } from '../src/lib/session-tokens';
import { AuthScope } from '../src/lib/auth-scope';
import { isValidTid } from '../src/lib/commit';
import { sha256b64url } from '../src/lib/oauth/dpop';
import { verifyResourceRequestHybrid } from '../src/lib/oauth/resource';
import * as CreateSession from '../src/pages/xrpc/com.atproto.server.createSession';
import * as RefreshSession from '../src/pages/xrpc/com.atproto.server.refreshSession';
import * as CreateAppPassword from '../src/pages/xrpc/com.atproto.server.createAppPassword';
import * as ListAppPasswords from '../src/pages/xrpc/com.atproto.server.listAppPasswords';
import * as RevokeAppPassword from '../src/pages/xrpc/com.atproto.server.revokeAppPassword';
import * as DescribeServer from '../src/pages/xrpc/com.atproto.server.describeServer';
import * as CreateRecord from '../src/pages/xrpc/com.atproto.repo.createRecord';
import * as ApplyWrites from '../src/pages/xrpc/com.atproto.repo.applyWrites';
import { GET as authServerMetadata } from '../src/pages/.well-known/oauth-authorization-server';
import { GET as authorizeGet } from '../src/pages/oauth/authorize';
import { GET as consentGet, POST as consentPost } from '../src/pages/oauth/consent';
import { POST as parPost } from '../src/pages/oauth/par';
import { POST as tokenPost } from '../src/pages/oauth/token';
import { POST as revokePost } from '../src/pages/oauth/revoke';

const FIXED_DATE = '2026-05-13T00:00:00.000Z';
const CLIENT_ID = 'https://client.example/metadata';

type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

function apiContext(env: TestEnv, request: Request) {
  return { locals: { runtime: { env } }, request, url: new URL(request.url) } as any;
}

async function json<T = any>(res: Response): Promise<T> {
  return await res.json() as T;
}

function postRecord(text = 'hello', extra: Record<string, unknown> = {}) {
  return {
    $type: 'app.bsky.feed.post',
    text,
    createdAt: FIXED_DATE,
    ...extra,
  };
}

function profileRecord(extra: Record<string, unknown> = {}) {
  return {
    $type: 'app.bsky.actor.profile',
    displayName: 'Test User',
    description: 'A local conformance fixture',
    ...extra,
  };
}

async function createSession(env: TestEnv, body: Record<string, unknown>) {
  return CreateSession.POST(apiContext(env, new Request(
    'https://pds.example/xrpc/com.atproto.server.createSession',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    },
  )));
}

async function primarySession(env: TestEnv) {
  const res = await createSession(env, {
    identifier: String(env.PDS_HANDLE),
    password: String(env.USER_PASSWORD),
  });
  expect(res.status).toBe(200);
  return json<{ accessJwt: string; refreshJwt: string; did: string; handle: string }>(res);
}

async function postJson(
  route: { POST: (ctx: any) => Promise<Response> },
  env: TestEnv,
  url: string,
  body: unknown,
  accessJwt: string,
) {
  return route.POST(apiContext(env, new Request(url, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${accessJwt}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  })));
}

async function getJson(
  route: { GET: (ctx: any) => Response | Promise<Response> },
  env: TestEnv,
  url: string,
  accessJwt?: string,
) {
  return route.GET(apiContext(env, new Request(url, {
    headers: accessJwt ? { authorization: `Bearer ${accessJwt}` } : undefined,
  })));
}

async function consentCsrf(env: TestEnv, requestUri: string) {
  const res = await consentGet(apiContext(env, new Request(
    `https://pds.example/oauth/consent?request_uri=${encodeURIComponent(requestUri)}&client_id=${encodeURIComponent(CLIENT_ID)}`,
  )));
  expect(res.status).toBe(200);
  const html = await res.text();
  const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1] ?? '';
  expect(csrf.length).toBeGreaterThan(8);
  return csrf;
}

describe('Lexicon-backed XRPC conformance', () => {
  it('rejects invalid inputs at route boundaries with XRPC error objects', async () => {
    const env = await makeEnv();
    const session = await primarySession(env);

    const missingIdentifier = await createSession(env, { password: String(env.USER_PASSWORD) });
    expect(missingIdentifier.status).toBe(400);
    expect(await json(missingIdentifier)).toMatchObject({ error: 'InvalidRequest' });

    const missingName = await postJson(
      CreateAppPassword,
      env,
      'https://pds.example/xrpc/com.atproto.server.createAppPassword',
      {},
      session.accessJwt,
    );
    expect(missingName.status).toBe(400);
    expect(await json(missingName)).toMatchObject({ error: 'InvalidRequest' });

    const invalidCreateRecord = await postJson(
      CreateRecord,
      env,
      'https://pds.example/xrpc/com.atproto.repo.createRecord',
      { record: postRecord('missing collection') },
      session.accessJwt,
    );
    expect(invalidCreateRecord.status).toBe(400);
    expect(await json(invalidCreateRecord)).toMatchObject({ error: 'InvalidRequest' });

    const invalidApplyWrites = await postJson(
      ApplyWrites,
      env,
      'https://pds.example/xrpc/com.atproto.repo.applyWrites',
      { repo: env.PDS_DID },
      session.accessJwt,
    );
    expect(invalidApplyWrites.status).toBe(400);
    expect(await json(invalidApplyWrites)).toMatchObject({ error: 'InvalidRequest' });
  });

  it('returns lexicon-compatible outputs for local session, app-password, and repo write endpoints', async () => {
    const env = await makeEnv();
    const session = await primarySession(env);
    expect(() =>
      lexicons.assertValidXrpcOutput('com.atproto.server.createSession', session)
    ).not.toThrow();

    const createdPasswordRes = await postJson(
      CreateAppPassword,
      env,
      'https://pds.example/xrpc/com.atproto.server.createAppPassword',
      { name: 'conformance', privileged: true },
      session.accessJwt,
    );
    expect(createdPasswordRes.status).toBe(200);
    const createdPassword = await json(createdPasswordRes);
    expect(() =>
      lexicons.assertValidXrpcOutput('com.atproto.server.createAppPassword', createdPassword)
    ).not.toThrow();

    const listedRes = await getJson(
      ListAppPasswords,
      env,
      'https://pds.example/xrpc/com.atproto.server.listAppPasswords',
      session.accessJwt,
    );
    const listed = await json(listedRes);
    expect(() =>
      lexicons.assertValidXrpcOutput('com.atproto.server.listAppPasswords', listed)
    ).not.toThrow();
    expect(listed.passwords[0].password).toBeUndefined();

    const createRecordRes = await postJson(
      CreateRecord,
      env,
      'https://pds.example/xrpc/com.atproto.repo.createRecord',
      {
        repo: env.PDS_DID,
        collection: 'app.bsky.feed.post',
        record: postRecord('lexicon output'),
      },
      session.accessJwt,
    );
    expect(createRecordRes.status).toBe(200);
    const createdRecord = await json(createRecordRes);
    expect(() =>
      lexicons.assertValidXrpcOutput('com.atproto.repo.createRecord', createdRecord)
    ).not.toThrow();

    const applyWritesRes = await postJson(
      ApplyWrites,
      env,
      'https://pds.example/xrpc/com.atproto.repo.applyWrites',
      {
        repo: env.PDS_DID,
        writes: [{
          $type: 'com.atproto.repo.applyWrites#create',
          collection: 'app.bsky.feed.post',
          value: postRecord('applyWrites output'),
        }],
      },
      session.accessJwt,
    );
    expect(applyWritesRes.status).toBe(200);
    const applied = await json(applyWritesRes);
    expect(() =>
      lexicons.assertValidXrpcOutput('com.atproto.repo.applyWrites', applied)
    ).not.toThrow();

    const describedRes = await getJson(
      DescribeServer,
      env,
      'https://pds.example/xrpc/com.atproto.server.describeServer',
    );
    const described = await json(describedRes);
    expect(() =>
      lexicons.assertValidXrpcOutput('com.atproto.server.describeServer', described)
    ).not.toThrow();

    const revokedRes = await postJson(
      RevokeAppPassword,
      env,
      'https://pds.example/xrpc/com.atproto.server.revokeAppPassword',
      { name: 'conformance' },
      session.accessJwt,
    );
    expect(revokedRes.status).toBe(200);
    expect(await json<any>(revokedRes)).toEqual({});
  });

  it('validates record schemas and data-model identifiers with installed lexicons', async () => {
    expect(() =>
      lexicons.assertValidRecord('app.bsky.feed.post', postRecord('valid post'))
    ).not.toThrow();
    expect(() =>
      lexicons.assertValidRecord('app.bsky.actor.profile', profileRecord())
    ).not.toThrow();
    expect(() =>
      lexicons.assertValidRecord('app.bsky.feed.post', {
        $type: 'app.bsky.feed.post',
        createdAt: FIXED_DATE,
      })
    ).toThrow();

    const env = await makeEnv();
    const session = await primarySession(env);
    const res = await postJson(
      CreateRecord,
      env,
      'https://pds.example/xrpc/com.atproto.repo.createRecord',
      {
        repo: env.PDS_DID,
        collection: 'app.bsky.feed.post',
        record: postRecord('format checks'),
      },
      session.accessJwt,
    );
    const body = await json(res);
    const recordCid = CID.parse(body.cid);
    const commitCid = CID.parse(body.commit.cid);
    expect(recordCid.version).toBe(1);
    expect(recordCid.code).toBe(dagCbor.code);
    expect(commitCid.version).toBe(1);
    expect(isValidTid(body.commit.rev)).toBe(true);
    expect(body.uri).toMatch(/^at:\/\/did:example:test\/app\.bsky\.feed\.post\/[a-z2-7]{13}$/);
  });
});

describe('Auth and OAuth conformance smoke', () => {
  it('uses scoped app-password sessions and blocks revoked app-password refresh credentials', async () => {
    const env = await makeEnv();
    const session = await primarySession(env);

    const createdPassword = await json(await postJson(
      CreateAppPassword,
      env,
      'https://pds.example/xrpc/com.atproto.server.createAppPassword',
      { name: 'mobile' },
      session.accessJwt,
    ));
    const appLogin = await createSession(env, {
      identifier: String(env.PDS_HANDLE),
      password: createdPassword.password,
    });
    expect(appLogin.status).toBe(200);
    const appSession = await json(appLogin);
    expect((await verifyAccessToken(env, appSession.accessJwt)).scope).toBe(AuthScope.AppPass);

    const refreshed = await RefreshSession.POST(apiContext(env, new Request(
      'https://pds.example/xrpc/com.atproto.server.refreshSession',
      { method: 'POST', headers: { authorization: `Bearer ${appSession.refreshJwt}` } },
    )));
    expect(refreshed.status).toBe(200);

    await postJson(
      RevokeAppPassword,
      env,
      'https://pds.example/xrpc/com.atproto.server.revokeAppPassword',
      { name: 'mobile' },
      session.accessJwt,
    );

    const blocked = await RefreshSession.POST(apiContext(env, new Request(
      'https://pds.example/xrpc/com.atproto.server.refreshSession',
      { method: 'POST', headers: { authorization: `Bearer ${(await json(refreshed)).refreshJwt}` } },
    )));
    expect(blocked.status).toBe(401);
    expect(await json(blocked)).toMatchObject({ error: 'InvalidToken' });
  });

  it('runs discovery, PAR, consent, token, DPoP resource, refresh, and revoke as one OAuth flow', async () => {
    const restore = mockClientMetadata(CLIENT_ID);
    try {
      const env = await makeEnv();
      const metadataRes = await authServerMetadata(apiContext(
        env,
        new Request('https://pds.example/.well-known/oauth-authorization-server'),
      ));
      const metadata = await json(metadataRes);
      expect(metadata.issuer).toBe('https://pds.example');
      expect(metadata.require_pushed_authorization_requests).toBe(true);
      expect(metadata.dpop_signing_alg_values_supported).toContain('ES256');

      const key = await makeDpopKey();
      const codeVerifier = 'correct horse battery staple';
      const parUrl = 'https://pds.example/oauth/par';
      const parProof = await signDpopProof({ key, method: 'POST', url: parUrl });
      const parRes = await parPost(apiContext(env, new Request(parUrl, {
        method: 'POST',
        headers: { dpop: parProof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: CLIENT_ID,
          response_type: 'code',
          redirect_uri: 'https://client.example/callback',
          scope: 'atproto transition:generic',
          state: 'state123',
          code_challenge: await sha256b64url(codeVerifier),
          code_challenge_method: 'S256',
        }).toString(),
      })));
      expect(parRes.status).toBe(201);
      const parBody = await json(parRes);
      const requestUri = String(parBody.request_uri);
      expect(requestUri).toMatch(/^urn:ietf:params:oauth:request_uri:/);

      const authorizeRes = await authorizeGet(apiContext(env, new Request(
        `https://pds.example/oauth/authorize?client_id=${encodeURIComponent(CLIENT_ID)}&request_uri=${encodeURIComponent(requestUri)}`,
      )));
      expect(authorizeRes.status).toBe(302);
      expect(new URL(authorizeRes.headers.get('location') ?? '').pathname).toBe('/oauth/consent');

      const csrf = await consentCsrf(env, requestUri);
      const consentRes = await consentPost(apiContext(env, new Request('https://pds.example/oauth/consent', {
        method: 'POST',
        headers: { origin: 'https://pds.example', 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          request_uri: requestUri,
          client_id: CLIENT_ID,
          csrf,
          decision: 'allow',
          password: String(env.USER_PASSWORD),
        }).toString(),
      })));
      expect(consentRes.status).toBe(302);
      const code = new URL(consentRes.headers.get('location') ?? '').searchParams.get('code') ?? '';
      expect(code.length).toBeGreaterThan(8);

      const tokenUrl = 'https://pds.example/oauth/token';
      const tokenProof = await signDpopProof({ key, method: 'POST', url: tokenUrl });
      const tokenRes = await tokenPost(apiContext(env, new Request(tokenUrl, {
        method: 'POST',
        headers: { dpop: tokenProof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: CLIENT_ID,
          redirect_uri: 'https://client.example/callback',
          code_verifier: codeVerifier,
        }).toString(),
      })));
      expect(tokenRes.status).toBe(200);
      const tokenBody = await json(tokenRes);
      expect(tokenBody.token_type).toBe('DPoP');
      expect(typeof tokenBody.access_token).toBe('string');
      expect(typeof tokenBody.refresh_token).toBe('string');

      const resourceUrl = 'https://pds.example/xrpc/com.atproto.repo.createRecord';
      const resourceProof = await signResourceDpop(env, key, 'POST', resourceUrl, tokenBody.access_token);
      const verified = await verifyResourceRequestHybrid(env, new Request(resourceUrl, {
        method: 'POST',
        headers: {
          authorization: `DPoP ${tokenBody.access_token}`,
          dpop: resourceProof,
        },
      }));
      expect(verified?.did).toBe(String(env.PDS_DID));
      expect(verified?.scope).toBe('atproto transition:generic');

      const refreshProof = await signDpopProof({ key, method: 'POST', url: tokenUrl });
      const refreshRes = await tokenPost(apiContext(env, new Request(tokenUrl, {
        method: 'POST',
        headers: { dpop: refreshProof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokenBody.refresh_token,
          client_id: CLIENT_ID,
        }).toString(),
      })));
      expect(refreshRes.status).toBe(200);
      const refreshBody = await json(refreshRes);
      expect(refreshBody.token_type).toBe('DPoP');

      const revokeUrl = 'https://pds.example/oauth/revoke';
      const revokeProof = await signDpopProof({ key, method: 'POST', url: revokeUrl });
      const revokeRes = await revokePost(apiContext(env, new Request(revokeUrl, {
        method: 'POST',
        headers: { dpop: revokeProof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          token: refreshBody.refresh_token,
          client_id: CLIENT_ID,
        }).toString(),
      })));
      expect(revokeRes.status).toBe(200);
    } finally {
      restore();
    }
  });

  it('uses stable XRPC auth error shapes for bad credentials and missing auth', async () => {
    const env = await makeEnv();
    const unauthenticated = await CreateAppPassword.POST(apiContext(env, new Request(
      'https://pds.example/xrpc/com.atproto.server.createAppPassword',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'blocked' }),
      },
    )));
    expect(unauthenticated.status).toBe(401);
    expect(await json<any>(unauthenticated)).toEqual({ error: 'AuthRequired' });

    for (let i = 0; i < 4; i++) {
      const bad = await createSession(env, {
        identifier: String(env.PDS_HANDLE),
        password: 'wrong',
      });
      expect(bad.status).toBe(401);
      expect(await json(bad)).toMatchObject({ error: 'AuthRequired' });
    }
    const locked = await createSession(env, {
      identifier: String(env.PDS_HANDLE),
      password: 'wrong',
    });
    expect(locked.status).toBe(429);
    expect(await json(locked)).toMatchObject({ error: 'RateLimitExceeded' });
  });
});
