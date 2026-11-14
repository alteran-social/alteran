import { describe, it } from './helpers/bdd';
import { expect } from '@std/expect';
import type { APIContext } from 'astro';
import { makeEnv } from './helpers/env';
import { makeDpopKey, mockClientMetadata, signAuthzDpop } from './helpers/oauth';
import { sha256b64url } from '../src/lib/oauth/dpop';
import { verifyAccessToken } from '../src/lib/session-tokens';
import { POST as parPost } from '../src/pages/oauth/par';
import { GET as consentGet, POST as consentPost } from '../src/pages/oauth/consent';
import { POST as tokenPost } from '../src/pages/oauth/token';

const ORIGIN = 'https://pds.example';
const CLIENT_ID = 'https://client.example/metadata';
const REDIRECT_URI = 'https://client.example/callback';
const COLLECTION = 'app.bsky.feed.post';
const SPACE_SCOPE = 'space:com.example.board?authority=*&action=read';
const GRANTED_SCOPE = `atproto transition:generic repo:${COLLECTION}?action=create`;
const REQUESTED_SCOPE = `${GRANTED_SCOPE} ${SPACE_SCOPE}`;
const CODE_VERIFIER = 'spaces-scope-test-code-verifier-0123456789';

type TestEnv = Awaited<ReturnType<typeof makeEnv>>;
type DpopKey = Awaited<ReturnType<typeof makeDpopKey>>;

function context(env: TestEnv, request: Request) {
  return { locals: { env }, request, url: new URL(request.url) } as unknown as APIContext;
}

function mockSpacesClientMetadata(): () => void {
  const restore = mockClientMetadata(CLIENT_ID);
  const fetchMock = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url === CLIENT_ID) {
      return Response.json({
        client_id: CLIENT_ID,
        client_name: 'Test Client',
        redirect_uris: [REDIRECT_URI],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        scope: REQUESTED_SCOPE,
        dpop_bound_access_tokens: true,
      });
    }
    return fetchMock(input, init);
  }) as typeof fetch;
  return restore;
}

async function pushAuthorizationRequest(
  env: TestEnv,
  key: DpopKey,
  clientId: string,
  redirectUri: string,
) {
  const url = `${ORIGIN}/oauth/par`;
  return parPost(context(env, new Request(url, {
    method: 'POST',
    headers: {
      dpop: await signAuthzDpop(env, key, 'POST', url),
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: clientId,
      response_type: 'code',
      redirect_uri: redirectUri,
      scope: REQUESTED_SCOPE,
      state: 'state123',
      code_challenge: await sha256b64url(CODE_VERIFIER),
      code_challenge_method: 'S256',
    }).toString(),
  })));
}

async function exchange(env: TestEnv, key: DpopKey, form: Record<string, string>) {
  const url = `${ORIGIN}/oauth/token`;
  const response = await tokenPost(context(env, new Request(url, {
    method: 'POST',
    headers: {
      dpop: await signAuthzDpop(env, key, 'POST', url),
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ client_id: CLIENT_ID, ...form }).toString(),
  })));
  return {
    status: response.status,
    body: await response.json() as { scope: string; access_token: string; refresh_token: string },
  };
}

describe('OAuth requests for unsupported Spaces permissions', () => {
  it('omits the Spaces grant from consent, tokens, and refresh while retaining supported permissions', async () => {
    const restore = mockSpacesClientMetadata();
    try {
      const env = await makeEnv();
      const key = await makeDpopKey();
      const par = await pushAuthorizationRequest(env, key, CLIENT_ID, REDIRECT_URI);
      expect(par.status).toBe(201);
      const requestUri = String((await par.json() as { request_uri: string }).request_uri);

      const consent = await consentGet(context(env, new Request(
        `${ORIGIN}/oauth/consent?request_uri=${encodeURIComponent(requestUri)}`,
      )));
      expect(consent.status).toBe(200);
      const html = await consent.text();
      expect(html).toContain(`Requested scope: <code>${GRANTED_SCOPE}</code>`);
      expect(html).toContain('Full access to your repository');
      expect(html).toContain(`Create records in the collection ${COLLECTION}`);
      expect(html).not.toContain('space:com.example.board');
      const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1] ?? '';
      expect(csrf).toBeTruthy();

      const authorization = await consentPost(context(env, new Request(`${ORIGIN}/oauth/consent`, {
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
      expect(authorization.status).toBe(302);
      const code = new URL(authorization.headers.get('location') ?? '').searchParams.get('code') ?? '';
      expect(code).toBeTruthy();

      const tokens = await exchange(env, key, {
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: CODE_VERIFIER,
      });
      expect(tokens.status).toBe(200);
      expect(tokens.body.scope).toBe(GRANTED_SCOPE);
      expect((await verifyAccessToken(env, tokens.body.access_token)).scope).toBe(GRANTED_SCOPE);

      const refreshed = await exchange(env, key, {
        grant_type: 'refresh_token',
        refresh_token: tokens.body.refresh_token,
      });
      expect(refreshed.status).toBe(200);
      expect(refreshed.body.scope).toBe(GRANTED_SCOPE);
      expect((await verifyAccessToken(env, refreshed.body.access_token)).scope).toBe(GRANTED_SCOPE);
    } finally {
      restore();
    }
  });

  it('rejects a localhost client that declares an unsupported Spaces scope', async () => {
    const env = await makeEnv();
    const clientId = `http://localhost?${new URLSearchParams({
      redirect_uri: 'http://127.0.0.1/callback',
      scope: REQUESTED_SCOPE,
    })}`;
    const response = await pushAuthorizationRequest(
      env,
      await makeDpopKey(),
      clientId,
      'http://127.0.0.1:51789/callback',
    );
    expect(response.status).toBe(400);
    expect((await response.json() as { error: string }).error).toBe('invalid_client');
  });
});
