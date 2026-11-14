import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { makeDpopKey, signAuthzDpop } from './helpers/oauth';
import { createAccount } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { hashPassword } from '../src/lib/password';
import { sha256b64url, withDpop } from '../src/lib/oauth/dpop';
import { POST as parPost } from '../src/pages/oauth/par';
import { GET as consentGet, POST as consentPost } from '../src/pages/oauth/consent';
import { POST as tokenPost } from '../src/pages/oauth/token';
import { POST as revokePost } from '../src/pages/oauth/revoke';

const ORIGIN = 'https://pds.example';
const DID = 'did:example:test';
const ACCEPTED_KEY = 'privateacceptedkey';
const REJECTED_KEY = 'privaterejectedkey';
const SPACE_SCOPE = `space:com.example.forum?authority=${DID}&skey=${ACCEPTED_KEY}&action=read_self`;
const SCOPE = `atproto ${SPACE_SCOPE}`;
const REJECTED_SCOPE = `atproto space:com.example.forum?authority=${DID}&skey=${REJECTED_KEY}&action=read_self`;
const CLIENT = `http://localhost?${new URLSearchParams({
  redirect_uri: 'http://127.0.0.1/callback', scope: SCOPE,
})}`;
const REDIRECT = 'http://127.0.0.1:51789/callback';
const VERIFIER = 'observability-flow-code-verifier-0123456789';

type TestEnv = Awaited<ReturnType<typeof makeEnv>>;
type Key = Awaited<ReturnType<typeof makeDpopKey>>;

function context(env: TestEnv, request: Request) {
  return { locals: { env }, request, url: new URL(request.url) } as never;
}

async function push(env: TestEnv, key: Key, scope: string) {
  const url = `${ORIGIN}/oauth/par`;
  return parPost(context(env, new Request(url, {
    method: 'POST',
    headers: {
      dpop: await signAuthzDpop(env, key, 'POST', url),
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: CLIENT, response_type: 'code', redirect_uri: REDIRECT,
      scope, state: 'state', code_challenge: await sha256b64url(VERIFIER),
      code_challenge_method: 'S256',
    }),
  })));
}

async function exchange(env: TestEnv, key: Key, form: Record<string, string>) {
  const url = `${ORIGIN}/oauth/token`;
  return tokenPost(context(env, new Request(url, {
    method: 'POST',
    headers: {
      dpop: await signAuthzDpop(env, key, 'POST', url),
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ client_id: CLIENT, ...form }),
  })));
}

describe('OAuth observability in signed flows', () => {
  it('does not log private scope identifiers on PAR success, scope failure, or token exchange', async () => {
    const env = await makeEnv();
    await createAccount(env, { did: DID, handle: 'test.example', passwordScrypt: await hashPassword('pwd') });
    await setAccountState(env, DID, { tag: 'active' });
    const key = await makeDpopKey();
    const lines: string[] = [];
    const originalLog = console.log;
    const originalError = console.error;
    console.log = (...values: unknown[]) => lines.push(values.map(String).join(' '));
    console.error = (...values: unknown[]) => lines.push(values.map(String).join(' '));
    try {
      const par = await push(env, key, SCOPE);
      expect(par.status).toBe(201);
      const requestUri = (await par.json() as { request_uri: string }).request_uri;
      const page = await consentGet(context(env, new Request(
        `${ORIGIN}/oauth/consent?request_uri=${encodeURIComponent(requestUri)}`,
      )));
      expect(page.status).toBe(200);
      const html = await page.text();
      const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1];
      if (!csrf) throw new Error('Missing consent token');
      const approved = await consentPost(context(env, new Request(`${ORIGIN}/oauth/consent`, {
        method: 'POST',
        headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ request_uri: requestUri, client_id: CLIENT, csrf, password: 'pwd', decision: 'allow' }),
      })));
      const code = new URL(approved.headers.get('location') ?? '').searchParams.get('code');
      if (!code) throw new Error('Missing authorization code');
      const issued = await exchange(env, key, {
        grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: VERIFIER,
      });
      expect(issued.status).toBe(200);
      expect((await issued.json() as { scope: string }).scope).toContain(ACCEPTED_KEY);

      const rejected = await push(env, key, REJECTED_SCOPE);
      expect(rejected.status).toBe(400);
      const error = await rejected.json() as { error: string; error_description: string };
      expect(error.error).toBe('invalid_scope');
      expect(error.error_description).toContain(REJECTED_KEY);
      const invalidGrant = await exchange(env, key, { grant_type: `invalid-${REJECTED_KEY}` });
      expect(invalidGrant.status).toBe(400);
    } finally {
      console.log = originalLog;
      console.error = originalError;
    }

    const captured = lines.join('\n');
    for (const privateValue of [ACCEPTED_KEY, REJECTED_KEY, DID, encodeURIComponent(DID), CLIENT, VERIFIER]) {
      expect(captured).not.toContain(privateValue);
    }
    const records = lines.map((line) => JSON.parse(line) as {
      type: string; stage: string; outcome: string; form: Record<string, unknown> | null;
    });
    const parSuccess = records.find((record) => record.type === 'oauth_par' && record.stage === 'success');
    const parFailure = records.find((record) => record.type === 'oauth_par' && record.stage === 'par_validate');
    const tokenSuccess = records.find((record) => record.type === 'oauth_token' && record.stage === 'success');
    const tokenFailure = records.find((record) => record.type === 'oauth_token' && record.stage === 'unsupported_grant');
    expect(parSuccess?.outcome).toBe('ok');
    expect(parSuccess?.form?.scopeCount).toBe(2);
    expect(parFailure?.outcome).toBe('error');
    expect(tokenSuccess?.outcome).toBe('ok');
    expect(tokenSuccess?.form?.grantType).toBe('authorization_code');
    expect(tokenFailure?.outcome).toBe('error');
    expect(tokenFailure?.form?.grantType).toBe('other');
  });

  it('returns generic errors for database faults and retains the DPoP challenge', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const marker = 'private-database-fault-identifier';
    const failingDatabase = new Proxy(env.ALTERAN_DB, {
      get(target, property) {
        if (property === 'prepare') return () => { throw new Error(marker); };
        return Reflect.get(target, property, target);
      },
    });
    const failingEnv = { ...env, ALTERAN_DB: failingDatabase };
    const handlers = [
      ['par', parPost], ['token', tokenPost], ['revoke', revokePost],
    ] as const;
    const lines: string[] = [];
    const originalLog = console.log;
    const originalError = console.error;
    console.log = (...values: unknown[]) => lines.push(values.map(String).join(' '));
    console.error = (...values: unknown[]) => lines.push(values.map(String).join(' '));
    try {
      for (const [name, handler] of handlers) {
        const url = `${ORIGIN}/oauth/${name}`;
        const proof = await signAuthzDpop(env, key, 'POST', url);
        const response = await handler(context(failingEnv, new Request(url, {
          method: 'POST', headers: { dpop: proof, 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ client_id: CLIENT, scope: SCOPE }),
        })));
        const body = await response.text();
        expect(response.status).toBe(400);
        expect(body).not.toContain(marker);
        expect(JSON.parse(body)).toEqual({ error: 'invalid_request', error_description: 'OAuth request failed' });

        const challenge = await handler(context(env, new Request(url, { method: 'POST' })));
        expect(challenge.status).toBe(401);
        expect(challenge.headers.get('DPoP-Nonce')).toBeTruthy();
        expect((await challenge.json() as { error: string }).error).toBe('use_dpop_nonce');
      }
      const wrapperUrl = `${ORIGIN}/oauth/wrapper`;
      const wrapperProof = await signAuthzDpop(env, key, 'POST', wrapperUrl);
      const wrapped = await withDpop(env, new Request(wrapperUrl, {
        method: 'POST', headers: { dpop: wrapperProof },
      }), async () => { throw new Error(marker); });
      expect(wrapped.status).toBe(400);
      const wrappedBody = await wrapped.text();
      expect(wrappedBody).not.toContain(marker);
      expect(JSON.parse(wrappedBody)).toEqual({ error: 'invalid_request', error_description: 'OAuth request failed' });
    } finally {
      console.log = originalLog;
      console.error = originalError;
    }
    expect(lines.join('\n')).not.toContain(marker);
    expect(lines.join('\n')).not.toContain(ACCEPTED_KEY);
  });

  it('does not return or log unexpected client metadata fetch errors', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const url = `${ORIGIN}/oauth/par`;
    const proof = await signAuthzDpop(env, key, 'POST', url);
    const marker = 'private-fetch-fault-identifier';
    const originalFetch = globalThis.fetch;
    const originalError = console.error;
    const lines: string[] = [];
    console.error = (...values: unknown[]) => lines.push(values.map(String).join(' '));
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const href = input instanceof Request ? input.url : String(input);
      if (href.startsWith('https://cloudflare-dns.com/dns-query')) {
        return new Response(JSON.stringify({ Answer: [{ type: 1, data: '93.184.216.34' }] }), {
          status: 200, headers: { 'content-type': 'application/json' },
        });
      }
      throw new Error(marker);
    }) as typeof fetch;
    try {
      const response = await parPost(context(env, new Request(url, {
        method: 'POST', headers: { dpop: proof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: 'https://client.example/metadata', state: 'state' }),
      })));
      const body = await response.text();
      expect(response.status).toBe(400);
      expect(JSON.parse(body)).toEqual({ error: 'invalid_client', error_description: 'Client metadata fetch failed' });
      expect(body).not.toContain(marker);
    } finally {
      globalThis.fetch = originalFetch;
      console.error = originalError;
    }
    expect(lines.join('\n')).not.toContain(marker);
  });
});
