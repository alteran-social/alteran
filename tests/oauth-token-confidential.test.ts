import type { APIContext } from 'astro';
import { expect } from '@std/expect';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { makeDpopKey, signDpopProof } from './helpers/oauth';
import { getSecret } from '../src/db/account';
import { jwkThumbprint, sha256b64url } from '../src/lib/oauth/dpop';
import { loadCodeSnapshot } from '../src/lib/oauth/store';
import { saveCode } from './helpers/oauth-store';
import { POST } from '../src/pages/oauth/token';
import { POST as revokePost } from '../src/pages/oauth/revoke';

const CLIENT = 'https://client.example/metadata';
const URL = 'https://pds.example/oauth/token';
const TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const VERIFIER = 'confidential-verifier';

async function fixture() {
  const env = await makeEnv();
  const proofKey = await makeDpopKey();
  const clientKey = await generateKeyPair('ES256');
  const clientJwk = { ...await exportJWK(clientKey.publicKey), kid: 'client-key' };
  const clientId = await jwkThumbprint(clientJwk);
  const code = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  await saveCode(env, code, { code, client_id: CLIENT, redirect_uri: 'https://client.example/callback',
    code_challenge: await sha256b64url(VERIFIER), scope: 'atproto', dpopJkt: proofKey.jkt,
    clientAuthMethod: 'private_key_jwt', clientAuthKeyId: clientId, clientAuthKeyBinding: 'jwk-thumbprint-v1',
    did: 'did:example:test', createdAt: now, expiresAt: now + 300 });
  const metadata = { client_id: CLIENT, redirect_uris: ['https://client.example/callback'],
    token_endpoint_auth_method: 'private_key_jwt', grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'], scope: 'atproto', dpop_bound_access_tokens: true, jwks: { keys: [clientJwk] } };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = input instanceof Request ? input.url : String(input);
    return url.startsWith('https://cloudflare-dns.com/dns-query')
      ? Response.json({ Answer: [{ type: 1, data: '93.184.216.34' }] })
      : url === CLIENT ? Response.json(metadata) : new Response(null, { status: 404 });
  }) as typeof fetch;
  async function assertion(exp = now + 120) {
    const jti = crypto.randomUUID();
    const jwt = await new SignJWT({ iss: CLIENT, sub: CLIENT, aud: 'https://pds.example', iat: now, exp, jti })
      .setProtectedHeader({ alg: 'ES256', kid: 'client-key' }).sign(clientKey.privateKey);
    return { jwt, jti };
  }
  async function proof() {
    const jti = crypto.randomUUID();
    return { jti, jwt: await signDpopProof({ key: proofKey, method: 'POST', url: URL, jti }) };
  }
  function form(clientAssertion: string) {
    return new URLSearchParams({ grant_type: 'authorization_code', code, client_id: CLIENT,
      redirect_uri: 'https://client.example/callback', code_verifier: VERIFIER,
      client_assertion_type: TYPE, client_assertion: clientAssertion });
  }
  function post(body: URLSearchParams, jwt: string) {
    const request = new Request(URL, { method: 'POST', headers: { DPoP: jwt }, body });
    return POST({ locals: { env }, request } as unknown as APIContext);
  }
  return { env, code, now, proofKey, assertion, proof, form, post, restore: () => { globalThis.fetch = originalFetch; } };
}

describe('confidential OAuth token transactions', () => {
  it('rolls back both proof claims on a skipped write and permits the same assertions to retry', async () => {
    const f = await fixture();
    try {
      const proof = await f.proof();
      const assertion = await f.assertion();
      await f.env.ALTERAN_DB.prepare(`CREATE TRIGGER skip_confidential_session BEFORE INSERT ON oauth_session
        BEGIN SELECT RAISE(IGNORE); END`).run();
      expect((await f.post(f.form(assertion.jwt), proof.jwt)).status).toBe(400);
      expect(await loadCodeSnapshot(f.env, f.code)).not.toBeNull();
      expect(await getSecret(f.env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
      expect(await getSecret(f.env, `oauth:client-assertion:jti:${CLIENT}:${assertion.jti}`)).toBeNull();
      await f.env.ALTERAN_DB.prepare('DROP TRIGGER skip_confidential_session').run();
      const exchanged = await f.post(f.form(assertion.jwt), proof.jwt);
      expect(exchanged.status).toBe(200);
      const token = (await exchanged.json() as { refresh_token: string }).refresh_token;
      const nextAssertion = await f.assertion();
      const nextProof = await f.proof();
      const refresh = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: token, client_id: CLIENT,
        client_assertion_type: TYPE, client_assertion: nextAssertion.jwt });
      const rotated = await f.post(refresh, nextProof.jwt);
      expect(rotated.status).toBe(200);
      expect(rotated.headers.get('Cache-Control')).toBe('no-store');
      expect(rotated.headers.get('Pragma')).toBe('no-cache');
    } finally {
      f.restore();
    }
  });

  it('rolls back code, session and both markers when the assertion expires during insertion', async () => {
    const f = await fixture();
    try {
      const proof = await f.proof();
      const assertion = await f.assertion(f.now + 30);
      await f.env.ALTERAN_DB.prepare(`CREATE TRIGGER expire_client_assertion AFTER INSERT ON secret
        WHEN NEW.key GLOB 'oauth:client-assertion:jti:*' BEGIN
          UPDATE oauth_replay_clock SET seconds = MAX(seconds, ${f.now + 30}) WHERE id = 1;
        END`).run();
      expect((await f.post(f.form(assertion.jwt), proof.jwt)).status).toBe(400);
      expect(await loadCodeSnapshot(f.env, f.code)).not.toBeNull();
      expect(await getSecret(f.env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
      expect(await getSecret(f.env, `oauth:client-assertion:jti:${CLIENT}:${assertion.jti}`)).toBeNull();
    } finally {
      f.restore();
    }
  });

  it('does not spend either marker when an assertion expires on the Worker during signing', async () => {
    const f = await fixture();
    const originalNow = Date.now;
    const originalSign = crypto.subtle.sign.bind(crypto.subtle);
    try {
      const proof = await f.proof();
      const assertion = await f.assertion(f.now + 30);
      let signatures = 0;
      Object.defineProperty(crypto.subtle, 'sign', { configurable: true, value: async (...args: Parameters<SubtleCrypto['sign']>) => {
        const result = await originalSign(...args);
        if (++signatures === 1) Date.now = () => (f.now + 31) * 1000;
        return result;
      } });
      Date.now = () => f.now * 1000;
      expect((await f.post(f.form(assertion.jwt), proof.jwt)).status).toBe(400);
      expect(signatures).toBeGreaterThan(0);
      expect(await loadCodeSnapshot(f.env, f.code)).not.toBeNull();
      expect(await getSecret(f.env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
      expect(await getSecret(f.env, `oauth:client-assertion:jti:${CLIENT}:${assertion.jti}`)).toBeNull();
    } finally {
      Date.now = originalNow;
      delete (crypto.subtle as { sign?: unknown }).sign;
      f.restore();
    }
  });

  it('rolls back both claims when rotation wins a confidential revocation race', async () => {
    const f = await fixture();
    try {
      const initialAssertion = await f.assertion();
      const initialProof = await f.proof();
      const exchange = await f.post(f.form(initialAssertion.jwt), initialProof.jwt);
      expect(exchange.status).toBe(200);
      const tokens = await exchange.json() as { access_token: string; refresh_token: string };
      const revokeAssertion = await f.assertion();
      const rotationAssertion = await f.assertion();
      const rotationProof = await f.proof();
      const jti = crypto.randomUUID();
      const revokeUrl = 'https://pds.example/oauth/revoke';
      const revokeProof = await signDpopProof({ key: f.proofKey, method: 'POST', url: revokeUrl, jti });
      const database = f.env.ALTERAN_DB;
      let rotated = false;
      const wrapped = { ...f.env, ALTERAN_DB: new Proxy(database, { get(target, property) {
        if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
          if (!rotated) {
            rotated = true;
            const form = new URLSearchParams({ grant_type: 'refresh_token', client_id: CLIENT,
              refresh_token: tokens.refresh_token, client_assertion_type: TYPE, client_assertion: rotationAssertion.jwt });
            expect((await f.post(form, rotationProof.jwt)).status).toBe(200);
          }
          return database.batch(statements);
        };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      } }) };
      const request = new Request(revokeUrl, { method: 'POST', headers: { DPoP: revokeProof },
        body: new URLSearchParams({ token: tokens.access_token, client_id: CLIENT,
          client_assertion_type: TYPE, client_assertion: revokeAssertion.jwt }) });
      expect((await revokePost({ locals: { env: wrapped }, request } as unknown as APIContext)).status).toBe(200);
      expect(rotated).toBe(true);
      expect(await getSecret(f.env, `oauth:dpop:jti:authz:${jti}`)).toBeNull();
      expect(await getSecret(f.env, `oauth:client-assertion:jti:${CLIENT}:${revokeAssertion.jti}`)).toBeNull();
    } finally {
      f.restore();
    }
  });
});
