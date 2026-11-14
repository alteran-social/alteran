import { createOAuthSession, getOAuthSession } from './helpers/oauth-store';
import type { APIContext } from 'astro';
import { expect } from '@std/expect';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyLike } from 'jose';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { makeDpopKey, signDpopProof } from './helpers/oauth';
import { advanceReplayClock } from './helpers/oauth-clock';
import type { Env } from '../src/env';
import { storeRefreshToken } from '../src/db/account';
import { jwkThumbprint, verifyDpop } from '../src/lib/oauth/dpop';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { POST as tokenPost } from '../src/pages/oauth/token';

const CLIENT = 'https://client.example/metadata';
const URL = 'https://pds.example/oauth/token';
const DID = 'did:example:test';
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
type DpopKey = Awaited<ReturnType<typeof makeDpopKey>>;

async function issueRefresh(env: Env, key: DpopKey, method = 'none', keyId: string | null = null, keyBinding: string | null = null) {
  const sessionId = crypto.randomUUID().replace(/-/g, '');
  const accessJti = crypto.randomUUID().replace(/-/g, '');
  const tokens = await issueSessionTokens(env, DID, {
    accessScope: 'atproto', clientId: CLIENT, dpopJkt: key.jkt, oauthSessionId: sessionId, accessJti,
  });
  await createOAuthSession(env, {
    id: sessionId, did: DID, clientId: CLIENT, clientAuthMethod: method, clientAuthKeyId: keyId, clientAuthKeyBinding: keyBinding,
    dpopJkt: key.jkt, scope: 'atproto', currentRefreshTokenId: tokens.refreshPayload.jti,
    accessJti, expiresAt: tokens.refreshExpiry,
  });
  await storeRefreshToken(env, {
    id: tokens.refreshPayload.jti, did: DID, expiresAt: tokens.refreshExpiry, tokenKind: 'oauth',
    oauthSessionId: sessionId, clientId: CLIENT, clientAuthMethod: method as 'none' | 'private_key_jwt',
    clientAuthKeyId: keyId, dpopJkt: key.jkt, oauthScope: 'atproto', accessJti,
  });
  return { sessionId, refreshToken: tokens.refreshJwt, refreshId: tokens.refreshPayload.jti };
}

function proof(key: DpopKey) {
  return signDpopProof({ key, method: 'POST', url: URL });
}

function refresh(env: Env, token: string, signedProof: string, extras: Record<string, string> = {}) {
  const request = new Request(URL, {
    method: 'POST',
    headers: { dpop: signedProof, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: token, client_id: CLIENT, ...extras }),
  });
  return tokenPost({ locals: { env }, request } as unknown as APIContext);
}

async function active(env: Env, sessionId: string): Promise<boolean> {
  const session = await getOAuthSession(env, sessionId);
  return !!session && !session.revokedAt;
}

describe('OAuth refresh replay authentication', () => {
  it('rejects wrong clients, wrong keys and replayed proofs without revoking; authentic replay revokes', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const wrongKey = await makeDpopKey();
    const issued = await issueRefresh(env, key);
    const originalProof = await proof(key);
    const rotation = await refresh(env, issued.refreshToken, originalProof);
    expect(rotation.status).toBe(200);
    const successor = (await rotation.json() as { refresh_token: string }).refresh_token;

    expect((await refresh(env, issued.refreshToken, await proof(key), { client_id: 'https://other.example/metadata' })).status).toBe(400);
    expect(await active(env, issued.sessionId)).toBe(true);
    expect((await refresh(env, issued.refreshToken, await proof(wrongKey))).status).toBe(400);
    expect(await active(env, issued.sessionId)).toBe(true);
    expect((await refresh(env, issued.refreshToken, originalProof)).status).toBe(401);
    expect(await active(env, issued.sessionId)).toBe(true);

    const replay = await refresh(env, issued.refreshToken, await proof(key));
    expect(replay.status).toBe(400);
    expect((await replay.json() as { error_description: string }).error_description).toContain('replay');
    expect(await active(env, issued.sessionId)).toBe(false);
    expect((await refresh(env, successor, await proof(key))).status).toBe(400);
  });

  it('rejects a subject mismatch without revoking the session', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const wrongKey = await makeDpopKey();
    const issued = await issueRefresh(env, key);
    await env.ALTERAN_DB.prepare('UPDATE refresh_token SET did = ? WHERE id = ?')
      .bind('did:example:other', issued.refreshId).run();

    const usedProof = await proof(key);
    await verifyDpop(env, new Request(URL, { method: 'POST', headers: { dpop: usedProof } }), { requireNonce: false });
    expect((await refresh(env, issued.refreshToken, usedProof)).status).toBe(400);
    expect((await refresh(env, issued.refreshToken, await proof(wrongKey))).status).toBe(400);
    expect(await active(env, issued.sessionId)).toBe(true);

    const boundProof = await proof(key);
    expect((await refresh(env, issued.refreshToken, boundProof, { client_id: 'https://other.example/metadata' })).status).toBe(400);
    expect(await active(env, issued.sessionId)).toBe(true);
    const mismatch = await refresh(env, issued.refreshToken, boundProof);
    expect(mismatch.status).toBe(400);
    expect((await mismatch.json() as { error_description: string }).error_description).toContain('binding mismatch');
    expect(await active(env, issued.sessionId)).toBe(true);
  });

  it('does not revoke a session when a verified duplicate is held past proof expiry', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const issued = await issueRefresh(env, key);
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    const signedProof = await new SignJWT({
      htm: 'POST', htu: URL, iat: now - 299, jti: crypto.randomUUID(),
    }).setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk as JWK }).sign(key.privateKey);
    const form = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: issued.refreshToken, client_id: CLIENT }).toString();
    const headers = { dpop: signedProof, 'content-type': 'application/x-www-form-urlencoded' };
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    const stream = new ReadableStream<Uint8Array>({ start(value) { controller = value; } });
    const held = new Request(URL, { method: 'POST', headers, body: stream, duplex: 'half' } as RequestInit);
    let signalReading!: () => void;
    const reading = new Promise<void>((resolve) => { signalReading = resolve; });
    const heldBody = held.body;
    Object.defineProperty(held, 'body', { get() { signalReading(); return heldBody; } });
    try {
      Date.now = () => now * 1000;
      const pending = tokenPost({ locals: { env }, request: held } as unknown as APIContext);
      await reading;
      const first = await refresh(env, issued.refreshToken, signedProof);
      const successor = (await first.json() as { refresh_token: string }).refresh_token;
      Date.now = () => (now + 2) * 1000;
      await advanceReplayClock(env, now + 2);
      controller.enqueue(new TextEncoder().encode(form));
      controller.close();
      const duplicate = await pending;
      expect(first.status).toBe(200);
      expect(duplicate.status).toBe(401);
      expect(await active(env, issued.sessionId)).toBe(true);
      expect((await refresh(env, successor, await proof(key))).status).toBe(200);
    } finally {
      Date.now = originalNow;
    }
  });

  it('does not revoke on a fresh proof that expires only on the Worker before replay admission', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const issued = await issueRefresh(env, key);
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    const jti = crypto.randomUUID();
    const heldProof = await new SignJWT({ htm: 'POST', htu: URL, iat: now - 290, jti })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk as JWK }).sign(key.privateKey);
    const form = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: issued.refreshToken, client_id: CLIENT }).toString();
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    const stream = new ReadableStream<Uint8Array>({ start(value) { controller = value; } });
    const held = new Request(URL, { method: 'POST', headers: { dpop: heldProof }, body: stream, duplex: 'half' } as RequestInit);
    let signalReading!: () => void;
    const reading = new Promise<void>((resolve) => { signalReading = resolve; });
    const heldBody = held.body;
    Object.defineProperty(held, 'body', { get() { signalReading(); return heldBody; } });
    try {
      Date.now = () => now * 1000;
      const pending = tokenPost({ locals: { env }, request: held } as unknown as APIContext);
      await reading;
      const first = await refresh(env, issued.refreshToken, await proof(key));
      expect(first.status).toBe(200);
      Date.now = () => (now + 11) * 1000;
      controller.enqueue(new TextEncoder().encode(form));
      controller.close();
      expect((await pending).status).toBe(401);
      expect(await active(env, issued.sessionId)).toBe(true);
      expect(await env.ALTERAN_DB.prepare('SELECT key FROM secret WHERE key = ?')
        .bind(`oauth:dpop:jti:authz:${jti}`).first()).toBeNull();
    } finally {
      Date.now = originalNow;
    }
  });

  it('requires the stored confidential client key before replay can revoke', async () => {
    const env = await makeEnv();
    const dpop = await makeDpopKey();
    const client = await generateKeyPair('ES256');
    const other = await generateKeyPair('ES256');
    const metadata = {
      client_id: CLIENT, redirect_uris: ['https://client.example/callback'],
      token_endpoint_auth_method: 'private_key_jwt', grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'], scope: 'atproto', dpop_bound_access_tokens: true,
      jwks: { keys: [
        { ...await exportJWK(client.publicKey), kid: 'client-key' },
        { ...await exportJWK(other.publicKey), kid: 'other-key' },
      ] },
    };
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.startsWith('https://cloudflare-dns.com/dns-query')) {
        return Response.json({ Answer: [{ type: 1, data: '93.184.216.34' }] });
      }
      if (url === CLIENT) return Response.json(metadata);
      return new Response(null, { status: 404 });
    }) as typeof fetch;
    const assertion = async (privateKey: KeyLike, kid: string) => {
      const now = Math.floor(Date.now() / 1000);
      return await new SignJWT({ iss: CLIENT, sub: CLIENT, aud: 'https://pds.example', iat: now, exp: now + 60, jti: crypto.randomUUID() })
        .setProtectedHeader({ alg: 'ES256', kid }).sign(privateKey);
    };
    const auth = async (privateKey: KeyLike, kid: string) => ({
      client_assertion_type: ASSERTION_TYPE, client_assertion: await assertion(privateKey, kid),
    });
    try {
      const issued = await issueRefresh(env, dpop, 'private_key_jwt', await jwkThumbprint(metadata.jwks.keys[0]), 'jwk-thumbprint-v1');
      const rotation = await refresh(env, issued.refreshToken, await proof(dpop), await auth(client.privateKey, 'client-key'));
      expect(rotation.status).toBe(200);

      expect((await refresh(env, issued.refreshToken, await proof(dpop))).status).toBe(400);
      expect(await active(env, issued.sessionId)).toBe(true);
      expect((await refresh(env, issued.refreshToken, await proof(dpop), await auth(other.privateKey, 'other-key'))).status).toBe(400);
      expect(await active(env, issued.sessionId)).toBe(true);

      const replay = await refresh(env, issued.refreshToken, await proof(dpop), await auth(client.privateKey, 'client-key'));
      expect(replay.status).toBe(400);
      expect((await replay.json() as { error_description: string }).error_description).toContain('replay');
      expect(await active(env, issued.sessionId)).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('atomically consumes one proof when identical refresh requests race', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const issued = await issueRefresh(env, key);
    const sameProof = await proof(key);
    const results = await Promise.all([
      refresh(env, issued.refreshToken, sameProof),
      refresh(env, issued.refreshToken, sameProof),
    ]);
    expect(results.map((result) => result.status).sort()).toEqual([200, 401]);
    expect(await active(env, issued.sessionId)).toBe(true);
    const success = results.find((result) => result.status === 200)!;
    const successor = (await success.json() as { refresh_token: string }).refresh_token;
    expect((await refresh(env, successor, await proof(key))).status).toBe(200);
  });
});
