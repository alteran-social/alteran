import { createOAuthSession, getOAuthSession, saveCode } from './helpers/oauth-store';
import type { APIContext } from 'astro';
import { expect } from '@std/expect';
import { SignJWT } from 'jose';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { makeDpopKey, signDpopProof } from './helpers/oauth';
import { getSecret, storeRefreshToken } from '../src/db/account';
import { sha256b64url } from '../src/lib/oauth/dpop';
import { loadCodeSnapshot, type CodeRecord } from '../src/lib/oauth/store';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { POST } from '../src/pages/oauth/token';
import type { Env } from '../src/env';

const URL = 'https://pds.example/oauth/token';
const CLIENT = 'https://client.example/metadata';
const REDIRECT = 'https://client.example/callback';
const DID = 'did:example:test';
const SECRET = 'atomic-oauth-exchange-test-secret';
const VERIFIER = 'test-verifier-for-authorization-code';
type Key = Awaited<ReturnType<typeof makeDpopKey>>;

async function post(env: Env, form: URLSearchParams, proof: string) {
  const request = new Request(URL, { method: 'POST', headers: { DPoP: proof }, body: form });
  return POST({ locals: { env }, request } as unknown as APIContext);
}

async function signed(key: Key, jti = crypto.randomUUID()) {
  return { jti, jwt: await signDpopProof({ key, method: 'POST', url: URL, jti }) };
}

async function codeFixture(env: Env) {
  const key = await makeDpopKey();
  const code = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const record: CodeRecord = {
    code, client_id: CLIENT, redirect_uri: REDIRECT, code_challenge: await sha256b64url(VERIFIER),
    scope: 'atproto', dpopJkt: key.jkt, clientAuthMethod: 'none', clientAuthKeyId: null,
    did: DID, createdAt: now, expiresAt: now + 300,
  };
  await saveCode(env, code, record);
  const form = () => new URLSearchParams({ grant_type: 'authorization_code', code, client_id: CLIENT,
    redirect_uri: REDIRECT, code_verifier: VERIFIER });
  return { key, code, record, form };
}

async function refreshFixture(env: Env) {
  const key = await makeDpopKey();
  const id = crypto.randomUUID();
  const accessJti = crypto.randomUUID();
  const tokens = await issueSessionTokens(env, DID, { accessScope: 'atproto', clientId: CLIENT,
    dpopJkt: key.jkt, oauthSessionId: id, accessJti });
  await createOAuthSession(env, { id, did: DID, clientId: CLIENT, clientAuthMethod: 'none', dpopJkt: key.jkt,
    scope: 'atproto', currentRefreshTokenId: tokens.refreshPayload.jti, accessJti, expiresAt: tokens.refreshExpiry });
  await storeRefreshToken(env, { id: tokens.refreshPayload.jti, did: DID, expiresAt: tokens.refreshExpiry,
    tokenKind: 'oauth', oauthSessionId: id, clientId: CLIENT, clientAuthMethod: 'none', dpopJkt: key.jkt,
    oauthScope: 'atproto', accessJti });
  const form = (token = tokens.refreshJwt) => new URLSearchParams({ grant_type: 'refresh_token',
    client_id: CLIENT, refresh_token: token });
  return { key, id, tokens, form };
}

function wrapBatch(env: Env, batch: (statements: D1PreparedStatement[], database: D1Database) => Promise<D1Result[]>): Env {
  const database = env.ALTERAN_DB;
  return { ...env, ALTERAN_DB: new Proxy(database, {
    get(target, property) {
      if (property === 'batch') return (statements: D1PreparedStatement[]) => batch(statements, database);
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) };
}

async function count(env: Env, table: 'oauth_session' | 'refresh_token'): Promise<number> {
  const row = await env.ALTERAN_DB.prepare(`SELECT count(*) AS count FROM ${table}`).first<{ count: number }>();
  return row?.count ?? -1;
}

describe('atomic OAuth token exchange', () => {
  it('does not burn a code or proof for an invalid client, redirect, PKCE or DPoP key', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await codeFixture(env);
    const proof = await signed(fixture.key);
    for (const [field, value] of [['client_id', 'https://wrong.example'], ['redirect_uri', 'https://wrong.example'],
      ['code_verifier', 'wrong-verifier']] as const) {
      const form = fixture.form();
      form.set(field, value);
      expect((await post(env, form, proof.jwt)).status).toBe(400);
      expect(await loadCodeSnapshot(env, fixture.code)).not.toBeNull();
      expect(await getSecret(env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
    }
    expect((await post(env, fixture.form(), (await signed(await makeDpopKey())).jwt)).status).toBe(400);
    const response = await post(env, fixture.form(), proof.jwt);
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.get('Pragma')).toBe('no-cache');
    expect(await loadCodeSnapshot(env, fixture.code)).toBeNull();
    expect(await count(env, 'oauth_session')).toBe(1);
    expect(await count(env, 'refresh_token')).toBe(1);
  });

  it('rolls back a skipped or rewritten session insertion and permits the same proof to retry', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await codeFixture(env);
    const proof = await signed(fixture.key);
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER skip_oauth_session BEFORE INSERT ON oauth_session
      BEGIN SELECT RAISE(IGNORE); END`).run();
    expect((await post(env, fixture.form(), proof.jwt)).status).toBe(400);
    expect(await loadCodeSnapshot(env, fixture.code)).not.toBeNull();
    expect(await getSecret(env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
    expect(await count(env, 'refresh_token')).toBe(0);
    await env.ALTERAN_DB.prepare('DROP TRIGGER skip_oauth_session').run();
    expect((await post(env, fixture.form(), proof.jwt)).status).toBe(200);
  });

  it('does not commit a code that expires after proof insertion', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await codeFixture(env);
    const exp = Math.floor(Date.now() / 1000) + 30;
    await saveCode(env, fixture.code, { ...fixture.record, expiresAt: exp });
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER expire_code AFTER INSERT ON secret
      WHEN NEW.key GLOB 'oauth:dpop:jti:authz:*' BEGIN
        UPDATE oauth_replay_clock SET seconds = MAX(seconds, ${exp}) WHERE id = 1;
      END`).run();
    const proof = await signed(fixture.key);
    expect((await post(env, fixture.form(), proof.jwt)).status).toBe(400);
    expect(await loadCodeSnapshot(env, fixture.code)).not.toBeNull();
    expect(await getSecret(env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
    expect(await count(env, 'oauth_session')).toBe(0);
  });

  it('does not spend a code that expires on the Worker while tokens are signed', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await codeFixture(env);
    const proof = await signed(fixture.key);
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    await saveCode(env, fixture.code, { ...fixture.record, expiresAt: now + 5 });
    const originalSign = crypto.subtle.sign.bind(crypto.subtle);
    let signatures = 0;
    Object.defineProperty(crypto.subtle, 'sign', { configurable: true, value: async (...args: Parameters<SubtleCrypto['sign']>) => {
      const result = await originalSign(...args);
      if (++signatures === 1) Date.now = () => (now + 10) * 1000;
      return result;
    } });
    try {
      Date.now = () => now * 1000;
      expect((await post(env, fixture.form(), proof.jwt)).status).toBe(400);
      expect(signatures).toBeGreaterThan(0);
      expect(await getSecret(env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
      expect(await count(env, 'oauth_session')).toBe(0);
    } finally {
      Date.now = originalNow;
      delete (crypto.subtle as { sign?: unknown }).sign;
    }
  });

  it('allows one concurrent code exchange and commits exactly one session', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await codeFixture(env);
    const proofs = await Promise.all([signed(fixture.key), signed(fixture.key)]);
    const results = await Promise.all(proofs.map((proof) => post(env, fixture.form(), proof.jwt)));
    expect(results.map((result) => result.status).sort()).toEqual([200, 400]);
    expect(await count(env, 'oauth_session')).toBe(1);
    expect(await count(env, 'refresh_token')).toBe(1);
  });

  it('rejects an expired or revoked snapshot immediately before rotation', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await refreshFixture(env);
    const proof = await signed(fixture.key);
    const wrapped = wrapBatch(env, async (statements, database) => {
      await env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = ? WHERE id = ?')
        .bind(Math.floor(Date.now() / 1000), fixture.id).run();
      return database.batch(statements);
    });
    expect((await post(wrapped, fixture.form(), proof.jwt)).status).toBe(400);
    expect((await getOAuthSession(env, fixture.id))?.revokedAt).not.toBeNull();
    expect(await getSecret(env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
    expect(await count(env, 'refresh_token')).toBe(1);
  });

  it('rechecks session and signed-token expiry on the final D1 clock', async () => {
    for (const expiring of ['session', 'signed-token'] as const) {
      const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
      const fixture = await refreshFixture(env);
      const now = Math.floor(Date.now() / 1000);
      const expires = now + 30;
      let token = fixture.tokens.refreshJwt;
      if (expiring === 'session') {
        await env.ALTERAN_DB.prepare('UPDATE oauth_session SET expires_at = ? WHERE id = ?').bind(expires, fixture.id).run();
      } else {
        token = await new SignJWT({ scope: 'com.atproto.refresh', jti: fixture.tokens.refreshPayload.jti,
          client_id: CLIENT, oauth_session: fixture.id, cnf: { jkt: fixture.key.jkt } })
          .setProtectedHeader({ alg: 'HS256', typ: 'refresh+jwt' }).setSubject(DID).setAudience(DID)
          .setIssuedAt(now).setExpirationTime(expires).sign(new TextEncoder().encode(SECRET));
      }
      await env.ALTERAN_DB.prepare(`CREATE TRIGGER expire_refresh_after_proof AFTER INSERT ON secret
        WHEN NEW.key GLOB 'oauth:dpop:jti:authz:*' BEGIN
          UPDATE oauth_replay_clock SET seconds = MAX(seconds, ${expires}) WHERE id = 1;
        END`).run();
      const proof = await signed(fixture.key);
      expect((await post(env, fixture.form(token), proof.jwt)).status).toBe(400);
      expect((await getOAuthSession(env, fixture.id))?.currentRefreshTokenId).toBe(fixture.tokens.refreshPayload.jti);
      expect(await getSecret(env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
      expect(await count(env, 'refresh_token')).toBe(1);
    }
  });

  it('does not rotate when a signed refresh token expires on the Worker during signing', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await refreshFixture(env);
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    const token = await new SignJWT({ scope: 'com.atproto.refresh', jti: fixture.tokens.refreshPayload.jti,
      client_id: CLIENT, oauth_session: fixture.id, cnf: { jkt: fixture.key.jkt } })
      .setProtectedHeader({ alg: 'HS256', typ: 'refresh+jwt' }).setSubject(DID).setAudience(DID)
      .setIssuedAt(now).setExpirationTime(now + 5).sign(new TextEncoder().encode(SECRET));
    const proof = await signed(fixture.key);
    const originalSign = crypto.subtle.sign.bind(crypto.subtle);
    let signatures = 0;
    Object.defineProperty(crypto.subtle, 'sign', { configurable: true, value: async (...args: Parameters<SubtleCrypto['sign']>) => {
      const result = await originalSign(...args);
      if (++signatures === 1) Date.now = () => (now + 10) * 1000;
      return result;
    } });
    try {
      Date.now = () => now * 1000;
      expect((await post(env, fixture.form(token), proof.jwt)).status).toBe(400);
      expect(signatures).toBeGreaterThan(0);
      expect((await getOAuthSession(env, fixture.id))?.revokedAt).toBeNull();
      expect(await getSecret(env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
      expect(await count(env, 'refresh_token')).toBe(1);
    } finally {
      Date.now = originalNow;
      delete (crypto.subtle as { sign?: unknown }).sign;
    }
  });

  it('rolls back post-proof session changes and skipped refresh writes', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await refreshFixture(env);
    const proof = await signed(fixture.key);
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER alter_session_after_proof AFTER INSERT ON secret
      WHEN NEW.key GLOB 'oauth:dpop:jti:authz:*' BEGIN
        UPDATE oauth_session SET scope = 'altered';
      END`).run();
    expect((await post(env, fixture.form(), proof.jwt)).status).toBe(400);
    expect((await getOAuthSession(env, fixture.id))?.scope).toBe('atproto');
    expect(await getSecret(env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
    await env.ALTERAN_DB.prepare('DROP TRIGGER alter_session_after_proof').run();
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER skip_refresh_rotation BEFORE UPDATE OF next_id ON refresh_token
      BEGIN SELECT RAISE(IGNORE); END`).run();
    expect((await post(env, fixture.form(), proof.jwt)).status).toBe(400);
    expect(await count(env, 'refresh_token')).toBe(1);
    expect(await getSecret(env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
    await env.ALTERAN_DB.prepare('DROP TRIGGER skip_refresh_rotation').run();
    expect((await post(env, fixture.form(), proof.jwt)).status).toBe(200);
  });

  it('does not revoke or spend a proof on a database failure', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await refreshFixture(env);
    const proof = await signed(fixture.key);
    const broken = wrapBatch(env, () => Promise.reject(new Error('simulated database fault')));
    expect((await post(broken, fixture.form(), proof.jwt)).status).toBe(400);
    expect((await getOAuthSession(env, fixture.id))?.revokedAt).toBeNull();
    expect(await getSecret(env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
    expect((await post(env, fixture.form(), proof.jwt)).status).toBe(200);
  });

  it('bounds a streaming form without relying on Content-Length', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await codeFixture(env);
    const proof = await signed(fixture.key);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(600_000));
        controller.enqueue(new Uint8Array(600_000));
        controller.close();
      },
    });
    const request = new Request(URL, { method: 'POST', headers: { DPoP: proof.jwt }, body: stream, duplex: 'half' } as RequestInit);
    expect((await POST({ locals: { env }, request } as unknown as APIContext)).status).toBe(400);
    expect(await loadCodeSnapshot(env, fixture.code)).not.toBeNull();
    expect(await getSecret(env, `oauth:dpop:jti:authz:${proof.jti}`)).toBeNull();
  });

  it('accepts fragmented forms and caps streams of empty chunks', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await codeFixture(env);
    const proof = await signed(fixture.key);
    const bytes = new TextEncoder().encode(fixture.form().toString());
    let offset = 0;
    const fragmented = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (offset === bytes.length) controller.close();
        else controller.enqueue(bytes.slice(offset, ++offset));
      },
    });
    const request = new Request(URL, { method: 'POST', headers: { DPoP: proof.jwt }, body: fragmented, duplex: 'half' } as RequestInit);
    expect((await POST({ locals: { env }, request } as unknown as APIContext)).status).toBe(200);

    const next = await codeFixture(env);
    const nextProof = await signed(next.key);
    let canceled = false;
    const empty = new ReadableStream<Uint8Array>({
      pull(controller) { controller.enqueue(new Uint8Array(0)); },
      cancel() { canceled = true; },
    });
    const repeated = new Request(URL, { method: 'POST', headers: { DPoP: nextProof.jwt }, body: empty, duplex: 'half' } as RequestInit);
    expect((await POST({ locals: { env }, request: repeated } as unknown as APIContext)).status).toBe(400);
    expect(canceled).toBe(true);
    expect(await loadCodeSnapshot(env, next.code)).not.toBeNull();
    expect(await getSecret(env, `oauth:dpop:jti:authz:${nextProof.jti}`)).toBeNull();
  });

  it('rejects mismatched signed refresh claims without revoking', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await refreshFixture(env);
    const now = Math.floor(Date.now() / 1000);
    const original = { scope: 'com.atproto.refresh', jti: fixture.tokens.refreshPayload.jti, client_id: CLIENT,
      oauth_session: fixture.id, cnf: { jkt: fixture.key.jkt } };
    for (const changes of [{ client_id: 'https://other.example' }, { oauth_session: 'other-session' },
      { cnf: { jkt: 'other-key' } }, { jti: 'other-token' }]) {
      const jwt = await new SignJWT({ ...original, ...changes }).setProtectedHeader({ alg: 'HS256', typ: 'refresh+jwt' })
        .setSubject(DID).setAudience(DID).setIssuedAt(now).setExpirationTime(now + 600).sign(new TextEncoder().encode(SECRET));
      expect((await post(env, fixture.form(jwt), (await signed(fixture.key)).jwt)).status).toBe(400);
      expect((await getOAuthSession(env, fixture.id))?.revokedAt).toBeNull();
    }
    expect((await post(env, fixture.form(), (await signed(fixture.key)).jwt)).status).toBe(200);
  });

  it('rejects a stale concurrent refresh snapshot without revoking the winner', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await refreshFixture(env);
    let arrivals = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const wrapped = wrapBatch(env, async (statements, database) => {
      if (++arrivals === 2) release();
      await gate;
      return database.batch(statements);
    });
    const proofs = await Promise.all([signed(fixture.key), signed(fixture.key)]);
    const results = await Promise.all(proofs.map((proof) => post(wrapped, fixture.form(), proof.jwt)));
    expect(results.map((result) => result.status).sort()).toEqual([200, 400]);
    expect((await getOAuthSession(env, fixture.id))?.revokedAt).toBeNull();
    expect(await count(env, 'refresh_token')).toBe(2);
  });

  it('documents lost-commit responses and authenticated retry revocation', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await refreshFixture(env);
    const wrapped = wrapBatch(env, async (statements, database) => {
      await database.batch(statements);
      throw new Error('response lost after commit');
    });
    expect((await post(wrapped, fixture.form(), (await signed(fixture.key)).jwt)).status).toBe(401);
    const rotated = await getOAuthSession(env, fixture.id);
    expect(rotated?.revokedAt).toBeNull();
    expect(rotated?.currentRefreshTokenId).not.toBe(fixture.tokens.refreshPayload.jti);
    expect((await post(env, fixture.form(), (await signed(fixture.key)).jwt)).status).toBe(400);
    expect((await getOAuthSession(env, fixture.id))?.revokedAt).not.toBeNull();
  });

  it('withholds a rotated token response when the proof expires during the D1 batch', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await refreshFixture(env);
    const proof = await signed(fixture.key);
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    const delayed = wrapBatch(env, async (statements, database) => {
      const result = await database.batch(statements);
      Date.now = () => (now + 301) * 1000;
      return result;
    });
    try {
      Date.now = () => now * 1000;
      expect((await post(delayed, fixture.form(), proof.jwt)).status).toBe(401);
      const rotated = await getOAuthSession(env, fixture.id);
      expect(rotated?.revokedAt).toBeNull();
      expect(rotated?.currentRefreshTokenId).not.toBe(fixture.tokens.refreshPayload.jti);
    } finally {
      Date.now = originalNow;
    }
  });

  it('does not reissue tokens after a lost authorization-code response', async () => {
    const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
    const fixture = await codeFixture(env);
    const wrapped = wrapBatch(env, async (statements, database) => {
      await database.batch(statements);
      throw new Error('response lost after commit');
    });
    expect((await post(wrapped, fixture.form(), (await signed(fixture.key)).jwt)).status).toBe(401);
    expect((await post(env, fixture.form(), (await signed(fixture.key)).jwt)).status).toBe(400);
    expect(await count(env, 'oauth_session')).toBe(1);
    expect(await count(env, 'refresh_token')).toBe(1);
  });
});
