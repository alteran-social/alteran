import type { APIContext } from 'astro';
import { expect } from '@std/expect';
import { SignJWT } from 'jose';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { makeDpopKey, signDpopProof } from './helpers/oauth';
import { createOAuthSession, getOAuthSession } from './helpers/oauth-store';
import { getSecret, storeRefreshToken } from '../src/db/account';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { verifyDpop } from '../src/lib/oauth/dpop';
import { POST as revokePost } from '../src/pages/oauth/revoke';
import { POST as tokenPost } from '../src/pages/oauth/token';
import type { Env } from '../src/env';

const DID = 'did:example:test';
const CLIENT = 'https://client.example/metadata';
const SECRET = 'oauth-revocation-fence-test-secret';
const TOKEN_URL = 'https://pds.example/oauth/token';
const REVOKE_URL = 'https://pds.example/oauth/revoke';

async function fixture() {
  const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
  const key = await makeDpopKey();
  const session = crypto.randomUUID();
  const accessJti = crypto.randomUUID();
  const tokens = await issueSessionTokens(env, DID, { accessScope: 'atproto', clientId: CLIENT,
    dpopJkt: key.jkt, oauthSessionId: session, accessJti });
  await createOAuthSession(env, { id: session, did: DID, clientId: CLIENT, clientAuthMethod: 'none', dpopJkt: key.jkt,
    scope: 'atproto', currentRefreshTokenId: tokens.refreshPayload.jti, accessJti, expiresAt: tokens.refreshExpiry });
  await storeRefreshToken(env, { id: tokens.refreshPayload.jti, did: DID, expiresAt: tokens.refreshExpiry,
    tokenKind: 'oauth', oauthSessionId: session, clientId: CLIENT, clientAuthMethod: 'none', dpopJkt: key.jkt,
    oauthScope: 'atproto', accessJti });
  async function rotate() {
    const proof = await signDpopProof({ key, method: 'POST', url: TOKEN_URL });
    const request = new Request(TOKEN_URL, { method: 'POST', headers: { DPoP: proof },
      body: new URLSearchParams({ grant_type: 'refresh_token', client_id: CLIENT, refresh_token: tokens.refreshJwt }) });
    return tokenPost({ locals: { env }, request } as unknown as APIContext);
  }
  async function revoke(token: string, requestEnv: Env = env, jti = crypto.randomUUID()) {
    const proof = await signDpopProof({ key, method: 'POST', url: REVOKE_URL, jti });
    const request = new Request(REVOKE_URL, { method: 'POST', headers: { DPoP: proof },
      body: new URLSearchParams({ token, client_id: CLIENT }) });
    return revokePost({ locals: { env: requestEnv }, request } as unknown as APIContext);
  }
  return { env, key, session, accessJti, tokens, rotate, revoke };
}

describe('OAuth revocation session fence', () => {
  it('does not let a superseded access token revoke the rotated session', async () => {
    const f = await fixture();
    const rotation = await f.rotate();
    expect(rotation.status).toBe(200);
    const current = await rotation.json() as { access_token: string };
    expect((await f.revoke(f.tokens.accessJwt)).status).toBe(200);
    expect((await getOAuthSession(f.env, f.session))?.revokedAt).toBeNull();
    expect((await f.revoke(current.access_token)).status).toBe(200);
    expect((await getOAuthSession(f.env, f.session))?.revokedAt).not.toBeNull();
  });

  it('permits an authenticated older refresh token to revoke its grant', async () => {
    const f = await fixture();
    expect((await f.rotate()).status).toBe(200);
    expect((await f.revoke(f.tokens.refreshJwt)).status).toBe(200);
    expect((await getOAuthSession(f.env, f.session))?.revokedAt).not.toBeNull();
  });

  it('does not revoke on mismatched signed subject, client, key or scope', async () => {
    const f = await fixture();
    const now = Math.floor(Date.now() / 1000);
    const base = { scope: 'atproto', client_id: CLIENT, oauth_session: f.session, cnf: { jkt: f.key.jkt }, jti: f.accessJti };
    for (const changes of [{ client_id: 'https://other.example' }, { cnf: { jkt: 'other' } },
      { scope: 'atproto transition:generic' }, { jti: 'other-token' }, { subject: 'did:example:other' }]) {
      const { subject, ...claims } = changes as { subject?: string } & Record<string, unknown>;
      const token = await new SignJWT({ ...base, ...claims }).setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
        .setSubject(subject ?? DID).setAudience(DID).setIssuedAt(now).setExpirationTime(now + 600)
        .sign(new TextEncoder().encode(SECRET));
      expect((await f.revoke(token)).status).toBe(200);
      expect((await getOAuthSession(f.env, f.session))?.revokedAt).toBeNull();
    }
    const refreshBase = { scope: 'com.atproto.refresh', client_id: CLIENT, oauth_session: f.session,
      cnf: { jkt: f.key.jkt }, jti: f.tokens.refreshPayload.jti };
    for (const changes of [{ client_id: 'https://other.example' }, { cnf: { jkt: 'other' } },
      { oauth_session: 'other-session' }, { subject: 'did:example:other' }]) {
      const { subject, ...claims } = changes as { subject?: string } & Record<string, unknown>;
      const token = await new SignJWT({ ...refreshBase, ...claims }).setProtectedHeader({ alg: 'HS256', typ: 'refresh+jwt' })
        .setSubject(subject ?? DID).setAudience(DID).setIssuedAt(now).setExpirationTime(now + 600)
        .sign(new TextEncoder().encode(SECRET));
      expect((await f.revoke(token)).status).toBe(200);
      expect((await getOAuthSession(f.env, f.session))?.revokedAt).toBeNull();
    }
  });

  it('does not revoke a session rotated after the revocation snapshot was read', async () => {
    const f = await fixture();
    const database = f.env.ALTERAN_DB;
    let rotated = false;
    const wrapped = { ...f.env, ALTERAN_DB: new Proxy(database, {
      get(target, property) {
        if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
          if (!rotated) {
            rotated = true;
            expect((await f.rotate()).status).toBe(200);
          }
          return database.batch(statements);
        };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }) };
    const jti = crypto.randomUUID();
    expect((await f.revoke(f.tokens.accessJwt, wrapped, jti)).status).toBe(200);
    expect(rotated).toBe(true);
    expect((await getOAuthSession(f.env, f.session))?.revokedAt).toBeNull();
    expect(await getSecret(f.env, `oauth:dpop:jti:authz:${jti}`)).toBeNull();
  });

  it('does not revoke when the presented older refresh row disappears before the batch', async () => {
    const f = await fixture();
    expect((await f.rotate()).status).toBe(200);
    const database = f.env.ALTERAN_DB;
    const wrapped = { ...f.env, ALTERAN_DB: new Proxy(database, { get(target, property) {
      if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
        await database.prepare('DELETE FROM refresh_token WHERE id = ?').bind(f.tokens.refreshPayload.jti).run();
        return database.batch(statements);
      };
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } }) };
    const jti = crypto.randomUUID();
    expect((await f.revoke(f.tokens.refreshJwt, wrapped, jti)).status).toBe(200);
    expect((await getOAuthSession(f.env, f.session))?.revokedAt).toBeNull();
    expect(await getSecret(f.env, `oauth:dpop:jti:authz:${jti}`)).toBeNull();
  });

  it('reports an error when the current refresh row is missing or its revocation is skipped', async () => {
    const missing = await fixture();
    await missing.env.ALTERAN_DB.prepare('DELETE FROM refresh_token WHERE id = ?')
      .bind(missing.tokens.refreshPayload.jti).run();
    expect((await missing.revoke(missing.tokens.accessJwt)).status).toBe(400);
    expect((await getOAuthSession(missing.env, missing.session))?.revokedAt).toBeNull();

    const skipped = await fixture();
    const jti = crypto.randomUUID();
    await skipped.env.ALTERAN_DB.prepare(`CREATE TRIGGER skip_current_refresh_revoke BEFORE UPDATE OF revoked_at ON refresh_token
      BEGIN SELECT RAISE(IGNORE); END`).run();
    expect((await skipped.revoke(skipped.tokens.accessJwt, skipped.env, jti)).status).toBe(400);
    expect((await getOAuthSession(skipped.env, skipped.session))?.revokedAt).toBeNull();
    expect(await getSecret(skipped.env, `oauth:dpop:jti:authz:${jti}`)).toBeNull();
  });

  it('does not revoke on a replayed proof or database failure', async () => {
    const f = await fixture();
    const jti = crypto.randomUUID();
    const proof = await signDpopProof({ key: f.key, method: 'POST', url: REVOKE_URL, jti });
    await verifyDpop(f.env, new Request(REVOKE_URL, { method: 'POST', headers: { DPoP: proof } }), { requireNonce: false });
    const request = new Request(REVOKE_URL, { method: 'POST', headers: { DPoP: proof },
      body: new URLSearchParams({ token: f.tokens.accessJwt, client_id: CLIENT }) });
    expect((await revokePost({ locals: { env: f.env }, request } as unknown as APIContext)).status).toBe(401);
    expect((await getOAuthSession(f.env, f.session))?.revokedAt).toBeNull();
    const failedJti = crypto.randomUUID();
    const database = f.env.ALTERAN_DB;
    const broken = { ...f.env, ALTERAN_DB: new Proxy(database, { get(target, property) {
      if (property === 'batch') return () => Promise.reject(new Error('simulated D1 fault'));
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } }) };
    expect((await f.revoke(f.tokens.accessJwt, broken, failedJti)).status).toBe(400);
    expect((await getOAuthSession(f.env, f.session))?.revokedAt).toBeNull();
    expect(await getSecret(f.env, `oauth:dpop:jti:authz:${failedJti}`)).toBeNull();
  });

  it('rolls back the proof and revocation if session state changes during the batch', async () => {
    const f = await fixture();
    const jti = crypto.randomUUID();
    await f.env.ALTERAN_DB.prepare(`CREATE TRIGGER rewrite_session_during_revoke AFTER INSERT ON secret
      WHEN NEW.key GLOB 'oauth:dpop:jti:authz:*' BEGIN UPDATE oauth_session SET scope = 'altered'; END`).run();
    expect((await f.revoke(f.tokens.accessJwt, f.env, jti)).status).toBe(400);
    const session = await getOAuthSession(f.env, f.session);
    expect(session?.scope).toBe('atproto');
    expect(session?.revokedAt).toBeNull();
    expect(await getSecret(f.env, `oauth:dpop:jti:authz:${jti}`)).toBeNull();
  });

  it('rolls back when the proof expires on the final D1 clock', async () => {
    const f = await fixture();
    const now = Math.floor(Date.now() / 1000);
    const jti = crypto.randomUUID();
    await f.env.ALTERAN_DB.prepare(`CREATE TRIGGER expire_revoke_proof AFTER INSERT ON secret
      WHEN NEW.key GLOB 'oauth:dpop:jti:authz:*' BEGIN
        UPDATE oauth_replay_clock SET seconds = MAX(seconds, ${now + 301}) WHERE id = 1;
      END`).run();
    expect((await f.revoke(f.tokens.accessJwt, f.env, jti)).status).toBe(400);
    expect((await getOAuthSession(f.env, f.session))?.revokedAt).toBeNull();
    expect(await getSecret(f.env, `oauth:dpop:jti:authz:${jti}`)).toBeNull();
  });

  it('does not revoke when a verified proof expires on the Worker before the batch', async () => {
    const f = await fixture();
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    const jti = crypto.randomUUID();
    const proof = await new SignJWT({ htm: 'POST', htu: REVOKE_URL, iat: now - 290, jti })
      .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: f.key.jwk }).sign(f.key.privateKey);
    const body = new URLSearchParams({ token: f.tokens.accessJwt, client_id: CLIENT }).toString();
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    const stream = new ReadableStream<Uint8Array>({ start(value) { controller = value; } });
    const request = new Request(REVOKE_URL, { method: 'POST', headers: { DPoP: proof }, body: stream, duplex: 'half' } as RequestInit);
    let signalReading!: () => void;
    const reading = new Promise<void>((resolve) => { signalReading = resolve; });
    const originalBody = request.body;
    Object.defineProperty(request, 'body', { get() { signalReading(); return originalBody; } });
    try {
      Date.now = () => now * 1000;
      const pending = revokePost({ locals: { env: f.env }, request } as unknown as APIContext);
      await reading;
      Date.now = () => (now + 11) * 1000;
      controller.enqueue(new TextEncoder().encode(body));
      controller.close();
      expect((await pending).status).toBe(401);
      expect((await getOAuthSession(f.env, f.session))?.revokedAt).toBeNull();
      expect(await getSecret(f.env, `oauth:dpop:jti:authz:${jti}`)).toBeNull();
    } finally {
      Date.now = originalNow;
    }
  });

  it('treats a lost committed revocation response as idempotently revoked', async () => {
    const f = await fixture();
    const database = f.env.ALTERAN_DB;
    const delayed = { ...f.env, ALTERAN_DB: new Proxy(database, { get(target, property) {
      if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
        await database.batch(statements);
        throw new Error('lost revocation response');
      };
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } }) };
    expect((await f.revoke(f.tokens.accessJwt, delayed)).status).toBe(200);
    expect((await getOAuthSession(f.env, f.session))?.revokedAt).not.toBeNull();
    expect((await f.revoke(f.tokens.accessJwt)).status).toBe(200);
  });
});
