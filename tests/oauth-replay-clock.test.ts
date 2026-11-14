import { expect } from '@std/expect';
import { SignJWT, type JWK } from 'jose';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { makeDpopKey } from './helpers/oauth';
import { advanceReplayClock, afterReplayBatch } from './helpers/oauth-clock';
import { getSecret } from '../src/db/account';
import { cleanupExpiredOAuthReplaySecrets, consumeOAuthReplay } from '../src/db/oauth-replay';
import { verifyDpop } from '../src/lib/oauth/dpop';
import { cleanupExpiredTokens } from '../src/lib/token-cleanup';

const URL = 'https://pds.example/oauth/token';

describe('OAuth replay clock', () => {
  it('does not let differently clocked Workers delete and reuse a valid proof', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    const jti = crypto.randomUUID();
    const proof = await new SignJWT({ htm: 'POST', htu: URL, iat: now - 280, jti })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk as JWK })
      .sign(key.privateKey);
    const request = () => new Request(URL, { method: 'POST', headers: { dpop: proof } });
    try {
      Date.now = () => now * 1000;
      await verifyDpop(env, request(), { requireNonce: false });
      Date.now = () => (now + 21) * 1000;
      await cleanupExpiredTokens(env);
      Date.now = () => (now + 20) * 1000;
      await expect(verifyDpop(env, request(), { requireNonce: false })).rejects
        .toThrow('DPoP proof replayed');

      await advanceReplayClock(env, now + 21);
      await expect(verifyDpop(env, request(), { requireNonce: false })).rejects
        .toThrow('DPoP proof expired');
      expect(await getSecret(env, `oauth:dpop:jti:authz:${jti}`)).toBeNull();
    } finally {
      Date.now = originalNow;
    }
  });

  it('allows one concurrent claimant for a proof', async () => {
    const env = await makeEnv();
    const issuedAt = Math.floor(Date.now() / 1000);
    const key = `oauth:dpop:jti:authz:${crypto.randomUUID()}`;
    const results = await Promise.all(Array.from({ length: 12 }, () =>
      consumeOAuthReplay(env, key, { tag: 'dpop', issuedAt })
    ));
    expect(results.filter((result) => result.tag === 'accepted')).toHaveLength(1);
    expect(results.filter((result) => result.tag === 'replayed')).toHaveLength(11);
  });

  it('cannot reset, replace, delete, or move the clock backwards', async () => {
    const env = await makeEnv();
    const row = await env.ALTERAN_DB.prepare('SELECT seconds FROM oauth_replay_clock WHERE id = 1')
      .first<{ seconds: number }>();
    if (!row) throw new Error('Missing replay clock');
    await expect(env.ALTERAN_DB.prepare('DELETE FROM oauth_replay_clock WHERE id = 1').run()).rejects.toThrow();
    await expect(env.ALTERAN_DB.prepare('INSERT OR REPLACE INTO oauth_replay_clock (id, seconds, nonce) VALUES (1, ?, ?)')
      .bind(row.seconds, '0'.repeat(32)).run()).rejects.toThrow();
    await expect(advanceReplayClock(env, row.seconds - 1)).rejects.toThrow();
  });

  it('rejects admission when the clock is missing or corrupt', async () => {
    const env = await makeEnv();
    await env.ALTERAN_DB.exec('DROP TRIGGER oauth_replay_clock_no_delete');
    await env.ALTERAN_DB.exec('DELETE FROM oauth_replay_clock');
    const key = `oauth:dpop:jti:authz:${crypto.randomUUID()}`;
    await expect(consumeOAuthReplay(env, key, { tag: 'dpop', issuedAt: Math.floor(Date.now() / 1000) }))
      .rejects.toThrow();
    expect(await getSecret(env, key)).toBeNull();

    await env.ALTERAN_DB.exec('DROP TABLE oauth_replay_clock');
    await env.ALTERAN_DB.exec('CREATE TABLE oauth_replay_clock (id INTEGER PRIMARY KEY, seconds TEXT, nonce TEXT)');
    await env.ALTERAN_DB.prepare('INSERT INTO oauth_replay_clock VALUES (1, ?, ?)').bind('corrupt', '0'.repeat(32)).run();
    await expect(consumeOAuthReplay(env, key, { tag: 'dpop', issuedAt: Math.floor(Date.now() / 1000) }))
      .rejects.toThrow();
    expect(await getSecret(env, key)).toBeNull();
  });

  it('fails closed if a clock update or its final refresh is skipped', async () => {
    const env = await makeEnv();
    const issuedAt = Math.floor(Date.now() / 1000);
    const key = `oauth:dpop:jti:authz:${crypto.randomUUID()}`;
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER test_clock_skip BEFORE UPDATE ON oauth_replay_clock
      BEGIN SELECT RAISE(IGNORE); END`).run();
    await expect(consumeOAuthReplay(env, key, { tag: 'dpop', issuedAt })).rejects.toThrow();
    expect(await getSecret(env, key)).toBeNull();
    await env.ALTERAN_DB.exec('DROP TRIGGER test_clock_skip');
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER test_final_clock_skip BEFORE UPDATE ON oauth_replay_clock
      WHEN OLD.nonce = NEW.nonce BEGIN SELECT RAISE(IGNORE); END`).run();
    await expect(consumeOAuthReplay(env, key, { tag: 'dpop', issuedAt })).rejects.toThrow();
    expect(await getSecret(env, key)).toBeNull();
  });

  it('does not authorize skipped or removed replay markers', async () => {
    const env = await makeEnv();
    const issuedAt = Math.floor(Date.now() / 1000);
    const skipped = `oauth:dpop:jti:authz:${crypto.randomUUID()}`;
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER test_marker_skip BEFORE INSERT ON secret
      WHEN NEW.key LIKE 'oauth:dpop:jti:%' BEGIN SELECT RAISE(IGNORE); END`).run();
    expect((await consumeOAuthReplay(env, skipped, { tag: 'dpop', issuedAt })).tag).not.toBe('accepted');
    expect(await getSecret(env, skipped)).toBeNull();
    await env.ALTERAN_DB.exec('DROP TRIGGER test_marker_skip');
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER test_marker_remove AFTER INSERT ON secret
      WHEN NEW.key LIKE 'oauth:dpop:jti:%' BEGIN DELETE FROM secret WHERE key = NEW.key; END`).run();
    const removed = `oauth:dpop:jti:authz:${crypto.randomUUID()}`;
    await expect(consumeOAuthReplay(env, removed, { tag: 'dpop', issuedAt })).rejects.toThrow();
    expect(await getSecret(env, removed)).toBeNull();
  });

  it('does not authorize an ignored insert even if a trigger creates an identical marker', async () => {
    const env = await makeEnv();
    const issuedAt = Math.floor(Date.now() / 1000);
    const key = `oauth:dpop:jti:authz:${crypto.randomUUID()}`;
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER test_marker_side_effect BEFORE INSERT ON secret
      WHEN NEW.key LIKE 'oauth:dpop:jti:%' BEGIN
        INSERT OR IGNORE INTO secret (key, value, updated_at) VALUES (NEW.key, NEW.value, NEW.updated_at);
        SELECT RAISE(IGNORE);
      END`).run();
    expect((await consumeOAuthReplay(env, key, { tag: 'dpop', issuedAt })).tag).not.toBe('accepted');
    expect(await getSecret(env, key)).not.toBeNull();
  });

  it('denies a proof that expires during the transaction', async () => {
    const env = await makeEnv();
    const issuedAt = Math.floor(Date.now() / 1000);
    const key = `oauth:dpop:jti:authz:${crypto.randomUUID()}`;
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER test_advance_clock AFTER INSERT ON secret
      WHEN NEW.key LIKE 'oauth:dpop:jti:%' BEGIN
        UPDATE oauth_replay_clock SET seconds = seconds + 400 WHERE id = 1;
      END`).run();
    expect(await consumeOAuthReplay(env, key, { tag: 'dpop', issuedAt })).toEqual({ tag: 'expired' });
    await env.ALTERAN_DB.exec('DROP TRIGGER test_advance_clock');
    expect(await consumeOAuthReplay(env, key, { tag: 'dpop', issuedAt })).toEqual({ tag: 'expired' });
  });

  it('denies a client assertion that expires during the transaction', async () => {
    const env = await makeEnv();
    const issuedAt = Math.floor(Date.now() / 1000);
    const key = `oauth:client-assertion:jti:client:${crypto.randomUUID()}`;
    await env.ALTERAN_DB.prepare(`CREATE TRIGGER test_advance_assertion_clock AFTER INSERT ON secret
      WHEN NEW.key LIKE 'oauth:client-assertion:jti:%' BEGIN
        UPDATE oauth_replay_clock SET seconds = seconds + 60 WHERE id = 1;
      END`).run();
    expect(await consumeOAuthReplay(env, key, {
      tag: 'assertion', issuedAt, expiresAt: issuedAt + 30,
    })).toEqual({ tag: 'expired' });
  });

  it('does not infer success when a committed D1 response is lost', async () => {
    const env = await makeEnv();
    const issuedAt = Math.floor(Date.now() / 1000);
    const key = `oauth:dpop:jti:authz:${crypto.randomUUID()}`;
    const disconnected = afterReplayBatch(env, () => { throw new Error('response lost'); });
    await expect(consumeOAuthReplay(disconnected, key, { tag: 'dpop', issuedAt })).rejects.toThrow('response lost');
    expect(await consumeOAuthReplay(env, key, { tag: 'dpop', issuedAt })).toEqual({ tag: 'replayed' });
  });
});
