import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { authorizedReadFixture, interceptRead, COLLECTION, DID, OTHER_COLLECTION, SPACE } from './helpers/spaces-authorized-read';
import { readAuthorizedSpaceRecord } from '../src/db/space-authorized-record';
import { beginPersonalSpaceDeletion } from './helpers/space-storage';
import { createAccount } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import type { VerifiedSpacePrincipal } from '../src/lib/oauth/space-principal';

const target = { space: SPACE, repo: DID, collection: COLLECTION, rkey: 'one' };
type Fixture = Awaited<ReturnType<typeof authorizedReadFixture>>;
type ReadEnv = Fixture['env'];

async function read(f: Fixture, params = target, env: ReadEnv = f.env) {
  const { principal, request } = await f.principal(params, env);
  return readAuthorizedSpaceRecord(env, principal, request, params.space, params.repo, params.collection, params.rkey);
}

describe('private Space record authorization', () => {
  it('requires a fresh single-use principal and applies the Space and repo bounds', async () => {
    const f = await authorizedReadFixture();
    const first = await f.principal();
    expect((await readAuthorizedSpaceRecord(f.env, first.principal, first.request, SPACE, DID, COLLECTION, 'one')).tag).toBe('found');
    expect((await readAuthorizedSpaceRecord(f.env, first.principal, first.request, SPACE, DID, COLLECTION, 'one')).tag).toBe('unauthorized');
    const forged = await f.principal();
    expect((await readAuthorizedSpaceRecord(f.env, { ...forged.principal } as VerifiedSpacePrincipal,
      forged.request, SPACE, DID, COLLECTION, 'one')).tag).toBe('unauthorized');
    expect((await read(f, { ...target, collection: OTHER_COLLECTION, rkey: 'two' })).tag).toBe('found');
    expect((await read(f, { ...target, rkey: 'missing' })).tag).toBe('notFound');
    expect((await read(f, { ...target, repo: 'did:example:other' })).tag).toBe('unauthorized');
    expect((await read(f, { ...target, space: `${SPACE}x` })).tag).toBe('unauthorized');
    expect((await read(f, { ...target, space: `at://${DID}/space/com.example.other/read-record` })).tag).toBe('unauthorized');
  });

  it('binds the principal to the exact request, database and query parameters', async () => {
    const f = await authorizedReadFixture();
    const a = await f.principal();
    expect((await readAuthorizedSpaceRecord(f.env, a.principal, a.request.clone(), SPACE, DID, COLLECTION, 'one')).tag).toBe('unauthorized');
    expect((await readAuthorizedSpaceRecord(f.env, a.principal, a.request, SPACE, DID, COLLECTION, 'one')).tag).toBe('unauthorized');
    const b = await f.principal();
    const other = interceptRead(f.env);
    expect((await readAuthorizedSpaceRecord(other.env, b.principal, b.request, SPACE, DID, COLLECTION, 'one')).tag).toBe('unauthorized');
    const c = await f.principal();
    expect((await readAuthorizedSpaceRecord(f.env, c.principal, c.request, SPACE, DID, COLLECTION, 'missing')).tag).toBe('unauthorized');
    const d = await f.principal(target, f.env, undefined, '&rkey=two');
    expect((await readAuthorizedSpaceRecord(f.env, d.principal, d.request, SPACE, DID, COLLECTION, 'one')).tag).toBe('unauthorized');
  });

  it('projects no private row when revocation, rotation, account state or grant changes before the read', async () => {
    for (const change of ['revoke', 'rotate', 'deactivate', 'account', 'recreate', 'grant'] as const) {
      const f = await authorizedReadFixture();
      const watched = interceptRead(f.env, { before: async () => {
        if (change === 'revoke') await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
        if (change === 'rotate') await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET access_jti = ? WHERE id = ?').bind('new-token', f.sessionId).run();
        if (change === 'deactivate') await setAccountState(f.env, DID, { tag: 'deactivated' });
        if (change === 'account') await f.env.ALTERAN_DB.prepare('DELETE FROM account WHERE did = ?').bind(DID).run();
        if (change === 'recreate') {
          await f.env.ALTERAN_DB.prepare('DELETE FROM account WHERE did = ?').bind(DID).run();
          await f.env.ALTERAN_DB.prepare('DELETE FROM account_state WHERE did = ?').bind(DID).run();
          await createAccount(f.env, { did: DID, handle: 'test.example', passwordScrypt: null });
          await setAccountState(f.env, DID, { tag: 'active' });
        }
        if (change === 'grant') {
          await f.env.ALTERAN_DB.exec('DROP TRIGGER oauth_space_grant_update');
          await f.env.ALTERAN_DB.prepare("UPDATE oauth_space_grant SET snapshot = '{}' WHERE session_id = ?").bind(f.sessionId).run();
        }
      } });
      const { principal, request } = await f.principal(target, watched.env);
      watched.arm();
      expect((await readAuthorizedSpaceRecord(watched.env, principal, request, SPACE, DID, COLLECTION, 'one')).tag).toBe('unauthorized');
      expect(watched.returned()).toEqual([]);
    }
  });

  it('does not project a record after a personal Space is tombstoned', async () => {
    const f = await authorizedReadFixture();
    const watched = interceptRead(f.env, { before: async () => {
      expect((await beginPersonalSpaceDeletion(f.env, SPACE, crypto.randomUUID())).tag).toBe('started');
    } });
    const { principal, request } = await f.principal(target, watched.env);
    watched.arm();
    const result = await readAuthorizedSpaceRecord(watched.env, principal, request, SPACE, DID, COLLECTION, 'one');
    expect(result.tag).toBe('notFound');
    if (result.tag !== 'notFound') throw new Error('Expected bounded absence');
    expect(await result.complete(request, watched.env.ALTERAN_DB)).toBe(false);
    const rows = watched.returned() as { sentinel: number; value_cbor: unknown }[];
    expect(rows).toHaveLength(1);
    expect(rows[0].sentinel).toBe(1);
    expect(rows[0].value_cbor).toBeNull();
  });

  it('rechecks revocation and Space deletion after the data SELECT in the transaction', async () => {
    for (const change of ['revoke', 'deactivate', 'delete'] as const) {
      const f = await authorizedReadFixture();
      const { principal, request } = await f.principal();
      if (change === 'delete') {
        await f.env.ALTERAN_DB.exec('DROP TRIGGER space_lifecycle_update');
        await f.env.ALTERAN_DB.exec('DROP TRIGGER space_owner_space_update');
      }
      const operation = change === 'revoke'
        ? `UPDATE oauth_session SET revoked_at = 1 WHERE id = '${f.sessionId}';`
        : change === 'deactivate'
        ? `UPDATE account_state SET active = 0 WHERE did = '${DID}';`
        : `UPDATE space SET deleted_at = unixepoch() * 1000 WHERE space_ref = '${SPACE}';`;
      await f.env.ALTERAN_DB.exec(`CREATE TRIGGER test_after_read AFTER UPDATE ON oauth_replay_clock
        WHEN OLD.nonce = NEW.nonce BEGIN ${operation} END`.replaceAll('\n', ' '));
      const result = await readAuthorizedSpaceRecord(f.env, principal, request, SPACE, DID, COLLECTION, 'one');
      expect(result.tag).toBe('unauthorized');
    }
  });

  it('withholds a read when Worker time passes the session expiry during the query', async () => {
    const f = await authorizedReadFixture();
    const expiresAt = Math.floor(Date.now() / 1000) + 60;
    await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET expires_at = ? WHERE id = ?').bind(expiresAt, f.sessionId).run();
    const realNow = Date.now;
    const watched = interceptRead(f.env, { after: () => { Date.now = () => expiresAt * 1000; } });
    const { principal, request } = await f.principal(target, watched.env);
    watched.arm();
    try {
      expect((await readAuthorizedSpaceRecord(watched.env, principal, request, SPACE, DID, COLLECTION, 'one')).tag).toBe('unauthorized');
    } finally {
      Date.now = realNow;
    }
  });

  it('uses the final Worker time for access-token expiry after decoding', async () => {
    const f = await authorizedReadFixture(60);
    const realNow = Date.now;
    let accessExpiry = 0, samples = 0;
    const watched = interceptRead(f.env, { after: () => {
      Date.now = () => ++samples === 1 ? realNow() : accessExpiry * 1000;
    } });
    const { principal, request } = await f.principal(target, watched.env);
    accessExpiry = principal.expiresAt;
    watched.arm();
    try {
      expect((await readAuthorizedSpaceRecord(watched.env, principal, request, SPACE, DID, COLLECTION, 'one')).tag).toBe('unauthorized');
      expect(samples).toBeGreaterThanOrEqual(2);
    } finally {
      Date.now = realNow;
    }
  });

  it('persists a D1 clock advance after selection and cannot revive the expired session', async () => {
    const f = await authorizedReadFixture();
    const expiresAt = Math.floor(Date.now() / 1000) + 60;
    await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET expires_at = ? WHERE id = ?').bind(expiresAt, f.sessionId).run();
    const { principal, request } = await f.principal();
    await f.env.ALTERAN_DB.exec(`CREATE TRIGGER test_forward_clock AFTER UPDATE ON oauth_replay_clock
      WHEN OLD.nonce = NEW.nonce AND NEW.seconds < ${expiresAt} BEGIN
        UPDATE oauth_replay_clock SET seconds = ${expiresAt} WHERE id = 1;
      END`.replaceAll('\n', ' '));
    expect((await readAuthorizedSpaceRecord(f.env, principal, request, SPACE, DID, COLLECTION, 'one')).tag).toBe('unauthorized');
    await f.env.ALTERAN_DB.exec('DROP TRIGGER test_forward_clock');
    const clock = await f.env.ALTERAN_DB.prepare('SELECT seconds FROM oauth_replay_clock WHERE id = 1').first<{ seconds: number }>();
    expect(clock?.seconds).toBeGreaterThanOrEqual(expiresAt);
    await expect(f.principal()).rejects.toMatchObject({ code: 'invalid_token' });
  });

  it('fails closed if the final replay-clock update is skipped', async () => {
    const f = await authorizedReadFixture();
    const { principal, request } = await f.principal();
    await f.env.ALTERAN_DB.exec(`CREATE TRIGGER test_skip_final_clock BEFORE UPDATE ON oauth_replay_clock
      WHEN OLD.nonce = NEW.nonce BEGIN SELECT RAISE(IGNORE); END`.replaceAll('\n', ' '));
    await expect(readAuthorizedSpaceRecord(f.env, principal, request, SPACE, DID, COLLECTION, 'one')).rejects.toThrow();
  });

  it('fails closed on incomplete or malformed D1 batch results', async () => {
    for (const change of ['missing', 'initial', 'final', 'outcome', 'failure'] as const) {
      const f = await authorizedReadFixture();
      const watched = interceptRead(f.env, { after: (results) => {
        if (change === 'missing') results.pop();
        if (change === 'initial') results[1] = { success: true, results: [] };
        if (change === 'final') results[4] = { success: true, results: [{ valid: 0 }] };
        if (change === 'outcome') results[5] = { success: true, results: [] };
        if (change === 'failure') results[0] = { success: false };
      } });
      const { principal, request } = await f.principal(target, watched.env);
      watched.arm();
      expect((await readAuthorizedSpaceRecord(watched.env, principal, request, SPACE, DID, COLLECTION, 'one')).tag).toBe('unauthorized');
    }
  });

  it('withholds a read if the request is cancelled during the database transaction', async () => {
    const f = await authorizedReadFixture();
    const controller = new AbortController();
    const watched = interceptRead(f.env, { after: () => controller.abort() });
    const { principal, request } = await f.principal(target, watched.env, controller);
    watched.arm();
    expect((await readAuthorizedSpaceRecord(watched.env, principal, request, SPACE, DID, COLLECTION, 'one')).tag).toBe('unauthorized');
  });
});
