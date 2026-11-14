import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { COLLECTION, DID, interceptRead } from './helpers/spaces-authorized-read';
import { EMPTY, policyFixture } from './helpers/spaces-policy-read';
import { listContext, signedGenesisRequest, type GenesisFixture } from './helpers/spaces-list-genesis';
import { createAccount } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { beginPersonalSpaceDeletion } from '../src/db/space-lifecycle-delete';
import { applySpaceWrites } from '../src/db/space-store';
import { GET } from '../src/pages/xrpc/com.atproto.space.listRecords';

async function firstWrite(f: GenesisFixture) {
  await applySpaceWrites(f.env, EMPTY, DID, [{
    action: 'create', collection: COLLECTION, rkey: 'first', record: { $type: COLLECTION, text: 'private' },
  }], f.owner.incarnation);
}

function interceptCompletion(env: GenesisFixture['env'], phase: 'before-sample' | 'after-sample' | 'after-final',
  action: (watched: GenesisFixture['env']) => Promise<void>) {
  const database = env.ALTERAN_DB;
  const watched = { ...env };
  let called = false;
  const wrapped = new Proxy(database, { get(target, key) {
    if (key === 'prepare') return (sql: string) => {
      const statement = database.prepare(sql);
      const genesis = sql.includes('space_personal_policy p') && sql.includes('space_gc_attempt');
      const sample = genesis && sql.includes('RETURNING seconds, nonce');
      const final = genesis && sql.includes('SELECT clock.seconds, authorized.session_expires_at FROM authorized CROSS JOIN clock');
      if ((phase === 'after-final' && !final) || (phase !== 'after-final' && !sample)) return statement;
      return new Proxy(statement, { get(prepared, property) {
        if (property === 'bind') return (...values: Parameters<typeof prepared.bind>) => {
          const bound = prepared.bind(...values);
          return new Proxy(bound, { get(boundTarget, member) {
            if (member === 'first') return async () => {
              if (phase === 'before-sample') await action(watched);
              const row = await bound.first();
              if (phase !== 'before-sample') await action(watched);
              called = true;
              return row;
            };
            const value = Reflect.get(boundTarget, member, boundTarget);
            return typeof value === 'function' ? value.bind(boundTarget) : value;
          } });
        };
        const value = Reflect.get(prepared, property, prepared);
        return typeof value === 'function' ? value.bind(prepared) : value;
      } });
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  watched.ALTERAN_DB = wrapped;
  return { env: watched, called: () => called };
}

describe('fresh personal Space list races', () => {
  it('projects no genesis witness when revocation precedes selection', async () => {
    const f = await policyFixture();
    const watched = interceptRead(f.env, { before: async () => {
      await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
    } });
    const request = await signedGenesisRequest(f, { env: watched.env });
    watched.arm();
    const response = await GET(listContext(watched.env, request));
    expect(response.status).toBe(401);
    expect(watched.returned()).toEqual([]);
  });

  it('lists a committed first write rather than an empty page if it precedes selection', async () => {
    const f = await policyFixture();
    const watched = interceptRead(f.env, { before: async () => await firstWrite(f) });
    const request = await signedGenesisRequest(f, { env: watched.env });
    watched.arm();
    const response = await GET(listContext(watched.env, request));
    expect(response.status).toBe(200);
    expect((await response.json() as { records: unknown[] }).records).toHaveLength(1);
  });

  it('withholds the empty page when live state changes after selection', async () => {
    for (const mode of ['revoked', 'rotated', 'deleted', 'written', 'expired', 'cancelled', 'account', 'database', 'policy'] as const) {
      const f = await policyFixture();
      const other = mode === 'database' ? await policyFixture() : undefined;
      const controller = new AbortController();
      if (mode === 'policy') await f.env.ALTERAN_DB.prepare('DROP TRIGGER space_personal_policy_update').run();
      const watched = interceptRead(f.env, { after: async () => {
        if (mode === 'revoked') await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
          .bind(f.sessionId).run();
        if (mode === 'rotated') await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET access_jti = ? WHERE id = ?')
          .bind('new-access-jti', f.sessionId).run();
        if (mode === 'deleted') expect((await beginPersonalSpaceDeletion(f.env, EMPTY, crypto.randomUUID(), f.owner.incarnation)).tag)
          .toBe('started');
        if (mode === 'written') await firstWrite(f);
        if (mode === 'expired') await f.env.ALTERAN_DB.prepare('UPDATE oauth_replay_clock SET seconds = ? WHERE id = 1')
          .bind(f.tokens.accessPayload.exp).run();
        if (mode === 'cancelled') controller.abort();
        if (mode === 'account') {
          await f.env.ALTERAN_DB.prepare('DELETE FROM account WHERE did = ?').bind(DID).run();
          await f.env.ALTERAN_DB.prepare('DELETE FROM account_state WHERE did = ?').bind(DID).run();
          await createAccount(f.env, { did: DID, handle: 'test.example', passwordScrypt: null });
          await setAccountState(f.env, DID, { tag: 'active' });
        }
        if (mode === 'database' && other) watched.env.ALTERAN_DB = other.env.ALTERAN_DB;
        if (mode === 'policy') await f.env.ALTERAN_DB.prepare('UPDATE space_personal_policy SET creation_nonce = ? WHERE space_ref = ?')
          .bind(crypto.randomUUID(), EMPTY).run();
      } });
      const request = await signedGenesisRequest(f, { env: watched.env, signal: controller.signal });
      watched.arm();
      const response = await GET(listContext(watched.env, request));
      expect(response.status).toBe(401);
      expect(await response.text()).not.toContain('records');
    }
  });

  it('denies a policy identity change inside the selection transaction', async () => {
    const f = await policyFixture();
    const changed = crypto.randomUUID();
    const watched = interceptRead(f.env, { before: async () => {
      await f.env.ALTERAN_DB.prepare('DROP TRIGGER space_personal_policy_update').run();
      await f.env.ALTERAN_DB.exec(`CREATE TRIGGER test_genesis_change AFTER UPDATE ON oauth_replay_clock
        WHEN OLD.nonce = NEW.nonce BEGIN
          UPDATE space_personal_policy SET creation_nonce = '${changed}' WHERE space_ref = '${EMPTY}';
        END`.replaceAll('\n', ' '));
    } });
    const request = await signedGenesisRequest(f, { env: watched.env });
    watched.arm();
    expect((await GET(listContext(watched.env, request))).status).toBe(401);
    const row = await f.env.ALTERAN_DB.prepare('SELECT creation_nonce FROM space_personal_policy WHERE space_ref = ?')
      .bind(EMPTY).first<{ creation_nonce: string }>();
    expect(row?.creation_nonce).toBe(changed);
  });

  it('rechecks first-write state in both completion statements', async () => {
    for (const phase of ['before-sample', 'after-sample'] as const) {
      const f = await policyFixture();
      const watched = interceptCompletion(f.env, phase, async () => await firstWrite(f));
      const request = await signedGenesisRequest(f, { env: watched.env });
      const response = await GET(listContext(watched.env, request));
      expect(watched.called()).toBe(true);
      expect(response.status).toBe(401);
      expect(await response.text()).not.toContain('records');
    }
  });

  it('rechecks authorization and policy identity after the completion clock sample', async () => {
    for (const mode of ['revoked', 'rotated', 'expired', 'account', 'policy'] as const) {
      const f = await policyFixture();
      if (mode === 'policy') await f.env.ALTERAN_DB.prepare('DROP TRIGGER space_personal_policy_update').run();
      const watched = interceptCompletion(f.env, 'after-sample', async () => {
        if (mode === 'revoked') await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
          .bind(f.sessionId).run();
        if (mode === 'rotated') await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET access_jti = ? WHERE id = ?')
          .bind('new-access-jti', f.sessionId).run();
        if (mode === 'expired') await f.env.ALTERAN_DB.prepare('UPDATE oauth_replay_clock SET seconds = ? WHERE id = 1')
          .bind(f.tokens.accessPayload.exp).run();
        if (mode === 'account') await f.env.ALTERAN_DB.prepare('UPDATE account_state SET active = 0 WHERE did = ?').bind(DID).run();
        if (mode === 'policy') await f.env.ALTERAN_DB.prepare('UPDATE space_personal_policy SET creation_nonce = ? WHERE space_ref = ?')
          .bind(crypto.randomUUID(), EMPTY).run();
      });
      const request = await signedGenesisRequest(f, { env: watched.env });
      const response = await GET(listContext(watched.env, request));
      expect(watched.called()).toBe(true);
      expect(response.status).toBe(401);
    }
  });

  it('checks the database and cancellation after the final completion read', async () => {
    for (const mode of ['database', 'cancelled'] as const) {
      const f = await policyFixture();
      const other = mode === 'database' ? await policyFixture() : undefined;
      const controller = new AbortController();
      const watched = interceptCompletion(f.env, 'after-final', async (env) => {
        if (other) env.ALTERAN_DB = other.env.ALTERAN_DB;
        else controller.abort();
      });
      const request = await signedGenesisRequest(f, { env: watched.env, signal: controller.signal });
      const response = await GET(listContext(watched.env, request));
      expect(watched.called()).toBe(true);
      expect(response.status).toBe(401);
    }
  });
});
