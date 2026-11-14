import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { DID, TYPE, ref, fixture, context } from './helpers/spaces-owner-listing';
import { createAccount } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { applySpaceWrites } from '../src/db/space-store';
import { GET } from '../src/pages/xrpc/com.atproto.space.listSpaces';

function watchBatch(
  env: Awaited<ReturnType<typeof makeEnv>>,
  callback: () => Promise<void>,
  timing: 'before' | 'after' = 'after',
) {
  const database = env.ALTERAN_DB;
  let changed = false;
  const wrapped = new Proxy(database, { get(target, property) {
    if (property === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
      if (changed || statements.length !== 6) return database.batch(statements);
      changed = true;
      if (timing === 'before') await callback();
      const result = await database.batch(statements);
      if (timing === 'after') await callback();
      return result;
    };
    const value = Reflect.get(target, property, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  return { database: wrapped, changed: () => changed };
}

describe('owner Space listing races', () => {
  it('fences session revocation before selection and after the page is selected', async () => {
    for (const timing of ['before', 'after'] as const) {
      const f = await fixture(); await f.create('one');
      const watched = watchBatch(f.env, async () => {
        await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
      }, timing);
      const response = await GET(context({ ...f.env, ALTERAN_DB: watched.database }, await f.request()));
      expect(watched.changed()).toBe(true);
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: 'AuthRequired', message: 'Authentication required' });
    }
  });

  it('fences account replacement after selection', async () => {
    const f = await fixture(); await f.create('one');
    const watched = watchBatch(f.env, async () => {
      await f.env.ALTERAN_DB.prepare('DELETE FROM account WHERE did = ?').bind(DID).run();
      await f.env.ALTERAN_DB.prepare('DELETE FROM account_state WHERE did = ?').bind(DID).run();
      await createAccount(f.env, { did: DID, handle: 'test.example', passwordScrypt: null });
      await setAccountState(f.env, DID, { tag: 'active' });
    });
    const response = await GET(context({ ...f.env, ALTERAN_DB: watched.database }, await f.request()));
    expect(watched.changed()).toBe(true);
    expect(response.status).toBe(401);
  });

  it('fences a new repo or a new quarantined Space after selection', async () => {
    for (const change of ['repo', 'quarantine'] as const) {
      const f = await fixture(); await f.create('one');
      const watched = watchBatch(f.env, async () => {
        if (change === 'repo') {
          await applySpaceWrites(f.env, ref('one'), DID, [{ action: 'create', collection: 'com.example.note', rkey: 'a',
            record: { $type: 'com.example.note', text: 'a' } }], f.account.space_incarnation);
        } else {
          await f.env.ALTERAN_DB.prepare('INSERT INTO space (space_ref, authority_did, space_type, skey, created_at) VALUES (?, ?, ?, ?, 1)')
            .bind('malformed', 'bad authority', TYPE, 'bad').run();
        }
      });
      const response = await GET(context({ ...f.env, ALTERAN_DB: watched.database }, await f.request()));
      expect(watched.changed()).toBe(true);
      expect(response.status).toBe(401);
    }
  });

  it('fences insertion into an initially empty page', async () => {
    const f = await fixture();
    const watched = watchBatch(f.env, () => f.create('new'));
    const response = await GET(context({ ...f.env, ALTERAN_DB: watched.database }, await f.request()));
    expect(watched.changed()).toBe(true);
    expect(response.status).toBe(401);
  });

  it('fails closed when D1 selection fails or the bound database is replaced', async () => {
    for (const change of ['fault', 'binding'] as const) {
      const f = await fixture(); await f.create('one');
      const other = await makeEnv();
      const env = { ...f.env };
      const database = env.ALTERAN_DB;
      let changed = false;
      const watched = new Proxy(database, { get(target, property) {
        if (property === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
          if (!changed && statements.length === 6) {
            changed = true;
            if (change === 'fault') throw new Error('database fault');
            const result = await database.batch(statements);
            env.ALTERAN_DB = other.ALTERAN_DB;
            return result;
          }
          return database.batch(statements);
        };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      } });
      env.ALTERAN_DB = watched;
      const response = await GET(context(env, await f.request()));
      expect(changed).toBe(true);
      expect(response.status).toBe(401);
    }
  });
});
