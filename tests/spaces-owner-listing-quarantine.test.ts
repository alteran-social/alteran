import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { makeSpaceEnv } from './helpers/space-env';
import { DID, TYPE, ref, fixture, context } from './helpers/spaces-owner-listing';
import { GET } from '../src/pages/xrpc/com.atproto.space.listSpaces';

async function rejected(action: () => Promise<unknown>) {
  let failed = false;
  try { await action(); } catch { failed = true; }
  expect(failed).toBe(true);
}

describe('Space quarantine identity', () => {
  it('keeps exact binary references and rejects forged, replaced, or removed markers', async () => {
    const env = await makeSpaceEnv(), database = env.ALTERAN_DB;
    for (const key of ['a', 'A']) {
      await database.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?,?,?,?,1)')
        .bind(ref(key), DID, TYPE, key).run();
    }
    const rows = await database.prepare('SELECT space_ref FROM space_owner_unclassified ORDER BY space_ref COLLATE BINARY').all();
    expect(rows.results).toEqual([{ space_ref: ref('A') }, { space_ref: ref('a') }]);
    await rejected(() => database.prepare('INSERT INTO space_owner_unclassified (space_ref,authority_did,space_type) VALUES (?,?,?)')
      .bind(ref('missing'), DID, TYPE).run());
    await rejected(() => database.prepare('INSERT OR REPLACE INTO space_owner_unclassified (space_ref,authority_did,space_type) VALUES (?,?,?)')
      .bind(ref('a'), 'did:example:other', TYPE).run());
    await rejected(() => database.prepare('UPDATE space_owner_unclassified SET authority_did = ? WHERE space_ref = ?')
      .bind('did:example:other', ref('a')).run());
    await rejected(() => database.prepare('DELETE FROM space_owner_unclassified WHERE space_ref = ?').bind(ref('a')).run());
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_owner_unclassified').first())?.n).toBe(2);
  });

  it('retains an immutable global sentinel for malformed, non-text, and oversized references', async () => {
    for (const value of ['not-a-reference', new Uint8Array([0, 1, 2]).buffer, 'x'.repeat(8193)] as const) {
      const f = await fixture();
      await f.create('visible');
      await f.env.ALTERAN_DB.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?,?,?,?,1)')
        .bind(value, DID, TYPE, 'bad').run();
      expect((await f.env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_owner_quarantine_global').first())?.n).toBe(1);
      expect((await f.env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_owner_unclassified').first())?.n).toBe(0);
      await rejected(() => f.env.ALTERAN_DB.prepare('DELETE FROM space_owner_quarantine_global').run());
      await rejected(() => f.env.ALTERAN_DB.prepare('UPDATE space_owner_quarantine_global SET id = 1').run());
      await rejected(() => f.env.ALTERAN_DB.prepare('INSERT OR REPLACE INTO space_owner_quarantine_global (id) VALUES (1)').run());
      expect((await GET(context(f.env, await f.request()))).status).toBe(401);
    }
  });

  it('aborts an unindexable source insert if its global sentinel is skipped', async () => {
    const env = await makeSpaceEnv(), database = env.ALTERAN_DB;
    await database.exec('CREATE TRIGGER skip_global_quarantine BEFORE INSERT ON space_owner_quarantine_global BEGIN SELECT RAISE(IGNORE); END');
    await rejected(() => database.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?,?,?,?,1)')
      .bind('not-a-reference', DID, TYPE, 'bad').run());
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space').first())?.n).toBe(0);
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_owner_quarantine_global').first())?.n).toBe(0);
  });

  it('aborts an older direct insertion when its per-reference marker is skipped', async () => {
    const env = await makeSpaceEnv(), database = env.ALTERAN_DB;
    await database.exec('CREATE TRIGGER skip_old_marker BEFORE INSERT ON space_owner_unclassified BEGIN SELECT RAISE(IGNORE); END');
    await rejected(() => database.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?,?,?,?,1)')
      .bind(ref('old-writer'), DID, TYPE, 'old-writer').run());
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space').first())?.n).toBe(0);
    await database.exec('DROP TRIGGER skip_old_marker');
    await database.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?,?,?,?,1)')
      .bind(ref('old-writer'), DID, TYPE, 'old-writer').run();
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_owner_unclassified WHERE space_ref = ?')
      .bind(ref('old-writer')).first())?.n).toBe(1);
  });
});
