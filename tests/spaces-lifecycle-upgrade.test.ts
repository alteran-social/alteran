import { Miniflare } from 'miniflare';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import type { D1Database } from '@cloudflare/workers-types';
import type { Env } from '../src/env';
import { createAccount } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { applySpaceWrites, getSpaceRecord } from '../src/db/space-store';
import { beginPersonalSpaceDeletion } from '../src/db/space-lifecycle-delete';
import { createPersonalSpace } from '../src/db/space-lifecycle-create';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';
import { spaceOwner } from './helpers/space-env';

const DID = 'did:example:test';
const LEGACY = `at://${DID}/space/com.example.notes/upgradelegacy`;
const ORPHAN = `at://${DID}/space/com.example.notes/upgradeorphan`;
const NEW = `at://${DID}/space/com.example.notes/upgradenew`;
const COLLECTION = 'com.example.note';
const directory = join(import.meta.dirname!, '..', 'migrations');
async function apply(database: D1Database, filename: string) {
  const source = readFileSync(join(directory, filename), 'utf8');
  for (const chunk of source.split('--> statement-breakpoint')) {
    const statement = chunk.trim();
    if (statement) await database.exec(statement.replace(/\n/g, ' '));
  }
}

/** Insert through the 0031 writer's attempt, head, winner and effect fences. */
async function seedOldWriter(database: D1Database, space: string, skey: string) {
  const mutation = crypto.randomUUID(), epoch = crypto.randomUUID(), rev = '3n2a5tw2wd22l';
  const [cid, value] = await encodeRecordBlock({ $type: COLLECTION, text: space });
  const hash = new Uint8Array(2048);
  await database.batch([
    database.prepare('INSERT INTO space (space_ref, authority_did, space_type, skey, created_at) VALUES (?, ?, ?, ?, 1)')
      .bind(space, DID, 'com.example.notes', skey),
    database.prepare(`INSERT INTO space_mutation_attempt
      (mutation_id, space_ref, repo_did, epoch_id, generation, rev, set_hash) VALUES (?, ?, ?, ?, 1, ?, ?)`)
      .bind(mutation, space, DID, epoch, rev, hash),
    database.prepare(`INSERT INTO space_repo (space_ref, repo_did, rev, set_hash, generation, mutation_id, active_epoch_id)
      VALUES (?, ?, ?, ?, 1, ?, ?)`).bind(space, DID, rev, hash, mutation, epoch),
    database.prepare('INSERT INTO space_commit_assertion (mutation_id, valid) VALUES (?, 1)').bind(`${mutation}:won`),
    database.prepare("INSERT INTO space_epoch (id, space_ref, repo_did, state, created_at) VALUES (?, ?, ?, 'active', 1)")
      .bind(epoch, space, DID),
    database.prepare('INSERT INTO space_record VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(space, DID, COLLECTION, 'a', cid.toString(), value, rev),
    database.prepare(`INSERT INTO space_record_version
      (epoch_id, space_ref, repo_did, path, collection, rkey, from_generation, until_generation, cid, value_cbor, value_size, repo_rev)
      VALUES (?, ?, ?, ?, ?, ?, 1, NULL, ?, ?, ?, ?)`)
      .bind(epoch, space, DID, `${COLLECTION}/a`, COLLECTION, 'a', cid.toString(), value, value.length, rev),
    database.prepare('INSERT INTO space_op VALUES (?, ?, ?, 0, ?, ?, ?, NULL)')
      .bind(space, DID, rev, COLLECTION, 'a', cid.toString()),
    database.prepare('DELETE FROM space_commit_assertion WHERE mutation_id = ?').bind(`${mutation}:won`),
    database.prepare('DELETE FROM space_mutation_attempt WHERE mutation_id = ?').bind(mutation),
  ]);
}

describe('personal Space lifecycle migration upgrade', () => {
  it('rejects forged owner bindings installed between the schema and guard migrations', async () => {
    const mf = new Miniflare({ d1Databases: { DB: ':memory:' }, compatibilityDate: '2025-10-02',
      script: "export default { fetch: () => new Response('ok') }", modules: true });
    await mf.ready;
    const database = await mf.getD1Database('DB') as unknown as D1Database;
    try {
      const files = readdirSync(directory).filter((name) => name.endsWith('.sql')).sort();
      for (const file of files.filter((name) => name < '0032')) await apply(database, file);
      await seedOldWriter(database, LEGACY, 'upgradelegacy');
      for (const file of files.filter((name) => name >= '0032' && name < '0043')) await apply(database, file);
      await database.prepare('UPDATE space_epoch SET owner_incarnation = ? WHERE space_ref = ?')
        .bind('a'.repeat(32), LEGACY).run();
      const guard = files.find((name) => name.startsWith('0043_'));
      if (!guard) throw new Error('Missing owner guard migration');
      await expect(apply(database, guard)).rejects.toThrow();
      expect((await database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'view' AND name = 'space_owned_epoch'")
        .first())?.n).toBe(0);
    } finally { await mf.dispose(); }
  });

  it('quarantines pre-ownership data without silently adopting its old epochs', async () => {
    const mf = new Miniflare({ d1Databases: { DB: ':memory:' }, compatibilityDate: '2025-10-02',
      script: "export default { fetch: () => new Response('ok') }", modules: true });
    await mf.ready;
    const database = await mf.getD1Database('DB') as unknown as D1Database;
    try {
      const files = readdirSync(directory).filter((name) => name.endsWith('.sql')).sort();
      for (const file of files.filter((name) => name < '0032')) await apply(database, file);
      await seedOldWriter(database, LEGACY, 'upgradelegacy');
      await seedOldWriter(database, ORPHAN, 'upgradeorphan');
      await database.prepare("UPDATE space_epoch SET state = 'quarantined' WHERE space_ref = ?").bind(LEGACY).run();
      await database.prepare(`INSERT INTO space_mutation_attempt
        SELECT 'orphan', space_ref, repo_did, active_epoch_id, generation, rev, set_hash FROM space_repo WHERE space_ref = ?`).bind(ORPHAN).run();
      const before = await database.prepare('SELECT space_ref, repo_did, rev, generation, hex(set_hash) AS hash FROM space_repo ORDER BY space_ref').all();
      for (const file of files.filter((name) => name >= '0032')) await apply(database, file);
      const after = await database.prepare('SELECT space_ref, repo_did, rev, generation, hex(set_hash) AS hash FROM space_repo ORDER BY space_ref').all();
      expect(after.results).toEqual(before.results);
      expect((await database.prepare('SELECT COUNT(*) AS n FROM space_epoch WHERE owner_incarnation IS NULL').first())?.n).toBe(2);
      expect((await database.prepare('SELECT state FROM space_epoch WHERE space_ref = ?').bind(LEGACY).first())?.state).toBe('quarantined');
      expect((await database.prepare('SELECT COUNT(*) AS n FROM space_mutation_attempt WHERE mutation_id = ?').bind('orphan').first())?.n).toBe(1);
      expect((await database.prepare('SELECT COUNT(*) AS n FROM space_personal_policy').first())?.n).toBe(0);
      const env = { ALTERAN_DB: database, PDS_DID: DID, PDS_HANDLE: 'test.example' } as unknown as Env;
      await createAccount(env, { did: DID, handle: 'test.example', passwordScrypt: null });
      await setAccountState(env, DID, { tag: 'active' });
      const owner = await spaceOwner(env);
      expect((await beginPersonalSpaceDeletion(env, LEGACY, crypto.randomUUID(), owner)).tag).toBe('unsupported');
      expect((await beginPersonalSpaceDeletion(env, ORPHAN, crypto.randomUUID(), owner)).tag).toBe('unsupported');
      expect(await getSpaceRecord(env, LEGACY, DID, COLLECTION, 'a', owner)).toBeNull();
      expect(await getSpaceRecord(env, ORPHAN, DID, COLLECTION, 'a', owner)).toBeNull();
      await expect(applySpaceWrites(env, ORPHAN, DID, [{ action: 'update', collection: COLLECTION, rkey: 'a',
        record: { $type: COLLECTION, text: 'replacement' } }], owner)).rejects.toThrow();
      await createPersonalSpace(env, NEW, { $type: 'com.atproto.personalspace.policy' }, crypto.randomUUID(), owner);
      expect((await beginPersonalSpaceDeletion(env, NEW, crypto.randomUUID(), owner)).tag).toBe('started');
      const plan = await database.prepare('EXPLAIN QUERY PLAN SELECT 1 FROM space_mutation_attempt WHERE space_ref = ? LIMIT 1')
        .bind(ORPHAN).all<{detail: string}>();
      expect(plan.results.map((row: { detail: string }) => row.detail).join('\n')).toContain('space_mutation_attempt_owner');
    } finally { await mf.dispose(); }
  });
});
