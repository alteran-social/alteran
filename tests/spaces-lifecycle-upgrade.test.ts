import { Miniflare } from 'miniflare';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import type { D1Database } from '@cloudflare/workers-types';
import type { Env } from '../src/env';
import { createLocalSpace, applySpaceWrites, getSpaceRecord } from '../src/db/space-store';
import { beginPersonalSpaceDeletion } from '../src/db/space-lifecycle-delete';
import { createPersonalSpace } from '../src/db/space-lifecycle-create';

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

describe('personal Space lifecycle migration upgrade', () => {
  it('upgrades populated 0031 state without reclassifying quarantined or legacy Spaces', async () => {
    const mf = new Miniflare({ d1Databases: { DB: ':memory:' }, compatibilityDate: '2025-10-02',
      script: "export default { fetch: () => new Response('ok') }", modules: true });
    await mf.ready;
    const database = await mf.getD1Database('DB') as unknown as D1Database;
    try {
      const files = readdirSync(directory).filter((name) => name.endsWith('.sql')).sort();
      for (const file of files.filter((name) => name < '0032')) await apply(database, file);
      const env = { ALTERAN_DB: database, PDS_DID: DID } as unknown as Env;
      for (const space of [LEGACY, ORPHAN]) {
        await createLocalSpace(env, space);
        await applySpaceWrites(env, space, DID, [{ action: 'create', collection: COLLECTION, rkey: 'a', record: { $type: COLLECTION, text: space } }]);
      }
      await database.prepare("UPDATE space_epoch SET state = 'quarantined' WHERE space_ref = ?").bind(LEGACY).run();
      await database.prepare(`INSERT INTO space_mutation_attempt
        SELECT 'orphan', space_ref, repo_did, active_epoch_id, generation, rev, set_hash FROM space_repo WHERE space_ref = ?`).bind(ORPHAN).run();
      const before = await database.prepare('SELECT space_ref, repo_did, rev, generation, hex(set_hash) AS hash FROM space_repo ORDER BY space_ref').all();
      for (const file of files.filter((name) => name >= '0032' && name < '0037')) await apply(database, file);
      const after = await database.prepare('SELECT space_ref, repo_did, rev, generation, hex(set_hash) AS hash FROM space_repo ORDER BY space_ref').all();
      expect(after.results).toEqual(before.results);
      expect((await database.prepare('SELECT state FROM space_epoch WHERE space_ref = ?').bind(LEGACY).first())?.state).toBe('quarantined');
      expect((await database.prepare('SELECT COUNT(*) AS n FROM space_mutation_attempt WHERE mutation_id = ?').bind('orphan').first())?.n).toBe(1);
      expect((await database.prepare('SELECT COUNT(*) AS n FROM space_personal_policy').first())?.n).toBe(0);
      expect((await beginPersonalSpaceDeletion(env, LEGACY, crypto.randomUUID())).tag).toBe('unsupported');
      expect((await beginPersonalSpaceDeletion(env, ORPHAN, crypto.randomUUID())).tag).toBe('unsupported');
      expect(await getSpaceRecord(env, LEGACY, DID, COLLECTION, 'a')).toBeNull();
      expect(await getSpaceRecord(env, ORPHAN, DID, COLLECTION, 'a')).not.toBeNull();
      await createPersonalSpace(env, NEW, { $type: 'com.atproto.personalspace.policy' }, crypto.randomUUID());
      expect((await beginPersonalSpaceDeletion(env, NEW, crypto.randomUUID())).tag).toBe('started');
      const plan = await database.prepare('EXPLAIN QUERY PLAN SELECT 1 FROM space_mutation_attempt WHERE space_ref = ? LIMIT 1').bind(ORPHAN).all<{detail: string}>();
      expect(plan.results.map((row: { detail: string }) => row.detail).join('\n')).toContain('space_mutation_attempt_owner');
    } finally { await mf.dispose(); }
  });
});
