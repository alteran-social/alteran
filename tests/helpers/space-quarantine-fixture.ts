import type { D1Database } from '@cloudflare/workers-types';
import { Miniflare } from 'miniflare';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Env } from '../../src/env';
import { encodeRecordBlock } from '../../src/services/repo/blockstore-ops';
import { applySpaceSetHashChanges, spaceRecordHashElement } from '../../src/lib/spaces/lthash';
import { bindQuarantineFixtureOwners } from './space-quarantine-owner';

export const did = 'did:example:test';
export const space = `at://${did}/space/com.example.notes/a`;
export const revision = '3n2a5tw2wd22l';
const migrations = join(import.meta.dirname, '..', '..', 'migrations');

type LegacyRecord = { collection: string; rkey: string; text: string };

async function applyFile(database: D1Database, name: string): Promise<void> {
  for (const chunk of readFileSync(join(migrations, name), 'utf8').split('--> statement-breakpoint')) {
    const statement = chunk.trim();
    if (statement) await database.exec(statement.replace(/\n/g, ' '));
  }
}

export async function setup(
  records: LegacyRecord[],
  wrongHash = false,
  beforeMigrations?: (database: D1Database) => Promise<void>,
) {
  const miniflare = new Miniflare({
    d1Databases: { DB: ':memory:' }, compatibilityDate: '2025-10-02',
    script: "export default { fetch: () => new Response('ok') }", modules: true,
  });
  await miniflare.ready;
  const database = await miniflare.getD1Database('DB') as unknown as D1Database;
  const names = readdirSync(migrations).filter((name) => name.endsWith('.sql')).sort();
  for (const name of names.filter((name) => name < '0016')) await applyFile(database, name);
  const encoded = await Promise.all(records.map(async (record) => {
    const [cid, value] = await encodeRecordBlock({ $type: record.collection, text: record.text });
    return { ...record, cid: cid.toString(), value };
  }));
  const hash = wrongHash ? new Uint8Array(2048) : applySpaceSetHashChanges(null, encoded.map((record) => ({
    action: 'add' as const, element: spaceRecordHashElement(record.collection, record.rkey, record.cid),
  })));
  await database.batch([
    database.prepare('INSERT INTO space (space_ref, authority_did, space_type, skey, created_at) VALUES (?, ?, ?, ?, 1)')
      .bind(space, did, 'com.example.notes', 'a'),
    database.prepare('INSERT INTO space_repo (space_ref, repo_did, rev, set_hash, generation, mutation_id) VALUES (?, ?, ?, ?, 7, ?)')
      .bind(space, did, revision, hash, 'legacy-mutation'),
    ...encoded.map((record) => database.prepare(
      `INSERT INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(space, did, record.collection, record.rkey, record.cid, record.value, revision)),
  ]);
  if (beforeMigrations) await beforeMigrations(database);
  for (const name of names.filter((name) => name >= '0016')) await applyFile(database, name);
  await bindQuarantineFixtureOwners(database);
  return { env: { ALTERAN_DB: database, PDS_DID: did } as unknown as Env, database, dispose: () => miniflare.dispose() };
}

