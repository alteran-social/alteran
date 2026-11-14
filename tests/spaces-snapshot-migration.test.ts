import { expect } from '@std/expect';
import { Miniflare } from 'miniflare';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { D1Database } from '@cloudflare/workers-types';
import type { Env } from '../src/env';
import { describe, it } from './helpers/bdd';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';
import { applySpaceSetHashChanges, spaceRecordHashElement } from '../src/lib/spaces/lthash';
import { acquireSpaceSnapshot } from '../src/db/space-snapshot';
import { applySpaceWrites, getSpaceRecord } from '../src/db/space-store';
import { createAccount } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { spaceOwner } from './helpers/space-env';

const did = 'did:example:test';
const space = `at://${did}/space/com.example.notes/a`;
const collection = 'com.example.note';
const revision = '3n2a5tw2wd22l';
const directory = join(import.meta.dirname, '..', 'migrations');

async function applyFile(database: D1Database, filename: string): Promise<void> {
  const sql = readFileSync(join(directory, filename), 'utf8');
  for (const chunk of sql.split('--> statement-breakpoint')) {
    const statement = chunk.trim();
    if (statement) await database.exec(statement.replace(/\n/g, ' '));
  }
}

async function legacyDatabase(): Promise<{ database: D1Database; dispose: () => Promise<void> }> {
  const miniflare = new Miniflare({
    d1Databases: { DB: ':memory:' }, compatibilityDate: '2025-10-02',
    script: "export default { fetch: () => new Response('ok') }", modules: true,
  });
  await miniflare.ready;
  const database = await miniflare.getD1Database('DB') as unknown as D1Database;
  for (const filename of readdirSync(directory).filter((name) => name.endsWith('.sql') && name < '0016').sort()) {
    await applyFile(database, filename);
  }
  return { database, dispose: () => miniflare.dispose() };
}

async function seedLegacy(database: D1Database, corrupt: boolean): Promise<{ cid: string; bytes: Uint8Array }> {
  const [cid, bytes] = await encodeRecordBlock({ $type: collection, text: 'original' });
  const state = corrupt ? new Uint8Array(2048) : applySpaceSetHashChanges(null, [{
    action: 'add', element: spaceRecordHashElement(collection, 'a', cid.toString()),
  }]);
  await database.batch([
    database.prepare('INSERT INTO space (space_ref, authority_did, space_type, skey, created_at) VALUES (?, ?, ?, ?, ?)')
      .bind(space, did, 'com.example.notes', 'a', 1),
    database.prepare('INSERT INTO space_repo (space_ref, repo_did, rev, set_hash, generation, mutation_id) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(space, did, revision, state, 7, 'legacy-mutation'),
    database.prepare('INSERT INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(space, did, collection, 'a', corrupt ? 'wrong-cid' : cid.toString(), new Uint8Array(bytes).buffer, revision),
  ]);
  return { cid: cid.toString(), bytes };
}

async function applySnapshotMigrations(database: D1Database): Promise<void> {
  for (const filename of readdirSync(directory).filter((name) => name.endsWith('.sql') && name >= '0016').sort()) {
    await applyFile(database, filename);
  }
}

async function activeLegacyOwner(env: Env): Promise<string> {
  await createAccount(env, { did, handle: 'test.example', passwordScrypt: null });
  await setAccountState(env, did, { tag: 'active' });
  return await spaceOwner(env, did);
}

describe('space snapshot backfill', () => {
  it('copies existing records and quarantines the epoch until independent verification exists', async () => {
    const { database, dispose } = await legacyDatabase();
    try {
      const legacy = await seedLegacy(database, false);
      await applySnapshotMigrations(database);
      const row = await database.prepare(
        `SELECT e.state, h.generation, h.rev, v.cid, v.value_cbor FROM space_repo h
         JOIN space_epoch e ON e.id = h.active_epoch_id JOIN space_record_version v ON v.epoch_id = e.id
         WHERE h.space_ref = ? AND h.repo_did = ?`,
      ).bind(space, did).first<{ state: string; generation: number; rev: string; cid: string; value_cbor: number[] }>();
      expect(row!.state).toBe('quarantined');
      expect(row!.generation).toBe(7);
      expect(row!.rev).toBe(revision);
      expect(row!.cid).toBe(legacy.cid);
      expect(Uint8Array.from(row!.value_cbor)).toEqual(legacy.bytes);
      const env = { ALTERAN_DB: database, PDS_DID: did } as unknown as Env;
      const owner = await activeLegacyOwner(env);
      expect((await database.prepare('SELECT owner_incarnation FROM space_epoch WHERE space_ref = ?')
        .bind(space).first())?.owner_incarnation).toBeNull();
      expect(await getSpaceRecord(env, space, did, collection, 'a', owner)).toBeNull();
      await expect(acquireSpaceSnapshot(env, space, did, owner)).rejects.toThrow();
      await expect(database.prepare("UPDATE space_epoch SET state = 'active' WHERE space_ref = ?")
        .bind(space).run()).rejects.toThrow();
      await expect(applySpaceWrites(env, space, did, [
        { action: 'create', collection, rkey: 'b', record: { $type: collection } },
      ], owner)).rejects.toThrow();
    } finally {
      await dispose();
    }
  });

  it('does not expose a legacy epoch with corrupt CID or hash', async () => {
    const { database, dispose } = await legacyDatabase();
    try {
      await seedLegacy(database, true);
      await applySnapshotMigrations(database);
      const env = { ALTERAN_DB: database, PDS_DID: did } as unknown as Env;
      const owner = await activeLegacyOwner(env);
      expect(await getSpaceRecord(env, space, did, collection, 'a', owner)).toBeNull();
      await expect(acquireSpaceSnapshot(env, space, did, owner)).rejects.toThrow();
      expect((await database.prepare('SELECT state FROM space_epoch WHERE space_ref = ?').bind(space).first())?.state)
        .toBe('quarantined');
    } finally {
      await dispose();
    }
  });

  it('rolls back the backfill if a legacy record has no repo head', async () => {
    const { database, dispose } = await legacyDatabase();
    try {
      const [, bytes] = await encodeRecordBlock({ $type: collection });
      await database.prepare(
        'INSERT INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ).bind(space, did, collection, 'a', 'cid', new Uint8Array(bytes).buffer, revision).run();
      const schema = readdirSync(directory).find((name) => name.startsWith('0016_') && name.endsWith('.sql'));
      const backfill = readdirSync(directory).find((name) => name.startsWith('0017_') && name.endsWith('.sql'));
      if (!schema || !backfill) throw new Error('Missing snapshot migrations');
      await applyFile(database, schema);
      await expect(applyFile(database, backfill)).rejects.toThrow();
      expect((await database.prepare('SELECT COUNT(*) AS count FROM space_epoch').first())?.count).toBe(0);
      expect((await database.prepare('SELECT COUNT(*) AS count FROM space_record_version').first())?.count).toBe(0);
      expect((await database.prepare('SELECT COUNT(*) AS count FROM space_record').first())?.count).toBe(1);
    } finally {
      await dispose();
    }
  });
});
