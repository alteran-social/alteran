import { expect } from '@std/expect';
import * as dagCbor from '@ipld/dag-cbor';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { applySpaceWrites, createLocalSpace } from '../src/db/space-store';
import { acquireSpaceSnapshot, readSpaceSnapshotPage, releaseSpaceSnapshot } from '../src/db/space-snapshot';
import { readSpaceRepoArchive } from '../src/lib/spaces/repo-archive';
import { streamSpaceRepoArchive } from '../src/services/space-repo-export';

const DID = 'did:example:test';
const COLLECTION = 'com.example.note';
const SPACE = `at://${DID}/space/com.example.notes/pagination`;
type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

function create(rkey: string, text = 'value') {
  return { action: 'create' as const, collection: COLLECTION, rkey, record: { $type: COLLECTION, text } };
}

async function fixture() {
  const env = await makeEnv();
  await createLocalSpace(env, SPACE);
  await applySpaceWrites(env, SPACE, DID, [create('z', 'original')]);
  return env;
}

describe('bounded Space snapshot pagination', () => {
  it('advances through paths with no version visible at the leased generation', async () => {
    const env = await fixture();
    await applySpaceWrites(env, SPACE, DID, [create('a')]);
    await applySpaceWrites(env, SPACE, DID, [{ action: 'delete', collection: COLLECTION, rkey: 'a' }]);
    const lease = await acquireSpaceSnapshot(env, SPACE, DID);
    await applySpaceWrites(env, SPACE, DID, [create('b')]);
    const before = await readSpaceSnapshotPage(env, lease, null, 1);
    const after = await readSpaceSnapshotPage(env, lease, before.cursor, 1);
    const visible = await readSpaceSnapshotPage(env, lease, after.cursor, 1);
    const end = await readSpaceSnapshotPage(env, lease, visible.cursor, 1);
    expect(before).toEqual({ records: [], cursor: `${COLLECTION}/a` });
    expect(after).toEqual({ records: [], cursor: `${COLLECTION}/b` });
    expect(visible.records.map((record) => record.rkey)).toEqual(['z']);
    expect(end).toEqual({ records: [], cursor: null });
    await releaseSpaceSnapshot(env, lease);
  });

  it('keeps the cursor before a visible record excluded by the byte limit', async () => {
    const env = await fixture();
    const text = 'x'.repeat(600_000);
    await applySpaceWrites(env, SPACE, DID, [create('a', text)]);
    await applySpaceWrites(env, SPACE, DID, [create('c', text)]);
    const lease = await acquireSpaceSnapshot(env, SPACE, DID);
    await applySpaceWrites(env, SPACE, DID, [create('b')]);
    const first = await readSpaceSnapshotPage(env, lease, null);
    const second = await readSpaceSnapshotPage(env, lease, first.cursor);
    expect(first.records.map((record) => record.rkey)).toEqual(['a']);
    expect(first.cursor).toBe(`${COLLECTION}/b`);
    expect(second.records.map((record) => record.rkey)).toEqual(['c', 'z']);
    await releaseSpaceSnapshot(env, lease);
  });

  it('exports correctly when a whole path page is newer than its snapshot', async () => {
    const env = await fixture();
    const opened = await streamSpaceRepoArchive(env, SPACE, DID);
    for (let offset = 0; offset < 120; offset += 30) {
      await applySpaceWrites(env, SPACE, DID, Array.from({ length: 30 }, (_, index) =>
        create(`a${(offset + index).toString().padStart(3, '0')}`)));
    }
    const bytes = new Uint8Array(await new Response(opened.body).arrayBuffer());
    const archive = await readSpaceRepoArchive(bytes, { space: SPACE, repo: DID });
    expect(archive.records.map((record) => record.rkey)).toEqual(['z']);
    expect(dagCbor.decode(archive.records[0].value)).toMatchObject({ text: 'original' });
  });

  it('seeks rather than scanning thousands of versions of a single path', async () => {
    const env = await fixture();
    const lease = await acquireSpaceSnapshot(env, SPACE, DID);
    for (const trigger of ['space_record_version_update_guard', 'space_version_fence_update',
      'space_record_version_insert_guard', 'space_version_fence_insert']) {
      await env.ALTERAN_DB.prepare(`DROP TRIGGER ${trigger}`).run();
    }
    await env.ALTERAN_DB.prepare('UPDATE space_record_version SET until_generation = 2 WHERE epoch_id = ?')
      .bind(lease.epochId).run();
    await env.ALTERAN_DB.prepare(`WITH RECURSIVE n(i) AS (VALUES(2) UNION ALL SELECT i + 1 FROM n WHERE i < 3001)
      INSERT INTO space_record_version (epoch_id, space_ref, repo_did, path, collection, rkey,
        from_generation, until_generation, cid, value_cbor, value_size, repo_rev)
      SELECT v.epoch_id, v.space_ref, v.repo_did, v.path, v.collection, v.rkey, n.i,
        CASE WHEN n.i = 3001 THEN NULL ELSE n.i + 1 END, v.cid, v.value_cbor, v.value_size, v.repo_rev
      FROM space_record_version v CROSS JOIN n WHERE v.epoch_id = ? AND v.from_generation = 1`)
      .bind(lease.epochId).run();
    const { env: observed, rowsRead } = captureRowsRead(env);
    const page = await readSpaceSnapshotPage(observed, lease, null);
    expect(page.records.map((record) => record.rkey)).toEqual(['z']);
    expect(rowsRead()).toBeLessThan(100);
    await releaseSpaceSnapshot(env, lease);
  });
});

function captureRowsRead(env: TestEnv) {
  const database = env.ALTERAN_DB;
  let count = Number.POSITIVE_INFINITY;
  const wrapped = new Proxy(database, {
    get(target, property) {
      if (property === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
        const results = await database.batch(statements);
        count = results[1].meta.rows_read;
        return results;
      };
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  return { env: { ...env, ALTERAN_DB: wrapped }, rowsRead: () => count };
}
