import { expect } from '@std/expect';
import * as dagCbor from '@ipld/dag-cbor';
import type { D1PreparedStatement } from '@cloudflare/workers-types';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { seedLegacySpaceBlobUsage } from './helpers/space-legacy';
import { applySpaceWrites, createLocalSpace, getSpaceRecord } from '../src/db/space-store';
import { acquireSpaceSnapshot, readSpaceSnapshotPage, releaseSpaceSnapshot } from '../src/db/space-snapshot';
import { pruneExpiredSpaceSnapshotLeases } from '../src/db/space-lease-expiry';
import { pruneSpaceRecordVersionsPage } from '../src/db/space-version-gc';
import { applySpaceSetHashChanges, spaceRecordHashElement, spaceSetHashDigest } from '../src/lib/spaces/lthash';
import { SpaceStorageError } from '../src/db/space-types';
import { parseSpaceRef } from '../src/db/space-ref';
import { commitSpaceWrites, loadSpaceSnapshot } from '../src/db/space-mutation';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';

const did = 'did:example:test';
const firstSpace = `at://${did}/space/com.example.notes/a`;
const secondSpace = `at://${did}/space/com.example.notes/b`;
const collection = 'com.example.note';
const nestedCollection = 'com.example.note.sub';
const pruneSpaceRecordVersions = async (...args: Parameters<typeof pruneSpaceRecordVersionsPage>) =>
  (await pruneSpaceRecordVersionsPage(...args)).pruned;

function create(pathCollection: string, rkey: string, text: string) {
  return { action: 'create' as const, collection: pathCollection, rkey, record: { $type: pathCollection, text } };
}

function update(pathCollection: string, rkey: string, text: string) {
  return { action: 'update' as const, collection: pathCollection, rkey, record: { $type: pathCollection, text } };
}

function remove(pathCollection: string, rkey: string) {
  return { action: 'delete' as const, collection: pathCollection, rkey };
}

async function expectError(action: () => Promise<unknown>, code: string): Promise<void> {
  try {
    await action();
    throw new Error('Expected failure');
  } catch (error) {
    expect(error).toBeInstanceOf(SpaceStorageError);
    expect((error as SpaceStorageError).code).toBe(code);
  }
}

describe('space snapshot leases', () => {
  it('keeps a binary-ordered snapshot stable across creates, updates and deletes', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    await createLocalSpace(env, secondSpace);
    const original = await applySpaceWrites(env, firstSpace, did, [
      create(collection, 'a', 'old a'), create(collection, 'b', 'old b'),
      create(nestedCollection, 'a', 'nested'),
    ]);
    await applySpaceWrites(env, secondSpace, did, [create(collection, 'a', 'other space')]);
    const lease = await acquireSpaceSnapshot(env, firstSpace, did);
    const first = await readSpaceSnapshotPage(env, lease, null, 1);
    expect(first.records[0].path).toBe(`${nestedCollection}/a`);
    await applySpaceWrites(env, firstSpace, did, [
      update(collection, 'a', 'new a'), remove(collection, 'b'), create(collection, 'c', 'new c'),
    ]);
    const second = await readSpaceSnapshotPage(env, lease, first.cursor, 1);
    const third = await readSpaceSnapshotPage(env, lease, second.cursor, 1);
    const end = await readSpaceSnapshotPage(env, lease, third.cursor, 1);
    const records = [...first.records, ...second.records, ...third.records];
    expect(records.map((item) => item.path)).toEqual([`${nestedCollection}/a`, `${collection}/a`, `${collection}/b`]);
    expect(dagCbor.decode(second.records[0].value)).toMatchObject({ text: 'old a' });
    expect(dagCbor.decode(third.records[0].value)).toMatchObject({ text: 'old b' });
    expect(end.records).toEqual([]);
    const state = applySpaceSetHashChanges(null, records.map((item) => ({
      action: 'add' as const, element: spaceRecordHashElement(item.collection, item.rkey, item.cid),
    })));
    expect(spaceSetHashDigest(state)).toEqual(lease.data);
    expect(lease.rev).toBe(original!.rev);
    const current = await acquireSpaceSnapshot(env, firstSpace, did);
    expect(current.rev > lease.rev).toBe(true);
    expect((await readSpaceSnapshotPage(env, current, null)).records.map((item) => item.path))
      .toEqual([`${nestedCollection}/a`, `${collection}/a`, `${collection}/c`]);
    await releaseSpaceSnapshot(env, lease);
    await releaseSpaceSnapshot(env, current);
  });

  it('preserves repeated-path semantics and a preexisting snapshot', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'before')]);
    const lease = await acquireSpaceSnapshot(env, firstSpace, did);
    const result = await applySpaceWrites(env, firstSpace, did, [
      update(collection, 'a', 'middle'), remove(collection, 'a'), create(collection, 'a', 'after'),
    ]);
    expect(result!.operations).toHaveLength(3);
    const previous = await readSpaceSnapshotPage(env, lease, null);
    expect(dagCbor.decode(previous.records[0].value)).toMatchObject({ text: 'before' });
    expect(dagCbor.decode((await getSpaceRecord(env, firstSpace, did, collection, 'a'))!.value)).toMatchObject({ text: 'after' });
    const versions = await env.ALTERAN_DB.prepare(
      'SELECT from_generation, until_generation FROM space_record_version WHERE space_ref = ? AND repo_did = ? ORDER BY from_generation',
    ).bind(firstSpace, did).all();
    expect(versions.results).toEqual([{ from_generation: 1, until_generation: 2 }, { from_generation: 2, until_generation: null }]);
  });

  it('bounds page bytes independently of the requested record count', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    const text = 'x'.repeat(600_000);
    await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', text)]);
    await applySpaceWrites(env, firstSpace, did, [create(collection, 'b', text)]);
    const lease = await acquireSpaceSnapshot(env, firstSpace, did);
    const first = await readSpaceSnapshotPage(env, lease, null, 100);
    const second = await readSpaceSnapshotPage(env, lease, first.cursor, 100);
    expect(first.records.map((item) => item.path)).toEqual([`${collection}/a`]);
    expect(second.records.map((item) => item.path)).toEqual([`${collection}/b`]);
    expect(first.records[0].value.byteLength).toBeGreaterThan(600_000);
  });

  it('captures lease identity before asynchronous authorization', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    await createLocalSpace(env, secondSpace);
    await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'first')]);
    await applySpaceWrites(env, secondSpace, did, [create(collection, 'b', 'second')]);
    const first = await acquireSpaceSnapshot(env, firstSpace, did);
    const second = await acquireSpaceSnapshot(env, secondSpace, did);
    const mutable = { ...first };
    const pendingPage = readSpaceSnapshotPage(env, mutable, null);
    Object.assign(mutable, second);
    const page = await pendingPage;
    expect(page.records.map((record) => record.path)).toEqual([`${collection}/a`]);
    Object.assign(mutable, first);
    const pendingRelease = releaseSpaceSnapshot(env, mutable);
    Object.assign(mutable, second);
    await pendingRelease;
    await expectError(() => readSpaceSnapshotPage(env, first, null), 'SpaceSnapshotUnavailable');
    expect((await readSpaceSnapshotPage(env, second, null)).records.map((record) => record.path))
      .toEqual([`${collection}/b`]);
  });

  it('fences expired or replaced leases and preserves versions until no live lease pins them', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'old')]);
    const lease = await acquireSpaceSnapshot(env, firstSpace, did);
    await applySpaceWrites(env, firstSpace, did, [update(collection, 'a', 'new')]);
    expect(await pruneSpaceRecordVersions(env, firstSpace, did)).toBe(0);
    expect(await pruneExpiredSpaceSnapshotLeases(env, firstSpace, did)).toBe(0);
    for (let index = 0; index < 4; index++) {
      const [page, pruned] = await Promise.all([
        readSpaceSnapshotPage(env, lease, null), pruneSpaceRecordVersions(env, firstSpace, did),
      ]);
      expect(dagCbor.decode(page.records[0].value)).toMatchObject({ text: 'old' });
      expect(pruned).toBe(0);
    }
    await releaseSpaceSnapshot(env, { ...lease, token: 'wrong' });
    expect((await readSpaceSnapshotPage(env, lease, null)).records).toHaveLength(1);
    await expectError(() => readSpaceSnapshotPage(env, { ...lease, epochId: 'wrong' }, null), 'SpaceSnapshotUnavailable');
    await env.ALTERAN_DB.prepare('UPDATE space_snapshot_lease SET expires_at = unixepoch() - 1 WHERE id = ?').bind(lease.id).run();
    const [expiredRead, pruned] = await Promise.all([
      readSpaceSnapshotPage(env, lease, null).then(() => 'unexpected', () => 'unavailable'),
      pruneSpaceRecordVersions(env, firstSpace, did),
    ]);
    expect(expiredRead).toBe('unavailable');
    expect(pruned).toBe(1);
    expect(await pruneSpaceRecordVersions(env, firstSpace, did)).toBe(0);
    await expectError(() => readSpaceSnapshotPage(env, lease, null), 'SpaceSnapshotUnavailable');
    expect(await pruneExpiredSpaceSnapshotLeases(env, firstSpace, did)).toBe(0);
    expect(await pruneSpaceRecordVersions(env, firstSpace, did)).toBe(0);
    expect(await pruneExpiredSpaceSnapshotLeases(env, firstSpace, did)).toBe(0);
    await releaseSpaceSnapshot(env, lease);
  });

  it('returns no rows when lease renewal is silently skipped', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'private')]);
    const lease = await acquireSpaceSnapshot(env, firstSpace, did);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER skip_snapshot_renew BEFORE UPDATE ON space_snapshot_lease BEGIN SELECT RAISE(IGNORE); END`,
    ).run();
    let selected: unknown;
    const database = new Proxy(env.ALTERAN_DB, {
      get(target, property) {
        if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
          const results = await target.batch(statements);
          selected = results[1].results;
          return results;
        };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    await expectError(() => readSpaceSnapshotPage({ ...env, ALTERAN_DB: database }, lease, null), 'SpaceSnapshotUnavailable');
    expect(selected).toEqual([]);
  });

  it('does not report an empty page when the renewed lease is no longer valid', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'private')]);
    const lease = await acquireSpaceSnapshot(env, firstSpace, did);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER expire_after_snapshot_renew AFTER UPDATE ON space_snapshot_lease
       BEGIN UPDATE space_snapshot_lease SET expires_at = unixepoch() - 1 WHERE id = NEW.id; END`,
    ).run();
    await expectError(() => readSpaceSnapshotPage(env, lease, null), 'SpaceSnapshotUnavailable');
  });

  it('rolls back the head and all record effects when a version insert is silently skipped', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    const first = await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'old')]);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER skip_version_insert BEFORE INSERT ON space_record_version BEGIN SELECT RAISE(IGNORE); END`,
    ).run();
    await expect(applySpaceWrites(env, firstSpace, did, [update(collection, 'a', 'new')])).rejects.toThrow();
    expect(dagCbor.decode((await getSpaceRecord(env, firstSpace, did, collection, 'a'))!.value)).toMatchObject({ text: 'old' });
    const head = await env.ALTERAN_DB.prepare('SELECT rev, generation FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(firstSpace, did).first();
    expect(head).toEqual({ rev: first!.rev, generation: first!.generation });
    const versions = await env.ALTERAN_DB.prepare('SELECT from_generation, until_generation FROM space_record_version WHERE space_ref = ?')
      .bind(firstSpace).all();
    expect(versions.results).toEqual([{ from_generation: 1, until_generation: null }]);
  });

  it('rolls back when a legacy blob-usage deletion is silently skipped', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    const first = await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'old')]);
    await seedLegacySpaceBlobUsage(env.ALTERAN_DB, firstSpace, did, collection, 'a', 'legacy-cid', 'legacy-key');
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER skip_space_blob_delete BEFORE DELETE ON space_blob_usage BEGIN SELECT RAISE(IGNORE); END`,
    ).run();
    await expect(applySpaceWrites(env, firstSpace, did, [update(collection, 'a', 'new')])).rejects.toThrow();
    expect(dagCbor.decode((await getSpaceRecord(env, firstSpace, did, collection, 'a'))!.value)).toMatchObject({ text: 'old' });
    expect(await env.ALTERAN_DB.prepare('SELECT rev, generation FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(firstSpace, did).first()).toEqual({ rev: first!.rev, generation: first!.generation });
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_blob_usage WHERE space_ref = ?')
      .bind(firstSpace).first())?.count).toBe(1);
  });

  it('does not advance the head when a touched current record changes without its version', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    const first = await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'old')]);
    const [cid, value] = await encodeRecordBlock({ $type: collection, text: 'new' });
    const write = { action: 'update' as const, collection, rkey: 'a', cid: cid.toString(), value, blobs: [] };
    const ref = parseSpaceRef(firstSpace);
    const snapshot = await loadSpaceSnapshot(env, ref, did, [write]);
    await env.ALTERAN_DB.prepare('DROP TRIGGER space_record_fence_update').run();
    await env.ALTERAN_DB.prepare('UPDATE space_record SET cid = ? WHERE space_ref = ? AND repo_did = ?')
      .bind('corrupt', firstSpace, did).run();
    expect((await commitSpaceWrites(env, ref, did, [write], snapshot)).tag).toBe('conflict');
    const head = await env.ALTERAN_DB.prepare('SELECT rev, generation FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(firstSpace, did).first();
    expect(head).toEqual({ rev: first!.rev, generation: first!.generation });
    await expect(getSpaceRecord(env, firstSpace, did, collection, 'a')).rejects.toThrow('Invalid Space record');
  });

  it('rejects forged records for an absent repo before creating its head', async () => {
    const env = await makeEnv();
    const remote = 'at://did:example:remote/space/com.example.notes/shared';
    const [cid, value] = await encodeRecordBlock({ $type: collection, text: 'new' });
    const write = { action: 'update' as const, collection, rkey: 'a', cid: cid.toString(), value, blobs: [] };
    const snapshot = { repo: null, records: new Map([[`${collection}/a`, { cid: cid.toString(), fromGeneration: 1 }]]) };
    await expectError(() => commitSpaceWrites(env, parseSpaceRef(remote), did, [write], snapshot), 'InvalidRepoState');
    for (const table of ['space', 'space_repo', 'space_epoch', 'space_record_version', 'space_op']) {
      expect((await env.ALTERAN_DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first())?.count).toBe(0);
    }
  });

  it('requires local repo ownership and derives authority from the space URI', async () => {
    const env = await makeEnv();
    const remoteRepo = 'did:example:remote';
    const ref = parseSpaceRef(firstSpace);
    const [cid, value] = await encodeRecordBlock({ $type: collection, text: 'new' });
    const write = { action: 'create' as const, collection, rkey: 'a', cid: cid.toString(), value, blobs: [] };
    const empty = { repo: null, records: new Map() };
    await expectError(() => loadSpaceSnapshot(env, ref, remoteRepo, [write]), 'RepoNotFound');
    await expectError(() => commitSpaceWrites(env, ref, remoteRepo, [write], empty), 'RepoNotFound');
    const forged = { ...ref, authorityDid: remoteRepo };
    expect((await commitSpaceWrites(env, forged, did, [write], empty)).tag).toBe('missingSpace');
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_repo').first())?.count).toBe(0);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space').first())?.count).toBe(0);
  });

  it('rejects prepared-write accessors without reading them', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    const ref = parseSpaceRef(firstSpace);
    const [cid, value] = await encodeRecordBlock({ $type: collection, text: 'new' });
    const write = { action: 'create' as const, collection, rkey: 'a', cid: cid.toString(), value, blobs: [] };
    const snapshot = await loadSpaceSnapshot(env, ref, did, [write]);
    let getterReads = 0;
    for (const key of ['action', 'collection', 'rkey', 'cid', 'value', 'blobs'] as const) {
      const forged = { ...write };
      Object.defineProperty(forged, key, { enumerable: true, get: () => { getterReads++; return write[key]; } });
      await expectError(() => commitSpaceWrites(env, ref, did, [forged], snapshot), 'InvalidRequest');
    }
    expect(getterReads).toBe(0);
    for (const table of ['space_repo', 'space_epoch', 'space_record', 'space_record_version', 'space_op']) {
      expect((await env.ALTERAN_DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first())?.count).toBe(0);
    }
  });

  it('captures mutable commit inputs before asynchronous authorization', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    await createLocalSpace(env, secondSpace);
    await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'old')]);
    const [cid, value] = await encodeRecordBlock({ $type: collection, text: 'new' });
    const write = { action: 'update' as const, collection, rkey: 'a', cid: cid.toString(), value, blobs: [] };
    const ref = { ...parseSpaceRef(firstSpace) };
    const loaded = await loadSpaceSnapshot(env, ref, did, [write]);
    await expectError(() => commitSpaceWrites(env, ref, did, [write], {
      ...loaded, repo: { ...loaded.repo!, setHash: new Uint8Array(2047) },
    }), 'InvalidRepoState');
    const snapshot = { repo: { ...loaded.repo!, setHash: new Uint8Array(loaded.repo!.setHash) }, records: new Map(loaded.records) };
    const pending = commitSpaceWrites(env, ref, did, [write], snapshot);
    ref.ref = secondSpace;
    snapshot.repo.setHash.fill(0);
    snapshot.records.clear();
    write.value.fill(0);
    const result = await pending;
    expect(result.tag).toBe('committed');
    if (result.tag !== 'committed') throw new Error('Expected commit');
    const expected = applySpaceSetHashChanges(null, [{ action: 'add', element: spaceRecordHashElement(collection, 'a', cid.toString()) }]);
    expect(result.commit.data).toEqual(spaceSetHashDigest(expected));
    expect(dagCbor.decode((await getSpaceRecord(env, firstSpace, did, collection, 'a'))!.value)).toMatchObject({ text: 'new' });
    expect(await getSpaceRecord(env, secondSpace, did, collection, 'a')).toBeNull();
  });

  it('rejects overlapping intervals and mutation or deletion of immutable versions', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'old')]);
    await applySpaceWrites(env, firstSpace, did, [update(collection, 'a', 'new')]);
    await expect(env.ALTERAN_DB.prepare(
      `INSERT INTO space_record_version
       SELECT epoch_id, space_ref, repo_did, path, collection, rkey, 1, 3, cid, value_cbor, value_size, repo_rev
       FROM space_record_version WHERE space_ref = ? AND from_generation = 2`,
    ).bind(firstSpace).run()).rejects.toThrow();
    await expect(env.ALTERAN_DB.prepare('UPDATE space_record_version SET cid = ? WHERE space_ref = ?')
      .bind('invalid', firstSpace).run()).rejects.toThrow();
    await expect(env.ALTERAN_DB.prepare('DELETE FROM space_record_version WHERE space_ref = ? AND until_generation IS NULL')
      .bind(firstSpace).run()).rejects.toThrow();
  });

  it('binds leases and pruning to the local repo and space', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, firstSpace);
    await createLocalSpace(env, secondSpace);
    await applySpaceWrites(env, firstSpace, did, [create(collection, 'a', 'one')]);
    await applySpaceWrites(env, secondSpace, did, [create(collection, 'a', 'two')]);
    const lease = await acquireSpaceSnapshot(env, firstSpace, did);
    await expectError(() => acquireSpaceSnapshot(env, firstSpace, 'did:example:other'), 'RepoNotFound');
    await expectError(() => readSpaceSnapshotPage(env, { ...lease, spaceRef: secondSpace }, null), 'SpaceSnapshotUnavailable');
    await expectError(() => pruneSpaceRecordVersions(env, firstSpace, 'did:example:other'), 'RepoNotFound');
    await env.ALTERAN_DB.prepare('UPDATE space SET deleted_at = unixepoch() WHERE space_ref = ?').bind(firstSpace).run();
    await expectError(() => readSpaceSnapshotPage(env, lease, null), 'SpaceSnapshotUnavailable');
  });
});
