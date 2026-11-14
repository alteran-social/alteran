import { describe, it } from './helpers/bdd';
import { expect } from '@std/expect';
import type { APIContext } from 'astro';
import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import { makeEnv } from './helpers/env';
import { seedLegacySpaceBlobUsage } from './helpers/space-legacy';
import { applySpaceWrites, createLocalSpace, getSpaceRecord } from '../src/db/space-store';
import { parseSpaceRef } from '../src/db/space-ref';
import { commitSpaceWrites, loadSpaceSnapshot } from '../src/db/space-mutation';
import { nextSpaceRevision } from '../src/db/space-tid';
import { SpaceStorageError, type PreparedSpaceWrite } from '../src/db/space-types';
import { putBlobRef, deleteBlobByKey, deleteUnreferencedBlobKeys, deleteUnreferencedBlobRef, listOrphanBlobRefs, setRecordBlobUsage, sweepEligibleUnreferencedBlobKeys } from '../src/db/dal';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';
import { collectBlobRefs, type BlobReference } from '../src/lib/repo-write-data';
import { GET as getPublicBlob } from '../src/pages/xrpc/com.atproto.sync.getBlob';
import { GET as listPublicBlobs } from '../src/pages/xrpc/com.atproto.sync.listBlobs';
import { applySpaceSetHashChanges, spaceRecordHashElement, spaceSetHashDigest } from '../src/lib/spaces/lthash';

const did = 'did:example:test';
const collection = 'com.example.note';
const spaceA = `at://${did}/space/com.example.notes/a`;
const spaceB = `at://${did}/space/com.example.notes/b`;
const remoteSpace = 'at://did:example:remote/space/com.example.notes/shared';

function record(text: string) {
  return { $type: collection, text };
}

function create(rkey: string, value: unknown) {
  return { action: 'create' as const, collection, rkey, record: value };
}

function update(rkey: string, value: unknown) {
  return { action: 'update' as const, collection, rkey, record: value };
}

function remove(rkey: string) {
  return { action: 'delete' as const, collection, rkey };
}

async function prepared(rkey: string, value: unknown): Promise<PreparedSpaceWrite> {
  const [cid, bytes] = await encodeRecordBlock(value);
  const blobs: BlobReference[] = [];
  collectBlobRefs(value, blobs);
  return { action: 'create', collection, rkey, cid: cid.toString(), value: bytes, blobs };
}

async function expectError(action: () => Promise<unknown>, code: string): Promise<void> {
  try {
    await action();
    throw new Error('Expected storage operation to fail');
  } catch (error) {
    expect(error).toBeInstanceOf(SpaceStorageError);
    expect((error as SpaceStorageError).code).toBe(code);
  }
}

async function seedSpaceBlobUsage(env: Awaited<ReturnType<typeof makeEnv>>, space: string, cid: string, key: string): Promise<void> {
  // Existing usage rows must remain protected while blob-bearing writes are disabled.
  await seedLegacySpaceBlobUsage(env.ALTERAN_DB, space, did, collection, 'private', cid, key);
}

describe('space storage', () => {
  it('requires a canonical space reference', () => {
    expect(parseSpaceRef(spaceA)).toEqual({ ref: spaceA, authorityDid: did, spaceType: 'com.example.notes', skey: 'a' });
    for (const invalid of [
      `${spaceA}/`, `${spaceA}?q=1`, `${spaceA}#/fragment`, `${spaceA}/${did}/${collection}/record`,
      'at://example.com/space/com.example.notes/a',
      `at://${did}/space/com.example.notes/..`,
      `at://${did}/space/com.example.notes/%61`,
    ]) {
      expect(() => parseSpaceRef(invalid)).toThrow(SpaceStorageError);
    }
  });
  it('keeps identical paths in separate spaces and out of the public repository', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, spaceA);
    await createLocalSpace(env, spaceB);
    const first = await applySpaceWrites(env, spaceA, did, [create('same', record('private A'))]);
    const second = await applySpaceWrites(env, spaceB, did, [create('same', record('private B'))]);
    expect(first?.generation).toBe(1);
    expect(second?.generation).toBe(1);
    const a = await getSpaceRecord(env, spaceA, did, collection, 'same');
    const b = await getSpaceRecord(env, spaceB, did, collection, 'same');
    expect(dagCbor.decode(a!.value)).toMatchObject(record('private A'));
    expect(dagCbor.decode(b!.value)).toMatchObject(record('private B'));
    expect(a!.cid).not.toBe(b!.cid);
    for (const table of ['record', 'repo_root', 'blockstore', 'commit_log']) {
      const row = await env.ALTERAN_DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{ count: number }>();
      expect(row?.count).toBe(0);
    }
    await expectError(() => getSpaceRecord(env, spaceA, 'did:example:other', collection, 'same'), 'RepoNotFound');
  });

  it('captures writes and nested records before awaiting account authorization', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, spaceA);
    const link = CID.createV1(0x55, await sha256.digest(new TextEncoder().encode('linked'))).toString();
    const input = { $type: collection, nested: { text: 'original', bytes: { $bytes: 'YWJj' }, link: { $link: link } } };
    const write = create('first', input);
    const writes = [write];
    let resolveDid: (value: string) => void = () => { throw new Error('Missing resolver'); };
    const secret = new Promise<string>((resolve) => { resolveDid = resolve; });
    const pending = applySpaceWrites({ ...env, PDS_DID: { get: () => secret } }, spaceA, did, writes);
    write.rkey = 'changed';
    input.nested.text = 'changed';
    input.nested.bytes.$bytes = 'eHl6';
    input.nested.link.$link = CID.createV1(0x55, await sha256.digest(new TextEncoder().encode('other'))).toString();
    writes.splice(0, 1, create('second', record('other')));
    resolveDid(did);
    await pending;
    const stored = await getSpaceRecord(env, spaceA, did, collection, 'first');
    const decoded = dagCbor.decode(stored!.value) as { nested: { text: string; bytes: Uint8Array; link: CID } };
    expect(decoded.nested.text).toBe('original');
    expect([...decoded.nested.bytes]).toEqual([97, 98, 99]);
    expect(decoded.nested.link.toString()).toBe(link);
    expect(await getSpaceRecord(env, spaceA, did, collection, 'changed')).toBeNull();
    expect(await getSpaceRecord(env, spaceA, did, collection, 'second')).toBeNull();
  });

  it('rejects complex record values and accessors without reading them', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, spaceA);
    let getterCalls = 0;
    const accessor = Object.defineProperty({}, 'value', { enumerable: true, get: () => { getterCalls++; return 'secret'; } });
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    const link = CID.createV1(0x55, await sha256.digest(new TextEncoder().encode('linked')));
    for (const value of [accessor, cycle, new Uint8Array([1, 2]), link, new Date()]) {
      await expectError(() => applySpaceWrites(env, spaceA, did, [create('bad', { $type: collection, value })]), 'InvalidRequest');
    }
    expect(getterCalls).toBe(0);
    expect(await getSpaceRecord(env, spaceA, did, collection, 'bad')).toBeNull();
  });

  it('bounds input size, node count and nesting before asynchronous work', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, spaceA);
    let secretReads = 0;
    const guardedEnv = { ...env, PDS_DID: { get: () => { secretReads++; return Promise.resolve(did); } } };
    const tooDeep: Record<string, unknown> = {};
    let current = tooDeep;
    for (let index = 0; index < 101; index++) {
      const child: Record<string, unknown> = {};
      current.child = child;
      current = child;
    }
    for (const value of ['x'.repeat(4_000_001), Array(200_001).fill(null), tooDeep]) {
      await expectError(() => applySpaceWrites(guardedEnv, spaceA, did, [create('bad', { $type: collection, value })]), 'InvalidRequest');
    }
    expect(secretReads).toBe(0);
    expect(await getSpaceRecord(env, spaceA, did, collection, 'bad')).toBeNull();
  });

  it('applies repeated paths in order and rolls back an invalid batch', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, spaceA);
    const first = await applySpaceWrites(env, spaceA, did, [create('key', record('one'))]);
    const same = await applySpaceWrites(env, spaceA, did, [update('key', record('one'))]);
    expect(same!.rev > first!.rev).toBe(true);
    expect(same!.data).toEqual(first!.data);
    expect(same!.operations[0].cid).toBe(same!.operations[0].prev);
    const committed = await applySpaceWrites(env, spaceA, did, [
      update('key', record('two')),
      remove('key'),
      create('key', record('three')),
    ]);
    expect(committed!.operations).toHaveLength(3);
    expect(committed!.operations[1].cid).toBeNull();
    expect(committed!.operations[2].prev).toBeNull();
    expect(dagCbor.decode((await getSpaceRecord(env, spaceA, did, collection, 'key'))!.value)).toMatchObject(record('three'));
    await expectError(() => applySpaceWrites(env, spaceA, did, [
      create('other', record('will not persist')),
      create('key', record('duplicate')),
    ]), 'RecordAlreadyExists');
    expect(await getSpaceRecord(env, spaceA, did, collection, 'other')).toBeNull();
    const repo = await env.ALTERAN_DB.prepare('SELECT rev, generation FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(spaceA, did).first<{ rev: string; generation: number }>();
    expect(repo).toEqual({ rev: committed!.rev, generation: 3 });
    expect(await applySpaceWrites(env, spaceA, did, [])).toBeNull();
  });

  it('makes losing initial writers inert and retries concurrent writers', async () => {
    const env = await makeEnv();
    const ref = parseSpaceRef(remoteSpace);
    const one = [await prepared('one', record('one'))];
    const two = [await prepared('two', record('two'))];
    const [firstSnapshot, secondSnapshot] = await Promise.all([
      loadSpaceSnapshot(env, ref, did, one),
      loadSpaceSnapshot(env, ref, did, two),
    ]);
    expect((await commitSpaceWrites(env, ref, did, one, firstSnapshot)).tag).toBe('committed');
    expect((await commitSpaceWrites(env, ref, did, two, secondSnapshot)).tag).toBe('conflict');
    expect(await getSpaceRecord(env, remoteSpace, did, collection, 'two')).toBeNull();
    const ops = await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_op WHERE space_ref = ?').bind(remoteSpace)
      .first<{ count: number }>();
    expect(ops?.count).toBe(1);
    await Promise.all([
      applySpaceWrites(env, remoteSpace, did, [create('two', record('two'))]),
      applySpaceWrites(env, remoteSpace, did, [create('three', record('three'))]),
    ]);
    const rows = await env.ALTERAN_DB.prepare('SELECT collection, rkey, cid FROM space_record WHERE space_ref = ? AND repo_did = ?')
      .bind(remoteSpace, did).all<{ collection: string; rkey: string; cid: string }>();
    expect(rows.results).toHaveLength(3);
    const stateRow = await env.ALTERAN_DB.prepare('SELECT generation, set_hash FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(remoteSpace, did).first<{ generation: number; set_hash: number[] }>();
    expect(stateRow?.generation).toBe(3);
    const expected = applySpaceSetHashChanges(null, rows.results.map((row) => ({
      action: 'add' as const,
      element: spaceRecordHashElement(row.collection, row.rkey, row.cid),
    })));
    expect(Uint8Array.from(stateRow!.set_hash)).toEqual(expected);
    expect(spaceSetHashDigest(Uint8Array.from(stateRow!.set_hash))).toEqual(spaceSetHashDigest(expected));
  });

  it('retains the repo tombstone and rejects a stale same-generation nonce', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, spaceA);
    const first = await applySpaceWrites(env, spaceA, did, [create('key', record('initial'))]);
    const ref = parseSpaceRef(spaceA);
    const staleCreate = await prepared('key', record('stale writer'));
    if (staleCreate.action === 'delete') throw new Error('Expected prepared create');
    const staleWrite: PreparedSpaceWrite = { ...staleCreate, action: 'update' };
    const snapshot = await loadSpaceSnapshot(env, ref, did, [staleWrite]);

    const replacementId = crypto.randomUUID();
    await expect(env.ALTERAN_DB.prepare('DELETE FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(spaceA, did).run()).rejects.toThrow();
    await env.ALTERAN_DB.prepare('DROP TRIGGER space_repo_fence_update').run();
    await env.ALTERAN_DB.prepare('UPDATE space_repo SET mutation_id = ? WHERE space_ref = ? AND repo_did = ?')
      .bind(replacementId, spaceA, did).run();
    expect((await commitSpaceWrites(env, ref, did, [staleWrite], snapshot)).tag).toBe('conflict');
    const stored = await getSpaceRecord(env, spaceA, did, collection, 'key');
    expect(dagCbor.decode(stored!.value)).toMatchObject(record('initial'));
    const repo = await env.ALTERAN_DB.prepare(
      'SELECT rev, generation, mutation_id, set_hash FROM space_repo WHERE space_ref = ? AND repo_did = ?',
    ).bind(spaceA, did).first<{ rev: string; generation: number; mutation_id: string; set_hash: number[] }>();
    expect(repo!.rev).toBe(first!.rev);
    expect(repo!.generation).toBe(1);
    expect(repo!.mutation_id).toBe(replacementId);
    expect(Uint8Array.from(repo!.set_hash)).toEqual(first!.setHash);
    const operations = await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_op WHERE space_ref = ?')
      .bind(spaceA).first<{ count: number }>();
    expect(operations!.count).toBe(1);
  });

  it('does not recreate a deleted local space or reset its repo revision', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, spaceA);
    const commit = await applySpaceWrites(env, spaceA, did, [create('key', record('before'))]);
    await env.ALTERAN_DB.prepare('UPDATE space SET deleted_at = ? WHERE space_ref = ?').bind(Date.now(), spaceA).run();
    await expectError(() => applySpaceWrites(env, spaceA, did, [create('other', record('after'))]), 'SpaceNotFound');
    await expectError(() => createLocalSpace(env, spaceA), 'SpaceAlreadyExists');
    expect(await getSpaceRecord(env, spaceA, did, collection, 'key')).toBeNull();
    const row = await env.ALTERAN_DB.prepare('SELECT rev, generation FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(spaceA, did).first<{ rev: string; generation: number }>();
    expect(row).toEqual({ rev: commit!.rev, generation: 1 });
    const first = nextSpaceRevision(null, 2_000_000_000_000);
    expect(nextSpaceRevision(first, 1) > first).toBe(true);
    expect(() => nextSpaceRevision('jzzzzzzzzzzzz', 1)).toThrow(SpaceStorageError);
  });

  it('rejects blob-bearing writes without creating a remote space or repo', async () => {
    const env = await makeEnv();
    const bytes = new TextEncoder().encode('missing blob');
    const cid = CID.createV1(0x55, await sha256.digest(bytes)).toString();
    const blob = { $type: 'blob', ref: { $link: cid }, mimeType: 'text/plain', size: bytes.length };
    await expectError(() => applySpaceWrites(env, remoteSpace, did, [create('key', { ...record('test'), blob })]), 'BlobIntegrityUnavailable');
    for (const table of ['space', 'space_repo', 'space_record', 'space_op', 'space_blob_usage']) {
      const row = await env.ALTERAN_DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{ count: number }>();
      expect(row?.count).toBe(0);
    }
    await putBlobRef(env, did, cid, `blobs/by-cid/${cid}`, 'text/plain', bytes.length);
    await expectError(() => applySpaceWrites(env, remoteSpace, did, [create('key', { ...record('test'), blob })]), 'BlobIntegrityUnavailable');
    expect(await env.ALTERAN_DB.prepare('SELECT 1 FROM space_repo WHERE space_ref = ?').bind(remoteSpace).first()).toBeNull();
  });

  it('commits more than 100 paths without exceeding D1 parameter limits', async () => {
    const env = await makeEnv();
    const writes = Array.from({ length: 101 }, (_, index) => create(`record${index}`, record(`value${index}`)));
    const result = await applySpaceWrites(env, remoteSpace, did, writes);
    expect(result?.operations).toHaveLength(101);
    const rows = await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_record WHERE space_ref = ?')
      .bind(remoteSpace).first<{ count: number }>();
    expect(rows?.count).toBe(101);
  });

  it('rolls back the repo, records, and space registration when a batch statement fails', async () => {
    const env = await makeEnv();
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER fail_space_op BEFORE INSERT ON space_op
       BEGIN SELECT RAISE(ABORT, 'forced failure'); END`,
    ).run();
    await expect(applySpaceWrites(env, remoteSpace, did, [create('key', record('no partial write'))])).rejects.toThrow();
    for (const table of ['space', 'space_repo', 'space_record', 'space_op', 'space_blob_usage']) {
      const row = await env.ALTERAN_DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{ count: number }>();
      expect(row?.count).toBe(0);
    }
  });

  it('rejects blob writes for correct and same-sized corrupt objects, even during replacement', async () => {
    const env = await makeEnv();
    const bytes = new TextEncoder().encode('good');
    const corrupt = new TextEncoder().encode('evil');
    const cid = CID.createV1(0x55, await sha256.digest(bytes)).toString();
    const key = `blobs/by-cid/${cid}`;
    await putBlobRef(env, did, cid, key, 'text/plain', bytes.length);
    await env.ALTERAN_BLOBS.put(key, bytes);
    const blob = { $type: 'blob', ref: { $link: cid }, mimeType: 'text/plain', size: bytes.length };
    const write = () => applySpaceWrites(env, remoteSpace, did, [create('key', { ...record('test'), blob })]);
    await expectError(write, 'BlobIntegrityUnavailable');
    await env.ALTERAN_BLOBS.put(key, corrupt);
    await expectError(write, 'BlobIntegrityUnavailable');
    await Promise.all([
      expectError(write, 'BlobIntegrityUnavailable'),
      env.ALTERAN_BLOBS.put(key, bytes),
    ]);
    for (const table of ['space', 'space_repo', 'space_record', 'space_op', 'space_blob_usage']) {
      const row = await env.ALTERAN_DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{ count: number }>();
      expect(row?.count).toBe(0);
    }
  });

  it('rejects encoded blobs and oversized records through the lower-level commit path', async () => {
    const env = await makeEnv();
    const first = await applySpaceWrites(env, remoteSpace, did, [create('first', record('existing'))]);
    const ref = parseSpaceRef(remoteSpace);
    const bytes = new TextEncoder().encode('blob');
    const cid = CID.createV1(0x55, await sha256.digest(bytes)).toString();
    const blob = { $type: 'blob', ref: { $link: cid }, mimeType: 'text/plain', size: bytes.length };
    await expectError(() => applySpaceWrites(env, remoteSpace, did, [
      create('other', record('must not commit')),
      update('first', { ...record('not committed'), blob }),
    ]), 'BlobIntegrityUnavailable');
    expect(await getSpaceRecord(env, remoteSpace, did, collection, 'other')).toBeNull();
    const write = await prepared('second', { ...record('not committed'), nested: [{ blob }] });
    if (write.action === 'delete') throw new Error('Expected prepared create');
    const snapshot = await loadSpaceSnapshot(env, ref, did, [write]);
    await expectError(() => commitSpaceWrites(env, ref, did, [write], snapshot), 'BlobIntegrityUnavailable');
    const forged = { ...write, blobs: [] };
    await expectError(() => commitSpaceWrites(env, ref, did, [forged], snapshot), 'BlobIntegrityUnavailable');
    const legacy = await prepared('second', { ...record('not committed'), nested: { cid, mimeType: 'text/plain' } });
    await expectError(() => commitSpaceWrites(env, ref, did, [legacy], snapshot), 'BlobIntegrityUnavailable');
    const oversized = { ...forged, value: new Uint8Array(1_000_001) };
    await expectError(() => commitSpaceWrites(env, ref, did, [oversized], snapshot), 'InvalidRequest');
    const safe = await prepared('second', record('safe'));
    if (safe.action === 'delete') throw new Error('Expected prepared create');
    await expectError(() => commitSpaceWrites(env, ref, did, [{ ...safe, cid: write.cid }], snapshot), 'InvalidRequest');
    const noncanonical = { ...safe, value: Uint8Array.from([
      0xa3, ...dagCbor.encode('$type'), ...dagCbor.encode(collection),
      ...dagCbor.encode('b'), ...dagCbor.encode(1), ...dagCbor.encode('a'), ...dagCbor.encode(2),
    ]) };
    await expectError(() => commitSpaceWrites(env, ref, did, [noncanonical], snapshot), 'InvalidRequest');
    await expectError(() => commitSpaceWrites(env, ref, did, [], snapshot), 'InvalidRequest');
    await expectError(() => commitSpaceWrites(env, ref, did, Array(201).fill(safe), snapshot), 'InvalidRequest');
    expect(await getSpaceRecord(env, remoteSpace, did, collection, 'second')).toBeNull();
    const repo = await env.ALTERAN_DB.prepare('SELECT rev, generation FROM space_repo WHERE space_ref = ? AND repo_did = ?')
      .bind(remoteSpace, did).first<{ rev: string; generation: number }>();
    expect(repo).toEqual({ rev: first!.rev, generation: first!.generation });
    const operations = await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_op WHERE space_ref = ?')
      .bind(remoteSpace).first<{ count: number }>();
    expect(operations!.count).toBe(1);
  });

  it('retains a private blob after its public reference is removed without serving it publicly', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, spaceA);
    await createLocalSpace(env, spaceB);
    const bytes = new TextEncoder().encode('shared blob');
    const cid = CID.createV1(0x55, await sha256.digest(bytes)).toString();
    const key = `blobs/by-cid/${cid}`;
    await putBlobRef(env, did, cid, key, 'text/plain', bytes.length);
    await env.ALTERAN_BLOBS.put(key, bytes);
    const publicUri = `at://${did}/${collection}/public`;
    await setRecordBlobUsage(env, did, publicUri, [key]);
    await applySpaceWrites(env, spaceA, did, [create('private', record('private'))]);
    await applySpaceWrites(env, spaceB, did, [create('private', record('other space'))]);
    await seedSpaceBlobUsage(env, spaceA, cid, key);
    await seedSpaceBlobUsage(env, spaceB, cid, key);
    expect(dagCbor.decode((await getSpaceRecord(env, spaceB, did, collection, 'private'))!.value))
      .toMatchObject(record('other space'));
    const usages = await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_blob_usage WHERE repo_did = ? AND cid = ?')
      .bind(did, cid).first<{ count: number }>();
    expect(usages?.count).toBe(2);
    const url = new URL(`https://pds.example/xrpc/com.atproto.sync.getBlob?did=${did}&cid=${cid}`);
    const publicRead = () => getPublicBlob({ locals: { env }, url } as unknown as APIContext);
    expect((await publicRead()).status).toBe(200);
    await setRecordBlobUsage(env, did, publicUri, []);
    expect((await publicRead()).status).toBe(400);
    const listUrl = new URL(`https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${did}`);
    const listed = await listPublicBlobs({ locals: { env }, url: listUrl } as unknown as APIContext);
    expect(listed.status).toBe(200);
    expect(await listed.json()).toEqual({ cids: [] });
    await deleteUnreferencedBlobRef(env, did, cid);
    await deleteBlobByKey(env, key);
    expect(await env.ALTERAN_DB.prepare('SELECT cid FROM blob WHERE did = ? AND cid = ?').bind(did, cid).first()).not.toBeNull();
    await env.ALTERAN_DB.prepare('UPDATE blob SET uploaded_at = ? WHERE did = ? AND cid = ?')
      .bind(Date.now() - 7_200_000, did, cid).run();
    expect(await listOrphanBlobRefs(env, { did })).toEqual([]);
    await env.ALTERAN_BLOBS.delete(key);
    expect(await sweepEligibleUnreferencedBlobKeys(env, { did })).toBe(0);
    await applySpaceWrites(env, spaceA, did, [remove('private')]);
    expect(await sweepEligibleUnreferencedBlobKeys(env, { did })).toBe(0);
    await applySpaceWrites(env, spaceB, did, [remove('private')]);
    expect(await sweepEligibleUnreferencedBlobKeys(env, { did })).toBe(1);
  });

  it('retains a private CID when its blob metadata moves to a different key', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, spaceA);
    const bytes = new TextEncoder().encode('relocated blob');
    const cid = CID.createV1(0x55, await sha256.digest(bytes)).toString();
    const oldKey = `blobs/by-cid/${cid}`;
    const newKey = `${oldKey}-relocated`;
    await putBlobRef(env, did, cid, oldKey, 'text/plain', bytes.length);
    await env.ALTERAN_BLOBS.put(oldKey, bytes);
    await applySpaceWrites(env, spaceA, did, [create('private', record('private'))]);
    await seedSpaceBlobUsage(env, spaceA, cid, oldKey);
    await env.ALTERAN_BLOBS.put(newKey, bytes);
    await putBlobRef(env, did, cid, newKey, 'text/plain', bytes.length);
    await env.ALTERAN_DB.prepare('UPDATE blob SET uploaded_at = ? WHERE did = ? AND cid = ?')
      .bind(Date.now() - 7_200_000, did, cid).run();
    const association = await env.ALTERAN_DB.prepare('SELECT key FROM space_blob_usage WHERE repo_did = ? AND cid = ?')
      .bind(did, cid).first<{ key: string }>();
    expect(association!.key).toBe(oldKey);
    expect(await listOrphanBlobRefs(env, { did })).toEqual([]);
    expect(await listOrphanBlobRefs(env)).toEqual([]);
    await deleteUnreferencedBlobRef(env, did, cid);
    await deleteBlobByKey(env, newKey);
    expect(await env.ALTERAN_DB.prepare('SELECT key FROM blob WHERE did = ? AND cid = ?').bind(did, cid).first())
      .toEqual({ key: newKey });
    const otherDid = 'did:example:other';
    await putBlobRef(env, otherDid, cid, newKey, 'text/plain', bytes.length);
    await deleteUnreferencedBlobRef(env, otherDid, cid);
    expect(await env.ALTERAN_DB.prepare('SELECT 1 FROM blob WHERE did = ? AND cid = ?').bind(otherDid, cid).first())
      .toBeNull();
    const url = new URL(`https://pds.example/xrpc/com.atproto.sync.getBlob?did=${did}&cid=${cid}`);
    expect((await getPublicBlob({ locals: { env }, url } as unknown as APIContext)).status).toBe(400);
    await env.ALTERAN_BLOBS.delete(newKey);
    expect(await deleteUnreferencedBlobKeys(env, [{ did, key: newKey }])).toBe(0);
    expect(await sweepEligibleUnreferencedBlobKeys(env, { did })).toBe(0);
    expect(await env.ALTERAN_DB.prepare('SELECT key FROM blob WHERE did = ? AND cid = ?').bind(did, cid).first())
      .toEqual({ key: newKey });
    await applySpaceWrites(env, spaceA, did, [remove('private')]);
    expect(await listOrphanBlobRefs(env, { did })).toEqual([{ did, key: newKey }]);
    expect(await deleteUnreferencedBlobKeys(env, [{ did, key: newKey }])).toBe(1);
  });
});
