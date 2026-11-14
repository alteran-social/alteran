import type { D1PreparedStatement } from '@cloudflare/workers-types';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { isValidNsid, isValidRecordKey } from '@atproto/syntax-spaces';
import type { Env } from '../env';
import {
  applySpaceSetHashChanges,
  spaceRecordHashElement,
  spaceSetHashDigest,
  type SpaceSetHashChange,
} from '../lib/spaces/lthash';
import { nextSpaceRevision } from './space-tid';
import {
  MAX_SPACE_WRITE_BYTES,
  MAX_SPACE_WRITES,
  SpaceStorageError,
  type PreparedSpaceWrite,
  type SpaceCommit,
  type SpaceOperation,
  type SpaceRef,
  type SpaceRepoState,
} from './space-types';

type Snapshot = {
  readonly repo: (SpaceRepoState & { readonly mutationId: string }) | null;
  readonly records: ReadonlyMap<string, string>;
};

type CommitResult =
  | { readonly tag: 'committed'; readonly commit: SpaceCommit }
  | { readonly tag: 'conflict' | 'missingSpace' };

const GUARD = `EXISTS (
  SELECT 1 FROM space_repo
  WHERE space_ref = ? AND repo_did = ? AND generation = ? AND mutation_id = ?
)`;

const SPACE_AVAILABLE = `(
  EXISTS (SELECT 1 FROM space WHERE space_ref = ? AND deleted_at IS NULL)
  OR (? <> ? AND NOT EXISTS (SELECT 1 FROM space WHERE space_ref = ?))
)`;

export async function loadSpaceSnapshot(
  env: Env,
  ref: SpaceRef,
  repoDid: string,
  writes: readonly PreparedSpaceWrite[],
): Promise<Snapshot> {
  const paths = JSON.stringify(writes.map(({ collection, rkey }) => [collection, rkey]));
  const [spaceResult, repoResult, recordResult] = await env.ALTERAN_DB.batch([
    env.ALTERAN_DB.prepare('SELECT deleted_at FROM space WHERE space_ref = ?').bind(ref.ref),
    env.ALTERAN_DB.prepare(
      'SELECT rev, set_hash, generation, mutation_id FROM space_repo WHERE space_ref = ? AND repo_did = ?',
    ).bind(ref.ref, repoDid),
    env.ALTERAN_DB.prepare(
      `SELECT collection, rkey, cid FROM space_record
       WHERE space_ref = ? AND repo_did = ?
         AND EXISTS (
           SELECT 1 FROM json_each(?) path
           WHERE json_extract(path.value, '$[0]') = space_record.collection
             AND json_extract(path.value, '$[1]') = space_record.rkey
         )`,
    ).bind(ref.ref, repoDid, paths),
  ]);
  const space = spaceResult.results?.[0] as { deleted_at: number | null } | undefined;
  if ((space && space.deleted_at !== null) || (!space && ref.authorityDid === repoDid)) {
    throw new SpaceStorageError('SpaceNotFound', 'Space does not exist or is deleted');
  }
  const row = repoResult.results?.[0] as {
    rev: string | null;
    set_hash: number[];
    generation: number;
    mutation_id: string;
  } | undefined;
  const repo = row ? decodeRepoState(row) : null;
  const records = new Map<string, string>();
  for (const record of recordResult.results ?? []) {
    const typed = record as { collection: string; rkey: string; cid: string };
    records.set(recordPath(typed.collection, typed.rkey), typed.cid);
  }
  return { repo, records };
}

export async function commitSpaceWrites(
  env: Env,
  ref: SpaceRef,
  repoDid: string,
  writes: readonly PreparedSpaceWrite[],
  snapshot: Snapshot,
): Promise<CommitResult> {
  if (writes.length === 0 || writes.length > MAX_SPACE_WRITES) {
    throw new SpaceStorageError('InvalidRequest', 'Invalid number of space writes');
  }
  let recordBytes = 0;
  const stagedWrites: PreparedSpaceWrite[] = [];
  for (const write of writes) {
    if (!isValidNsid(write.collection) || !isValidRecordKey(write.rkey) ||
      (write.action !== 'create' && write.action !== 'update' && write.action !== 'delete')) {
      throw new SpaceStorageError('InvalidRequest', 'Invalid space write');
    }
    if (write.action === 'delete') {
      stagedWrites.push({ ...write });
      continue;
    }
    if (!(write.value instanceof Uint8Array)) {
      throw new SpaceStorageError('InvalidRequest', 'Invalid encoded space record');
    }
    recordBytes += write.value.byteLength;
    if (recordBytes > MAX_SPACE_WRITE_BYTES) {
      throw new SpaceStorageError('InvalidRequest', 'Space write batch is too large');
    }
    const bytes = new Uint8Array(write.value);
    let value: unknown;
    let canonical: Uint8Array;
    try {
      value = dagCbor.decode(bytes);
      canonical = dagCbor.encode(value);
    } catch {
      throw new SpaceStorageError('InvalidRequest', 'Invalid encoded space record');
    }
    if (!isPlainRecord(value) || value.$type !== write.collection) {
      throw new SpaceStorageError('InvalidRequest', 'Invalid encoded space record');
    }
    if (write.blobs.length || containsBlob(value)) {
      throw new SpaceStorageError('BlobIntegrityUnavailable', 'Space blob storage is unavailable');
    }
    if (canonical.length !== bytes.length || canonical.some((byte, index) => byte !== bytes[index])) {
      throw new SpaceStorageError('InvalidRequest', 'Space record is not canonical DAG-CBOR');
    }
    const cid = CID.createV1(dagCbor.code, createDigest(0x12, sha256(bytes))).toString();
    if (cid !== write.cid) throw new SpaceStorageError('InvalidRequest', 'Space record CID does not match its bytes');
    stagedWrites.push({ ...write, value: bytes, blobs: [] });
  }
  const records = new Map(snapshot.records);
  const operations: SpaceOperation[] = [];
  const changes: SpaceSetHashChange[] = [];
  for (const write of stagedWrites) {
    const path = recordPath(write.collection, write.rkey);
    const previous = records.get(path) ?? null;
    if (write.action === 'create' && previous) {
      throw new SpaceStorageError('RecordAlreadyExists', 'Record already exists');
    }
    if (write.action !== 'create' && !previous) {
      throw new SpaceStorageError('RecordNotFound', 'Record does not exist');
    }
    const cid = write.action === 'delete' ? null : write.cid;
    if (previous) changes.push({ action: 'remove', element: spaceRecordHashElement(write.collection, write.rkey, previous) });
    if (cid) {
      changes.push({ action: 'add', element: spaceRecordHashElement(write.collection, write.rkey, cid) });
      records.set(path, cid);
    } else {
      records.delete(path);
    }
    operations.push({ collection: write.collection, rkey: write.rkey, cid, prev: previous });
  }

  const state = applySpaceSetHashChanges(snapshot.repo?.setHash ?? null, changes);
  const rev = nextSpaceRevision(snapshot.repo?.rev ?? null);
  const generation = (snapshot.repo?.generation ?? 0) + 1;
  const mutationId = crypto.randomUUID();
  const guard = [ref.ref, repoDid, generation, mutationId] as const;
  const availability = [ref.ref, ref.authorityDid, repoDid, ref.ref] as const;
  const root = snapshot.repo
    ? env.ALTERAN_DB.prepare(
      `UPDATE space_repo SET rev = ?, set_hash = ?, generation = ?, mutation_id = ?
       WHERE space_ref = ? AND repo_did = ? AND generation = ? AND mutation_id = ?
         AND ${SPACE_AVAILABLE}`,
    ).bind(rev, state, generation, mutationId, ref.ref, repoDid, snapshot.repo.generation, snapshot.repo.mutationId, ...availability)
    : env.ALTERAN_DB.prepare(
      `INSERT INTO space_repo (space_ref, repo_did, rev, set_hash, generation, mutation_id)
       SELECT ?, ?, ?, ?, ?, ? WHERE ${SPACE_AVAILABLE}
       ON CONFLICT(space_ref, repo_did) DO NOTHING`,
    ).bind(ref.ref, repoDid, rev, state, generation, mutationId, ...availability);

  const statements: D1PreparedStatement[] = [
    root,
    env.ALTERAN_DB.prepare(
      `INSERT INTO space (space_ref, authority_did, space_type, skey, created_at)
       SELECT ?, ?, ?, ?, ? WHERE ${GUARD}
       ON CONFLICT(space_ref) DO NOTHING`,
    ).bind(ref.ref, ref.authorityDid, ref.spaceType, ref.skey, Date.now(), ...guard),
  ];
  stagedWrites.forEach((write, ordinal) => {
    const path = [ref.ref, repoDid, write.collection, write.rkey] as const;
    statements.push(env.ALTERAN_DB.prepare(
      `DELETE FROM space_blob_usage
       WHERE space_ref = ? AND repo_did = ? AND collection = ? AND rkey = ? AND ${GUARD}`,
    ).bind(...path, ...guard));
    if (write.action === 'delete') {
      statements.push(env.ALTERAN_DB.prepare(
        `DELETE FROM space_record
         WHERE space_ref = ? AND repo_did = ? AND collection = ? AND rkey = ? AND ${GUARD}`,
      ).bind(...path, ...guard));
    } else {
      statements.push(env.ALTERAN_DB.prepare(
        `INSERT INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
         SELECT ?, ?, ?, ?, ?, ?, ? WHERE ${GUARD}
         ON CONFLICT(space_ref, repo_did, collection, rkey) DO UPDATE
         SET cid = excluded.cid, value_cbor = excluded.value_cbor, repo_rev = excluded.repo_rev`,
      ).bind(...path, write.cid, new Uint8Array(write.value).buffer, rev, ...guard));
    }
    const operation = operations[ordinal];
    statements.push(env.ALTERAN_DB.prepare(
      `INSERT INTO space_op (space_ref, repo_did, rev, ordinal, collection, rkey, cid, prev)
       SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE ${GUARD}`,
    ).bind(ref.ref, repoDid, rev, ordinal, operation.collection, operation.rkey, operation.cid, operation.prev, ...guard));
  });

  const results = await env.ALTERAN_DB.batch(statements);
  if (results[0].meta.changes === 1) {
    return { tag: 'committed', commit: { rev, setHash: state, data: spaceSetHashDigest(state), generation, operations } };
  }
  const spaceStatus = await env.ALTERAN_DB.prepare(`SELECT ${SPACE_AVAILABLE} AS ok`)
    .bind(ref.ref, ref.authorityDid, repoDid, ref.ref).first<{ ok: number }>();
  if (!spaceStatus?.ok) return { tag: 'missingSpace' };
  return { tag: 'conflict' };
}

function decodeRepoState(row: {
  rev: string | null;
  set_hash: number[];
  generation: number;
  mutation_id: string;
}): SpaceRepoState & { readonly mutationId: string } {
  const setHash = Uint8Array.from(row.set_hash);
  if (setHash.length !== 2048 || !Number.isSafeInteger(row.generation) || row.generation < 1 ||
    typeof row.mutation_id !== 'string' || !row.mutation_id) {
    throw new SpaceStorageError('InvalidRepoState', 'Invalid stored space repo state');
  }
  return { rev: row.rev, setHash, generation: row.generation, mutationId: row.mutation_id };
}

function recordPath(collection: string, rkey: string): string {
  return `${collection}/${rkey}`;
}

function containsBlob(root: unknown): boolean {
  const pending = [root];
  while (pending.length) {
    const value = pending.pop();
    if (!value || typeof value !== 'object') continue;
    if (Array.isArray(value)) {
      for (const item of value) pending.push(item);
      continue;
    }
    if (!isPlainRecord(value)) continue;
    const object = value;
    const keys = Object.keys(object);
    if (object.$type === 'blob' || (keys.length === 2 && typeof object.cid === 'string' &&
      typeof object.mimeType === 'string')) return true;
    for (const item of Object.values(object)) pending.push(item);
  }
  return false;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
