import type { D1PreparedStatement } from '@cloudflare/workers-types';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { isValidNsid, isValidRecordKey, isValidTid } from '@atproto/syntax-spaces';
import { MAX_RECORD_SIZE } from '@atproto/space';
import type { Env } from '../env';
import {
  applySpaceSetHashChanges,
  spaceRecordHashElement,
  spaceSetHashDigest,
  type SpaceSetHashChange,
} from '../lib/spaces/lthash';
import { nextSpaceRevision } from './space-tid';
import { assertLocalSpaceRepo, parseSpaceRef } from './space-ref';
import { ownSpaceWriteValue, spaceWriteArrayLength } from './space-write-input';
import { checkRecordCborBounds } from '../lib/spaces/record-cbor-bounds';
import { parseCanonicalRepoCid } from '../lib/spaces/repo-cid';
import { verifySpaceRecordDataModel } from './space-verify-record';
import { validSpaceRecordBlock } from './space-record-block';
import { MAX_SPACE_MUTATION_SNAPSHOT_BYTES, SPACE_MUTATION_SNAPSHOT_SQL } from './space-mutation-snapshot-sql';
import { SPACE_GENESIS_EMPTY } from './space-genesis-sql';
import { classifySpaceMutationConflict } from './space-mutation-conflict';
import { BOOTSTRAP_GUARD, EFFECT_GUARD, GUARD, RECORDS_MATCH, SPACE_AVAILABLE, WON_GUARD } from './space-mutation-sql';
import { captureSpaceOwner } from './space-owner';
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
  readonly ownerIncarnation: string;
  readonly repo: (SpaceRepoState & { readonly mutationId: string; readonly epochId: string }) | null;
  readonly records: ReadonlyMap<string, { readonly cid: string; readonly fromGeneration: number; readonly repoRev: string }>;
};

type CommitResult =
  | { readonly tag: 'committed'; readonly commit: SpaceCommit }
  | { readonly tag: 'conflict' | 'missingSpace' };

export async function loadSpaceSnapshot(
  env: Env,
  ref: SpaceRef,
  repoDid: string,
  writes: readonly PreparedSpaceWrite[],
  ownerIncarnation: string,
): Promise<Snapshot> {
  ref = parseSpaceRef(ref.ref);
  const owner = captureSpaceOwner(repoDid, ownerIncarnation);
  const count = spaceWriteArrayLength(writes);
  const requested: [string, string][] = [];
  for (let index = 0; index < count; index++) {
    const write = ownSpaceWriteValue(writes, String(index));
    if (!isPlainRecord(write)) throw new SpaceStorageError('InvalidRequest', 'Invalid space write');
    const collection = ownSpaceWriteValue(write, 'collection');
    const rkey = ownSpaceWriteValue(write, 'rkey');
    if (typeof collection !== 'string' || typeof rkey !== 'string' ||
      !isValidNsid(collection) || !isValidRecordKey(rkey)) {
      throw new SpaceStorageError('InvalidRequest', 'Invalid space write');
    }
    requested.push([collection, rkey]);
  }
  const paths = JSON.stringify(requested);
  await assertLocalSpaceRepo(env, repoDid);
  const [spaceResult, repoResult, recordResult] = await env.ALTERAN_DB.batch([
    env.ALTERAN_DB.prepare(`WITH t AS MATERIALIZED (SELECT ? AS space_ref, ? AS repo_did, ? AS owner_incarnation)
      SELECT s.deleted_at IS NULL AS active FROM t
      JOIN account a ON a.did = t.repo_did AND a.space_incarnation = t.owner_incarnation
      JOIN account_state state ON state.did = a.did AND typeof(state.active) = 'integer' AND state.active = 1
        AND state.status IS NULL AND state.suspended_until IS NULL
      JOIN space s ON s.space_ref = t.space_ref
        AND s.space_ref = 'at://' || s.authority_did || '/space/' || s.space_type || '/' || s.skey
      WHERE (s.authority_did != t.repo_did OR EXISTS (SELECT 1 FROM space_personal_policy p
          WHERE p.space_ref = s.space_ref AND p.authority_did = t.repo_did AND p.authority_incarnation = t.owner_incarnation))
        AND (EXISTS (SELECT 1 FROM space_repo h JOIN space_owned_epoch e ON e.id = h.active_epoch_id
            AND e.space_ref = h.space_ref AND e.repo_did = h.repo_did AND e.owner_incarnation = t.owner_incarnation
          WHERE h.space_ref = t.space_ref AND h.repo_did = t.repo_did)
          OR (${SPACE_GENESIS_EMPTY}))`).bind(ref.ref, repoDid, owner.incarnation),
    env.ALTERAN_DB.prepare(
      `SELECT CASE WHEN typeof(h.rev) = 'text' AND length(CAST(h.rev AS BLOB)) = 13 THEN h.rev END AS rev,
         CASE WHEN typeof(h.set_hash) = 'blob' AND length(h.set_hash) = 2048 THEN h.set_hash END AS set_hash,
         CASE WHEN typeof(h.generation) = 'integer' AND h.generation BETWEEN 1 AND 9007199254740991
           THEN h.generation END AS generation,
         CASE WHEN typeof(h.mutation_id) = 'text' AND length(CAST(h.mutation_id AS BLOB)) BETWEEN 1 AND 128
           THEN h.mutation_id END AS mutation_id,
         CASE WHEN typeof(h.active_epoch_id) = 'text' AND length(CAST(h.active_epoch_id AS BLOB)) BETWEEN 1 AND 128
           THEN h.active_epoch_id END AS active_epoch_id,
         CASE WHEN e.state = 'active' THEN 'active' END AS epoch_state
       FROM space_repo h JOIN space_owned_epoch e ON e.id = h.active_epoch_id
         AND e.space_ref = h.space_ref AND e.repo_did = h.repo_did
       JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL
       WHERE h.space_ref = ? AND h.repo_did = ? AND e.owner_incarnation = ?`,
    ).bind(ref.ref, repoDid, owner.incarnation),
    env.ALTERAN_DB.prepare(SPACE_MUTATION_SNAPSHOT_SQL).bind(paths, ref.ref, repoDid, owner.incarnation),
  ]);
  const space = spaceResult.results?.[0] as { active: number } | undefined;
  if ((space && space.active !== 1) || (!space && ref.authorityDid === repoDid)) {
    throw new SpaceStorageError('SpaceNotFound', 'Space does not exist or is deleted');
  }
  const row = repoResult.results?.[0] as {
    rev: string | null;
    set_hash: number[] | null;
    generation: number | null;
    mutation_id: string | null;
    active_epoch_id: string | null;
    epoch_state: string | null;
  } | undefined;
  const repo = row ? decodeRepoState(row) : null;
  const records = new Map<string, { cid: string; fromGeneration: number; repoRev: string }>();
  let snapshotBytes = 0;
  if (!recordResult.results || recordResult.results.length !== requested.length) {
    throw new SpaceStorageError('InvalidRepoState', 'Invalid Space snapshot result');
  }
  for (const record of recordResult.results ?? []) {
    const typed = record as { collection: string; rkey: string; cid: string | null; version_cid: string | null; from_generation: number | null; record_rev: string | null; value_cbor: number[] | null; consistent: number; over_budget: number };
    if (typed.over_budget === 1) throw new SpaceStorageError('InvalidRequest', 'Space write batch touches too much existing data');
    if (typed.over_budget !== 0 || typed.consistent !== 1 || typed.cid !== typed.version_cid || (typed.cid !== null &&
      (parseCanonicalRepoCid(typed.cid)?.toString() !== typed.cid || !Number.isSafeInteger(typed.from_generation) ||
        !typed.record_rev || !isValidTid(typed.record_rev)))) {
      throw new SpaceStorageError('InvalidRepoState', 'Current space record differs from its version');
    }
    if (typed.cid !== null && typed.from_generation !== null && typed.record_rev !== null) {
      if (!Array.isArray(typed.value_cbor) || !typed.value_cbor.length || typed.value_cbor.length > MAX_RECORD_SIZE ||
        (snapshotBytes += typed.value_cbor.length) > MAX_SPACE_MUTATION_SNAPSHOT_BYTES ||
        !typed.value_cbor.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255) ||
        !validSpaceRecordBlock(typed.collection, typed.cid, Uint8Array.from(typed.value_cbor))) {
        throw new SpaceStorageError('InvalidRepoState', 'Invalid Space record in write snapshot');
      }
      records.set(recordPath(typed.collection, typed.rkey), { cid: typed.cid, fromGeneration: typed.from_generation, repoRev: typed.record_rev });
    }
  }
  return { ownerIncarnation: owner.incarnation, repo, records };
}

export async function commitSpaceWrites(
  env: Env,
  ref: SpaceRef,
  repoDid: string,
  writes: readonly PreparedSpaceWrite[],
  snapshot: Snapshot,
): Promise<CommitResult> {
  ref = parseSpaceRef(ref.ref);
  const owner = captureSpaceOwner(repoDid, snapshot.ownerIncarnation);
  const writeCount = spaceWriteArrayLength(writes);
  if (writeCount === 0) {
    throw new SpaceStorageError('InvalidRequest', 'Invalid number of space writes');
  }
  if (snapshot.records.size > MAX_SPACE_WRITES || (snapshot.repo &&
    (!(snapshot.repo.setHash instanceof Uint8Array) || snapshot.repo.setHash.byteLength !== 2048))) {
    throw new SpaceStorageError('InvalidRepoState', 'Invalid space snapshot');
  }
  snapshot = {
    ownerIncarnation: owner.incarnation,
    repo: snapshot.repo ? { ...snapshot.repo, setHash: new Uint8Array(snapshot.repo.setHash) } : null,
    records: new Map([...snapshot.records].map(([path, record]) => [path, { ...record }])),
  };
  if (!snapshot.repo && snapshot.records.size !== 0) {
    throw new SpaceStorageError('InvalidRepoState', 'Missing repo has snapshot records');
  }
  let recordBytes = 0;
  const stagedWrites: PreparedSpaceWrite[] = [];
  for (let index = 0; index < writeCount; index++) {
    const write = ownSpaceWriteValue(writes, String(index));
    if (!isPlainRecord(write)) throw new SpaceStorageError('InvalidRequest', 'Invalid space write');
    const action = ownSpaceWriteValue(write, 'action');
    const collection = ownSpaceWriteValue(write, 'collection');
    const rkey = ownSpaceWriteValue(write, 'rkey');
    if (typeof collection !== 'string' || typeof rkey !== 'string' || !isValidNsid(collection) || !isValidRecordKey(rkey) ||
      (action !== 'create' && action !== 'update' && action !== 'delete')) {
      throw new SpaceStorageError('InvalidRequest', 'Invalid space write');
    }
    if (action === 'delete') {
      stagedWrites.push({ action, collection, rkey });
      continue;
    }
    const encoded = ownSpaceWriteValue(write, 'value');
    const claimedCid = ownSpaceWriteValue(write, 'cid');
    const blobs = ownSpaceWriteValue(write, 'blobs');
    if (!ArrayBuffer.isView(encoded) || !(encoded instanceof Uint8Array) || typeof claimedCid !== 'string') {
      throw new SpaceStorageError('InvalidRequest', 'Invalid encoded space record');
    }
    if (spaceWriteArrayLength(blobs) !== 0) {
      throw new SpaceStorageError('BlobIntegrityUnavailable', 'Space blob storage is unavailable');
    }
    const byteLength = Reflect.get(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength', encoded);
    if (!Number.isSafeInteger(byteLength) || byteLength < 0) {
      throw new SpaceStorageError('InvalidRequest', 'Invalid encoded space record');
    }
    recordBytes += byteLength;
    if (recordBytes > MAX_SPACE_WRITE_BYTES) {
      throw new SpaceStorageError('InvalidRequest', 'Space write batch is too large');
    }
    const bytes = new Uint8Array(encoded);
    if (bytes.byteLength !== byteLength) throw new SpaceStorageError('InvalidRequest', 'Invalid encoded space record');
    if (checkRecordCborBounds(bytes) !== 'valid') {
      throw new SpaceStorageError('InvalidRequest', 'Invalid or overly complex space record');
    }
    let value: unknown;
    let canonical: Uint8Array;
    try {
      value = dagCbor.decode(bytes);
      canonical = dagCbor.encode(value);
    } catch {
      throw new SpaceStorageError('InvalidRequest', 'Invalid encoded space record');
    }
    if (!isPlainRecord(value) || !Object.hasOwn(value, '$type') || value.$type !== collection) {
      throw new SpaceStorageError('InvalidRequest', 'Invalid encoded space record');
    }
    if (containsBlob(value)) {
      throw new SpaceStorageError('BlobIntegrityUnavailable', 'Space blob storage is unavailable');
    }
    if (verifySpaceRecordDataModel(value) !== 'valid') {
      throw new SpaceStorageError('InvalidRequest', 'Invalid Space record data model');
    }
    if (canonical.length !== bytes.length || canonical.some((byte, index) => byte !== bytes[index])) {
      throw new SpaceStorageError('InvalidRequest', 'Space record is not canonical DAG-CBOR');
    }
    const cid = CID.createV1(dagCbor.code, createDigest(0x12, sha256(bytes))).toString();
    if (cid !== claimedCid) throw new SpaceStorageError('InvalidRequest', 'Space record CID does not match its bytes');
    stagedWrites.push({ action, collection, rkey, cid, value: bytes, blobs: [] });
  }
  const records = new Map([...snapshot.records].map(([path, record]) => [path, record.cid]));
  const finalWrites = new Map<string, PreparedSpaceWrite>();
  const operations: SpaceOperation[] = [];
  const changes: SpaceSetHashChange[] = [];
  for (const write of stagedWrites) {
    const path = recordPath(write.collection, write.rkey);
    finalWrites.set(path, write);
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
  if (!Number.isSafeInteger(generation)) throw new SpaceStorageError('InvalidRepoState', 'Space generation overflow');
  const mutationId = crypto.randomUUID();
  const won = `${mutationId}:won`;
  const lost = `${mutationId}:lost`;
  const baselinePrefix = `${mutationId}:baseline:`;
  const baselineGlob = `${baselinePrefix}*`;
  const epochId = snapshot.repo?.epochId ?? crypto.randomUUID();
  const guard = [ref.ref, repoDid, generation, mutationId, epochId, rev, state] as const;
  const wonGuard = [...guard, won] as const;
  const effectGuard = [...wonGuard, epochId, ref.ref, repoDid] as const;
  const availability = [ref.ref, ref.authorityDid, repoDid, ref.ref] as const;
  const expectedRecords = JSON.stringify([...finalWrites].map(([path, write]) => ({
    path, collection: write.collection, rkey: write.rkey,
    cid: snapshot.records.get(path)?.cid ?? null,
    fromGeneration: snapshot.records.get(path)?.fromGeneration ?? null,
    repoRev: snapshot.records.get(path)?.repoRev ?? null,
  })));
  const expectedArguments = [expectedRecords, ref.ref, repoDid, epochId, ref.ref, repoDid] as const;
  const root = snapshot.repo
    ? env.ALTERAN_DB.prepare(
      `UPDATE space_repo SET rev = ?, set_hash = ?, generation = ?, mutation_id = ?
       WHERE space_ref = ? AND repo_did = ? AND generation = ? AND mutation_id = ? AND active_epoch_id = ?
         AND rev IS ? AND set_hash = ?
         AND EXISTS (SELECT 1 FROM space_epoch e WHERE e.id = ? AND e.space_ref = ? AND e.repo_did = ? AND e.state = 'active')
         AND ${SPACE_AVAILABLE} AND ${RECORDS_MATCH}`,
    ).bind(rev, state, generation, mutationId, ref.ref, repoDid, snapshot.repo.generation, snapshot.repo.mutationId,
      epochId, snapshot.repo.rev, snapshot.repo.setHash, epochId, ref.ref, repoDid, ...availability, ...expectedArguments)
    : env.ALTERAN_DB.prepare(
      `INSERT INTO space_repo (space_ref, repo_did, rev, set_hash, generation, mutation_id, active_epoch_id)
       SELECT ?, ?, ?, ?, ?, ?, ? WHERE ${SPACE_AVAILABLE}
         AND NOT EXISTS (SELECT 1 FROM space_repo WHERE space_ref = ? AND repo_did = ?)
         AND NOT EXISTS (SELECT 1 FROM space_epoch WHERE space_ref = ? AND repo_did = ?)
         AND NOT EXISTS (SELECT 1 FROM space_record WHERE space_ref = ? AND repo_did = ?)
       ON CONFLICT(space_ref, repo_did) DO NOTHING`,
    ).bind(ref.ref, repoDid, rev, state, generation, mutationId, epochId, ...availability,
      ref.ref, repoDid, ref.ref, repoDid, ref.ref, repoDid);

  // Preserve a connection-local total so ignored root statements cannot hide trigger writes.
  const statements: D1PreparedStatement[] = [
    env.ALTERAN_DB.prepare(
      `INSERT INTO space_commit_assertion (mutation_id, valid)
       SELECT ? || CAST(total_changes() + 2 AS TEXT), 1`,
    ).bind(baselinePrefix),
    env.ALTERAN_DB.prepare(
      `INSERT INTO space_mutation_attempt (mutation_id, space_ref, repo_did, epoch_id, generation, rev, set_hash, owner_incarnation)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(mutationId, ref.ref, repoDid, epochId, generation, rev, state, owner.incarnation),
    env.ALTERAN_DB.prepare(
      `SELECT CASE WHEN EXISTS (SELECT 1 FROM space_commit_assertion
         WHERE mutation_id = ? || CAST(total_changes() AS TEXT)) THEN 1 ELSE json('{') END AS valid`,
    ).bind(baselinePrefix),
    root,
    // SQLite changes() reports the direct root mutation; D1 metadata includes trigger effects.
    env.ALTERAN_DB.prepare(
      `INSERT INTO space_commit_assertion (mutation_id, valid)
       SELECT CASE changes() WHEN 1 THEN ? ELSE ? END,
         CASE
           WHEN changes() = 0 AND EXISTS (SELECT 1 FROM space_commit_assertion
             WHERE mutation_id = ? || CAST(total_changes() AS TEXT)) THEN 1
           WHEN changes() = 1 AND EXISTS (SELECT 1 FROM space_commit_assertion WHERE mutation_id GLOB ?)
             AND ${GUARD} THEN 1
           ELSE 0 END`,
    ).bind(won, lost, baselinePrefix, baselineGlob, ...guard),
  ];
  if (!snapshot.repo) {
    statements.push(env.ALTERAN_DB.prepare(
      `INSERT INTO space_epoch (id, space_ref, repo_did, state, created_at, owner_incarnation)
       SELECT ?, ?, ?, 'active', unixepoch(), ? WHERE ${WON_GUARD}`,
    ).bind(epochId, ref.ref, repoDid, owner.incarnation, ...wonGuard));
  }
  statements.push(env.ALTERAN_DB.prepare(
      `INSERT INTO space (space_ref, authority_did, space_type, skey, created_at)
       SELECT ?, ?, ?, ?, ? WHERE ${BOOTSTRAP_GUARD} AND NOT EXISTS (SELECT 1 FROM space WHERE space_ref = ?)
       ON CONFLICT(space_ref) DO NOTHING`,
    ).bind(ref.ref, ref.authorityDid, ref.spaceType, ref.skey, Date.now(), ...effectGuard, ref.ref));
  for (const [pathString, write] of finalWrites) {
    const path = [ref.ref, repoDid, write.collection, write.rkey] as const;
    statements.push(env.ALTERAN_DB.prepare(
      `DELETE FROM space_blob_usage
       WHERE space_ref = ? AND repo_did = ? AND collection = ? AND rkey = ? AND ${EFFECT_GUARD}`,
    ).bind(...path, ...effectGuard));
    statements.push(env.ALTERAN_DB.prepare(
      `UPDATE space_record_version SET until_generation = ?
       WHERE epoch_id = ? AND space_ref = ? AND repo_did = ? AND path = ?
         AND until_generation IS NULL AND ${EFFECT_GUARD}`,
    ).bind(generation, epochId, ref.ref, repoDid, pathString, ...effectGuard));
    if (write.action === 'delete') {
      statements.push(env.ALTERAN_DB.prepare(
        `DELETE FROM space_record
         WHERE space_ref = ? AND repo_did = ? AND collection = ? AND rkey = ? AND ${EFFECT_GUARD}`,
      ).bind(...path, ...effectGuard));
    } else {
      statements.push(snapshot.records.has(pathString)
        ? env.ALTERAN_DB.prepare(
          `UPDATE space_record SET cid = ?, value_cbor = ?, repo_rev = ?
           WHERE space_ref = ? AND repo_did = ? AND collection = ? AND rkey = ? AND ${EFFECT_GUARD}`,
        ).bind(write.cid, new Uint8Array(write.value).buffer, rev, ...path, ...effectGuard)
        : env.ALTERAN_DB.prepare(
          `INSERT INTO space_record (space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
           SELECT ?, ?, ?, ?, ?, ?, ? WHERE ${EFFECT_GUARD}`,
        ).bind(...path, write.cid, new Uint8Array(write.value).buffer, rev, ...effectGuard));
      statements.push(env.ALTERAN_DB.prepare(
        `INSERT INTO space_record_version
         (epoch_id, space_ref, repo_did, path, collection, rkey, from_generation, until_generation, cid, value_cbor, value_size, repo_rev)
         SELECT ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ? WHERE ${EFFECT_GUARD}`,
      ).bind(epochId, ref.ref, repoDid, pathString, write.collection, write.rkey, generation,
        write.cid, new Uint8Array(write.value).buffer, write.value.byteLength, rev, ...effectGuard));
    }
  }
  stagedWrites.forEach((write, ordinal) => {
    const operation = operations[ordinal];
    statements.push(env.ALTERAN_DB.prepare(
      `INSERT INTO space_op (space_ref, repo_did, rev, ordinal, collection, rkey, cid, prev)
       SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE ${EFFECT_GUARD}`,
    ).bind(ref.ref, repoDid, rev, ordinal, operation.collection, operation.rkey, operation.cid, operation.prev, ...effectGuard));
  });

  const finalRecords = JSON.stringify([...finalWrites].map(([path, write]) => ({
    path, collection: write.collection, rkey: write.rkey,
    cid: write.action === 'delete' ? null : write.cid,
    fromGeneration: write.action === 'delete' ? null : generation,
    repoRev: write.action === 'delete' ? null : rev,
  })));
  const finalArguments = [finalRecords, ref.ref, repoDid, epochId, ref.ref, repoDid] as const;
  // A failed assertion must abort the batch even if a trigger skips a write.
  statements.push(env.ALTERAN_DB.prepare(
    `SELECT CASE
       WHEN EXISTS (SELECT 1 FROM space_commit_assertion WHERE mutation_id = ?)
         AND NOT EXISTS (SELECT 1 FROM space_commit_assertion WHERE mutation_id = ?) THEN 1
       WHEN ${WON_GUARD}
       AND NOT EXISTS (SELECT 1 FROM space_commit_assertion WHERE mutation_id = ?)
       AND EXISTS (SELECT 1 FROM space_owned_epoch e WHERE e.id = ? AND e.space_ref = ? AND e.repo_did = ?
         AND e.state = 'active' AND e.owner_incarnation = ?)
       AND EXISTS (SELECT 1 FROM space s WHERE s.space_ref = ? AND s.deleted_at IS NULL)
       AND ${RECORDS_MATCH}
       AND NOT EXISTS (
         SELECT 1 FROM json_each(?) requested JOIN space_blob_usage b ON b.space_ref = ? AND b.repo_did = ?
           AND b.collection = json_extract(requested.value, '$.collection') AND b.rkey = json_extract(requested.value, '$.rkey')
       )
       AND (SELECT COUNT(*) FROM space_op WHERE space_ref = ? AND repo_did = ? AND rev = ?) = ?
       THEN 1 ELSE json('{') END AS valid`,
  ).bind(lost, won, ...wonGuard, lost, epochId, ref.ref, repoDid, owner.incarnation, ref.ref, ...finalArguments,
    finalRecords, ref.ref, repoDid, ref.ref, repoDid, rev, operations.length));
  const outcomeIndex = statements.length;
  statements.push(env.ALTERAN_DB.prepare(
    'SELECT mutation_id FROM space_commit_assertion WHERE mutation_id IN (?, ?)',
  ).bind(won, lost));
  statements.push(env.ALTERAN_DB.prepare(
    'DELETE FROM space_commit_assertion WHERE mutation_id IN (?, ?) OR mutation_id GLOB ?',
  ).bind(won, lost, baselineGlob));
  statements.push(env.ALTERAN_DB.prepare(
    'DELETE FROM space_mutation_attempt WHERE mutation_id = ?',
  ).bind(mutationId));
  statements.push(env.ALTERAN_DB.prepare(
    `SELECT CASE WHEN EXISTS (SELECT 1 FROM space_commit_assertion WHERE mutation_id IN (?, ?) OR mutation_id GLOB ?)
       OR EXISTS (SELECT 1 FROM space_mutation_attempt WHERE mutation_id = ?)
       OR NOT EXISTS (SELECT 1 FROM account a JOIN account_state state ON state.did = a.did
         WHERE a.did = ? AND a.space_incarnation = ? AND typeof(state.active) = 'integer' AND state.active = 1
           AND state.status IS NULL AND state.suspended_until IS NULL)
       OR (EXISTS (SELECT 1 FROM space_repo h WHERE h.space_ref = ? AND h.repo_did = ?)
         AND NOT EXISTS (SELECT 1 FROM space_repo h JOIN space_owned_epoch e ON e.id = h.active_epoch_id
           AND e.space_ref = h.space_ref AND e.repo_did = h.repo_did AND e.state = 'active'
           JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL
           WHERE h.space_ref = ? AND h.repo_did = ? AND e.owner_incarnation = ?))
       THEN json('{') ELSE 1 END AS valid`,
  ).bind(won, lost, baselineGlob, mutationId, repoDid, owner.incarnation, ref.ref, repoDid,
    ref.ref, repoDid, owner.incarnation));

  await assertLocalSpaceRepo(env, repoDid);
  const results = await env.ALTERAN_DB.batch(statements);
  if (!Array.isArray(results) || results.length !== statements.length || results.some((result) => result?.success !== true) ||
    results.at(-1)?.results?.length !== 1 || results.at(-1)?.results?.[0]?.valid !== 1) {
    throw new SpaceStorageError('InvalidRepoState', 'Invalid space commit result');
  }
  const outcome = results[outcomeIndex].results;
  if (outcome?.length !== 1) throw new SpaceStorageError('InvalidRepoState', 'Missing space commit outcome');
  if (outcome[0].mutation_id === won) {
    return { tag: 'committed', commit: { rev, setHash: state, data: spaceSetHashDigest(state), generation, operations } };
  }
  if (outcome[0].mutation_id !== lost) throw new SpaceStorageError('InvalidRepoState', 'Invalid space commit outcome');
  return await classifySpaceMutationConflict(env, ref, owner);
}

function decodeRepoState(row: {
  rev: string | null;
  set_hash: number[] | null;
  generation: number | null;
  mutation_id: string | null;
  active_epoch_id: string | null;
  epoch_state: string | null;
}): SpaceRepoState & { readonly mutationId: string; readonly epochId: string } {
  if (!Array.isArray(row.set_hash) || row.set_hash.length !== 2048 ||
    !row.set_hash.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255) ||
    typeof row.generation !== 'number' || !Number.isSafeInteger(row.generation) || row.generation < 1 ||
    typeof row.rev !== 'string' || !isValidTid(row.rev) ||
    typeof row.mutation_id !== 'string' || !row.mutation_id) {
    throw new SpaceStorageError('InvalidRepoState', 'Invalid stored space repo state');
  }
  const setHash = Uint8Array.from(row.set_hash);
  if (!row.active_epoch_id || row.epoch_state !== 'active') {
    throw new SpaceStorageError('SpaceEpochUnavailable', 'Space epoch is unavailable');
  }
  return { rev: row.rev, setHash, generation: row.generation, mutationId: row.mutation_id, epochId: row.active_epoch_id };
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
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}
