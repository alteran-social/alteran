import { isValidNsid, isValidRecordKey, isValidTid } from '@atproto/syntax-spaces';
import type { Env } from '../env';
import { spaceSetHashDigest } from '../lib/spaces/lthash';
import { copyPlainRecord } from '../lib/spaces/plain-values';
import { parseCanonicalRepoCid } from '../lib/spaces/repo-cid';
import { assertLocalSpaceRepo, parseSpaceRef } from './space-ref';
import { validSpaceRecordBlock } from './space-record-block';
import { globalLeaseExpiryStatements } from './space-lease-expiry';
import { SpaceStorageError } from './space-types';

const LEASE_SECONDS = 60;
const MAXIMUM_LEASE_SECONDS = 900;
const MAXIMUM_PAGE_RECORDS = 100;
const MAXIMUM_PAGE_BYTES = 1024 * 1024;
const MAXIMUM_REPO_LEASES = 16;
const MAXIMUM_GLOBAL_LEASES = 128;
const ACQUIRE_EXPIRY_BATCH_SIZE = 8;

export type SpaceSnapshotLease = {
  readonly id: string;
  readonly token: string;
  readonly spaceRef: string;
  readonly repoDid: string;
  readonly epochId: string;
  readonly generation: number;
  readonly rev: string;
  readonly data: Uint8Array;
  readonly setHash: Uint8Array;
};

export type SpaceSnapshotRecord = {
  readonly path: string;
  readonly collection: string;
  readonly rkey: string;
  readonly cid: string;
  readonly value: Uint8Array;
  readonly rev: string;
};

type LeaseRow = {
  epoch_id: string | null;
  generation: number | null;
  rev: string | null;
  set_hash: number[] | null;
};

type RecordRow = {
  path: string | null;
  collection: string | null;
  rkey: string | null;
  cid: string | null;
  value_cbor: number[] | null;
  value_size: number | null;
  repo_rev: string | null;
  valid: number;
  visibility: number;
  sentinel: number;
};

export async function acquireSpaceSnapshot(
  env: Env,
  spaceRef: string,
  repoDid: string,
): Promise<SpaceSnapshotLease> {
  await assertLocalRepo(env, spaceRef, repoDid);
  const id = crypto.randomUUID();
  const token = crypto.randomUUID();
  const nonce = crypto.randomUUID();
  const [, , , selected] = await env.ALTERAN_DB.batch([
    ...globalLeaseExpiryStatements(env, ACQUIRE_EXPIRY_BATCH_SIZE),
    env.ALTERAN_DB.prepare(
      `INSERT INTO space_snapshot_lease
       (id, token, renewal_nonce, space_ref, repo_did, epoch_id, generation, rev, set_hash, expires_at, maximum_expires_at)
       SELECT ?, ?, ?, h.space_ref, h.repo_did, h.active_epoch_id, h.generation, h.rev, h.set_hash,
         unixepoch() + ?, unixepoch() + ?
       FROM space_repo h JOIN space_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
         AND e.repo_did = h.repo_did AND e.state = 'active'
       JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL
       WHERE h.space_ref = ? AND h.repo_did = ?
         AND typeof(h.rev) = 'text' AND length(CAST(h.rev AS BLOB)) = 13
         AND typeof(h.set_hash) = 'blob' AND length(h.set_hash) = 2048
         AND typeof(h.generation) = 'integer' AND h.generation BETWEEN 1 AND 9007199254740991
         AND typeof(h.active_epoch_id) = 'text' AND length(CAST(h.active_epoch_id AS BLOB)) BETWEEN 1 AND 128
         AND NOT EXISTS (SELECT 1 FROM space_snapshot_lease l INDEXED BY space_snapshot_lease_owner_expiry
           WHERE l.space_ref = h.space_ref AND l.repo_did = h.repo_did LIMIT 1 OFFSET ?)
         AND NOT EXISTS (SELECT 1 FROM space_snapshot_lease LIMIT 1 OFFSET ?)`,
    ).bind(id, token, nonce, LEASE_SECONDS, MAXIMUM_LEASE_SECONDS, spaceRef, repoDid,
      MAXIMUM_REPO_LEASES - 1, MAXIMUM_GLOBAL_LEASES - 1),
    env.ALTERAN_DB.prepare(
      `SELECT CASE WHEN typeof(epoch_id) = 'text' AND length(CAST(epoch_id AS BLOB)) BETWEEN 1 AND 128 THEN epoch_id END AS epoch_id,
         CASE WHEN typeof(generation) = 'integer' AND generation BETWEEN 1 AND 9007199254740991 THEN generation END AS generation,
         CASE WHEN typeof(rev) = 'text' AND length(CAST(rev AS BLOB)) = 13 THEN rev END AS rev,
         CASE WHEN typeof(set_hash) = 'blob' AND length(set_hash) = 2048 THEN set_hash END AS set_hash
       FROM space_snapshot_lease WHERE id = ? AND token = ? AND renewal_nonce = ? AND space_ref = ? AND repo_did = ?`,
    ).bind(id, token, nonce, spaceRef, repoDid),
    env.ALTERAN_DB.prepare(
      `SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM space_snapshot_lease WHERE id = ?)
         OR EXISTS (
           SELECT 1 FROM space_snapshot_lease l
           JOIN space_repo h ON h.space_ref = l.space_ref AND h.repo_did = l.repo_did
             AND h.active_epoch_id = l.epoch_id AND h.generation = l.generation
             AND h.rev = l.rev AND h.set_hash IS l.set_hash
           JOIN space_epoch e ON e.id = l.epoch_id AND e.space_ref = l.space_ref
             AND e.repo_did = l.repo_did AND e.state = 'active'
           JOIN space s ON s.space_ref = l.space_ref AND s.deleted_at IS NULL
           WHERE l.id = ? AND l.token = ? AND l.renewal_nonce = ? AND l.space_ref = ? AND l.repo_did = ?
             AND typeof(l.set_hash) = 'blob' AND length(l.set_hash) = 2048
             AND l.expires_at > unixepoch() AND l.maximum_expires_at > unixepoch()
             AND NOT EXISTS (SELECT 1 FROM space_snapshot_lease quota INDEXED BY space_snapshot_lease_owner_expiry
               WHERE quota.space_ref = l.space_ref AND quota.repo_did = l.repo_did LIMIT 1 OFFSET ?)
             AND NOT EXISTS (SELECT 1 FROM space_snapshot_lease LIMIT 1 OFFSET ?)
         ) THEN 1 ELSE json('{') END AS valid`,
    ).bind(id, id, token, nonce, spaceRef, repoDid, MAXIMUM_REPO_LEASES, MAXIMUM_GLOBAL_LEASES),
  ]);
  const row = selected.results?.[0] as LeaseRow | undefined;
  if (!row) throw unavailable();
  if (!row.epoch_id || !row.rev || !isValidTid(row.rev) || !Number.isSafeInteger(row.generation) ||
    row.generation === null || row.generation < 1 || !validByteArray(row.set_hash, 2048)) {
    await env.ALTERAN_DB.prepare('DELETE FROM space_snapshot_lease WHERE id = ? AND token = ?').bind(id, token).run();
    throw new SpaceStorageError('InvalidRepoState', 'Invalid snapshot state');
  }
  const state = Uint8Array.from(row.set_hash);
  return { id, token, spaceRef, repoDid, epochId: row.epoch_id, generation: row.generation,
    rev: row.rev, data: spaceSetHashDigest(state), setHash: state };
}

export async function readSpaceSnapshotPage(
  env: Env,
  lease: SpaceSnapshotLease,
  cursor: string | null,
  limit = MAXIMUM_PAGE_RECORDS,
): Promise<{ readonly records: readonly SpaceSnapshotRecord[]; readonly cursor: string | null }> {
  const captured = captureLease(lease);
  const { id, token, spaceRef, repoDid, epochId, generation, rev, setHash } = captured;
  await assertLocalRepo(env, spaceRef, repoDid);
  if (!Number.isInteger(limit) || limit < 1 || limit > MAXIMUM_PAGE_RECORDS || (cursor !== null && !validPath(cursor))) {
    throw new SpaceStorageError('InvalidRequest', 'Invalid snapshot page');
  }
  const nonce = crypto.randomUUID();
  const identity = [id, token, spaceRef, repoDid, epochId, generation, rev, setHash.buffer] as const;
  // Seek distinct paths and then the newest prior version so old versions do
  // not turn one page into a scan of the entire history for a path.
  const [, selected] = await env.ALTERAN_DB.batch([
    env.ALTERAN_DB.prepare(
      `UPDATE space_snapshot_lease SET renewal_nonce = ?, expires_at = MIN(unixepoch() + ?, maximum_expires_at)
       WHERE id = ? AND token = ? AND space_ref = ? AND repo_did = ? AND epoch_id = ? AND generation = ?
         AND rev = ? AND set_hash = ?
         AND expires_at > unixepoch() AND maximum_expires_at > unixepoch()
         AND EXISTS (
           SELECT 1 FROM space_repo h JOIN space_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
             AND e.repo_did = h.repo_did AND e.state = 'active'
           JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL
           WHERE h.space_ref = space_snapshot_lease.space_ref AND h.repo_did = space_snapshot_lease.repo_did
             AND h.active_epoch_id = space_snapshot_lease.epoch_id
         )`,
    ).bind(nonce, LEASE_SECONDS, ...identity),
    env.ALTERAN_DB.prepare(
      `WITH RECURSIVE valid_lease AS (
         SELECT 1 FROM space_snapshot_lease l JOIN space_epoch e ON e.id = l.epoch_id
           AND e.space_ref = l.space_ref AND e.repo_did = l.repo_did AND e.state = 'active'
         JOIN space_repo h ON h.space_ref = l.space_ref AND h.repo_did = l.repo_did AND h.active_epoch_id = l.epoch_id
         JOIN space s ON s.space_ref = l.space_ref AND s.deleted_at IS NULL
         WHERE l.id = ? AND l.token = ? AND l.space_ref = ? AND l.repo_did = ? AND l.epoch_id = ?
           AND l.generation = ? AND l.rev = ? AND l.set_hash = ? AND l.renewal_nonce = ? AND l.expires_at > unixepoch()
           AND l.maximum_expires_at > unixepoch()
       ), paths(path, ordinal) AS (
         SELECT (SELECT path FROM space_record_version WHERE epoch_id = ? AND path > ? COLLATE BINARY
           ORDER BY path COLLATE BINARY LIMIT 1), 1 FROM valid_lease
         UNION ALL
         SELECT (SELECT path FROM space_record_version WHERE epoch_id = ? AND path > p.path COLLATE BINARY
           ORDER BY path COLLATE BINARY LIMIT 1), p.ordinal + 1
         FROM paths p WHERE typeof(p.path) = 'text' AND length(CAST(p.path AS BLOB)) BETWEEN 1 AND 830
           AND p.ordinal < ?
       ), chosen AS MATERIALIZED (
         SELECT p.path, p.ordinal, (SELECT v.from_generation FROM space_record_version v
           WHERE v.epoch_id = ? AND v.path = p.path AND v.from_generation <= ?
           ORDER BY v.from_generation DESC LIMIT 1) AS generation
         FROM paths p WHERE p.path IS NOT NULL
       ), candidates AS MATERIALIZED (
         SELECT p.path, p.ordinal, p.generation,
           CASE WHEN typeof(v.value_cbor) = 'blob' THEN length(v.value_cbor) ELSE 0 END AS bytes,
           CASE WHEN p.generation IS NULL THEN 0
             WHEN v.epoch_id IS NULL OR v.space_ref IS NOT ? OR v.repo_did IS NOT ?
               OR typeof(v.from_generation) <> 'integer' OR v.from_generation < 1
               OR (v.until_generation IS NOT NULL AND (typeof(v.until_generation) <> 'integer'
                 OR v.until_generation <= v.from_generation)) THEN -1
             WHEN v.until_generation IS NOT NULL AND v.until_generation <= ? THEN 0 ELSE 1 END AS visibility
         FROM chosen p LEFT JOIN space_record_version v ON v.epoch_id = ? AND v.path = p.path
           AND v.from_generation = p.generation
       ), sized AS (
         SELECT *, SUM(CASE WHEN visibility = 1 THEN bytes ELSE 0 END)
           OVER (ORDER BY ordinal) AS total FROM candidates
       )
       SELECT CASE WHEN typeof(p.path) = 'text' AND length(CAST(p.path AS BLOB)) <= 830 THEN p.path END AS path,
         CASE WHEN p.visibility = 1 AND typeof(v.collection) = 'text' AND length(CAST(v.collection AS BLOB)) <= 317 THEN v.collection END AS collection,
         CASE WHEN p.visibility = 1 AND typeof(v.rkey) = 'text' AND length(CAST(v.rkey AS BLOB)) <= 512 THEN v.rkey END AS rkey,
         CASE WHEN p.visibility = 1 AND typeof(v.cid) = 'text' AND length(CAST(v.cid AS BLOB)) <= 128 THEN v.cid END AS cid,
         CASE WHEN p.visibility = 1 AND typeof(v.value_cbor) = 'blob' AND length(v.value_cbor) <= ? THEN v.value_cbor END AS value_cbor,
         CASE WHEN p.visibility = 1 AND typeof(v.value_size) = 'integer' AND v.value_size BETWEEN 1 AND ? THEN v.value_size END AS value_size,
         CASE WHEN p.visibility = 1 AND typeof(v.repo_rev) = 'text' AND length(CAST(v.repo_rev AS BLOB)) = 13 THEN v.repo_rev END AS repo_rev,
         CASE WHEN typeof(p.path) = 'text' AND length(CAST(p.path AS BLOB)) <= 830 AND (p.visibility = 0 OR (
           p.visibility = 1 AND typeof(v.collection) = 'text' AND length(CAST(v.collection AS BLOB)) <= 317
           AND typeof(v.rkey) = 'text' AND length(CAST(v.rkey AS BLOB)) <= 512
           AND typeof(v.cid) = 'text' AND length(CAST(v.cid AS BLOB)) <= 128
           AND typeof(v.value_cbor) = 'blob' AND length(v.value_cbor) BETWEEN 1 AND ?
           AND typeof(v.value_size) = 'integer' AND v.value_size = length(v.value_cbor)
           AND typeof(v.repo_rev) = 'text' AND length(CAST(v.repo_rev AS BLOB)) = 13)) THEN 1 ELSE 0 END AS valid,
         p.visibility, 0 AS sentinel
       FROM sized p LEFT JOIN space_record_version v ON v.epoch_id = ? AND v.path = p.path
         AND v.from_generation = p.generation
       WHERE p.total <= ? OR p.ordinal = 1
       UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1, 0, 1 FROM valid_lease
       ORDER BY 1`,
    ).bind(...identity, nonce, epochId, cursor ?? '', epochId, limit, epochId, generation,
      spaceRef, repoDid, generation, epochId, MAXIMUM_PAGE_BYTES, MAXIMUM_PAGE_BYTES,
      MAXIMUM_PAGE_BYTES, epochId, MAXIMUM_PAGE_BYTES),
  ]);
  const selectedRows = selected.results as RecordRow[] | undefined;
  if (!selectedRows || selectedRows.filter((row) => row.sentinel === 1).length !== 1) throw unavailable();
  const rows = selectedRows.filter((row) => row.sentinel === 0);
  if (rows.length + 1 !== selectedRows.length) throw unavailable();
  const records: SpaceSnapshotRecord[] = [];
  for (const row of rows) {
    if (row.valid !== 1 || !row.path || !validPath(row.path)) {
      throw new SpaceStorageError('InvalidRepoState', 'Invalid Space snapshot path');
    }
    if (row.visibility === 0) continue;
    if (row.visibility !== 1 || !row.collection || !isValidNsid(row.collection) ||
      !row.rkey || !isValidRecordKey(row.rkey) || row.path !== `${row.collection}/${row.rkey}` ||
      !row.cid || parseCanonicalRepoCid(row.cid)?.toString() !== row.cid || !row.repo_rev ||
      !isValidTid(row.repo_rev) || row.repo_rev > rev || row.value_size === null ||
      !validByteArray(row.value_cbor, row.value_size)) {
      throw new SpaceStorageError('InvalidRepoState', 'Space snapshot record exceeds the page limit');
    }
    const value = Uint8Array.from(row.value_cbor);
    if (!validSpaceRecordBlock(row.collection, row.cid, value)) {
      throw new SpaceStorageError('InvalidRepoState', 'Invalid Space snapshot record');
    }
    records.push({ path: row.path, collection: row.collection, rkey: row.rkey, cid: row.cid, value, rev: row.repo_rev });
  }
  // Paths created after the lease can advance the cursor without yielding records.
  return { records, cursor: rows.at(-1)?.path ?? null };
}

export async function releaseSpaceSnapshot(env: Env, lease: SpaceSnapshotLease): Promise<void> {
  const { id, token, spaceRef, repoDid, epochId, generation } = captureLease(lease);
  await assertLocalRepo(env, spaceRef, repoDid);
  await env.ALTERAN_DB.prepare(
    `DELETE FROM space_snapshot_lease
     WHERE id = ? AND token = ? AND space_ref = ? AND repo_did = ? AND epoch_id = ? AND generation = ?`,
  ).bind(id, token, spaceRef, repoDid, epochId, generation).run();
}

async function assertLocalRepo(env: Env, spaceRef: string, repoDid: string): Promise<void> {
  parseSpaceRef(spaceRef);
  await assertLocalSpaceRepo(env, repoDid);
}

function captureLease(value: SpaceSnapshotLease): SpaceSnapshotLease {
  const fields = copyPlainRecord(value, ['id', 'token', 'spaceRef', 'repoDid', 'epochId', 'generation', 'rev', 'data', 'setHash']);
  if (!fields || typeof fields.id !== 'string' || !fields.id || fields.id.length > 128 ||
    typeof fields.token !== 'string' || !fields.token || fields.token.length > 128 ||
    typeof fields.spaceRef !== 'string' || fields.spaceRef.length > 8192 ||
    typeof fields.repoDid !== 'string' || fields.repoDid.length > 2048 ||
    typeof fields.epochId !== 'string' || !fields.epochId || fields.epochId.length > 128 ||
    typeof fields.generation !== 'number' || !Number.isSafeInteger(fields.generation) || fields.generation < 1 ||
    typeof fields.rev !== 'string' || !isValidTid(fields.rev) ||
    !(fields.data instanceof Uint8Array) || !(fields.setHash instanceof Uint8Array)) throw unavailable();
  try {
    const typedArray = Object.getPrototypeOf(Uint8Array.prototype);
    if (Reflect.get(typedArray, 'byteLength', fields.data) !== 32 ||
      Reflect.get(typedArray, 'byteLength', fields.setHash) !== 2048 ||
      !(Reflect.get(typedArray, 'buffer', fields.data) instanceof ArrayBuffer) ||
      !(Reflect.get(typedArray, 'buffer', fields.setHash) instanceof ArrayBuffer)) throw unavailable();
    const data = new Uint8Array(fields.data);
    const setHash = new Uint8Array(fields.setHash);
    if (data.byteLength !== 32 || setHash.byteLength !== 2048 ||
      spaceSetHashDigest(setHash).some((byte, index) => byte !== data[index])) throw unavailable();
    return { id: fields.id, token: fields.token, spaceRef: fields.spaceRef, repoDid: fields.repoDid,
      epochId: fields.epochId, generation: fields.generation, rev: fields.rev, data, setHash };
  } catch {
    throw unavailable();
  }
}

function validByteArray(value: unknown, length: number): value is number[] {
  return Array.isArray(value) && value.length === length && value.every((byte) =>
    Number.isInteger(byte) && byte >= 0 && byte <= 255
  );
}

function validPath(path: string): boolean {
  if (typeof path !== 'string' || path.length > 830) return false;
  const parts = path.split('/');
  return parts.length === 2 && isValidNsid(parts[0]) && isValidRecordKey(parts[1]);
}

function unavailable(): SpaceStorageError {
  return new SpaceStorageError('SpaceSnapshotUnavailable', 'Space snapshot is unavailable');
}
