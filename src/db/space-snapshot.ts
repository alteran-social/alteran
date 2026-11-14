import { isValidNsid, isValidRecordKey, isValidTid } from '@atproto/syntax-spaces';
import type { Env } from '../env';
import { spaceSetHashDigest } from '../lib/spaces/lthash';
import { assertLocalSpaceRepo, parseSpaceRef } from './space-ref';
import { SpaceStorageError } from './space-types';

const LEASE_SECONDS = 60;
const MAXIMUM_LEASE_SECONDS = 900;
const MAXIMUM_PAGE_RECORDS = 100;
const MAXIMUM_PAGE_BYTES = 1024 * 1024;

export type SpaceSnapshotLease = {
  readonly id: string;
  readonly token: string;
  readonly spaceRef: string;
  readonly repoDid: string;
  readonly epochId: string;
  readonly generation: number;
  readonly rev: string;
  readonly data: Uint8Array;
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
  id: string;
  token: string;
  space_ref: string;
  repo_did: string;
  epoch_id: string;
  generation: number;
  rev: string;
  set_hash: number[];
};

type RecordRow = {
  path: string;
  collection: string;
  rkey: string;
  cid: string;
  value_cbor: number[];
  value_size: number;
  repo_rev: string;
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
  const [created, selected] = await env.ALTERAN_DB.batch([
    env.ALTERAN_DB.prepare(
      `INSERT INTO space_snapshot_lease
       (id, token, renewal_nonce, space_ref, repo_did, epoch_id, generation, rev, set_hash, expires_at, maximum_expires_at)
       SELECT ?, ?, ?, h.space_ref, h.repo_did, h.active_epoch_id, h.generation, h.rev, h.set_hash,
         unixepoch() + ?, unixepoch() + ?
       FROM space_repo h JOIN space_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
         AND e.repo_did = h.repo_did AND e.state = 'active'
       JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL
       WHERE h.space_ref = ? AND h.repo_did = ? AND h.rev IS NOT NULL`,
    ).bind(id, token, nonce, LEASE_SECONDS, MAXIMUM_LEASE_SECONDS, spaceRef, repoDid),
    env.ALTERAN_DB.prepare(
      `SELECT id, token, space_ref, repo_did, epoch_id, generation, rev, set_hash
       FROM space_snapshot_lease WHERE id = ? AND token = ? AND renewal_nonce = ?`,
    ).bind(id, token, nonce),
  ]);
  const row = selected.results?.[0] as LeaseRow | undefined;
  if (created.meta.changes !== 1 || !row) throw unavailable();
  const state = Uint8Array.from(row.set_hash);
  if (state.length !== 2048 || !isValidTid(row.rev) || !Number.isSafeInteger(row.generation) || row.generation < 1) {
    await releaseSpaceSnapshot(env, { id, token, spaceRef, repoDid, epochId: row.epoch_id, generation: row.generation, rev: row.rev, data: new Uint8Array() });
    throw new SpaceStorageError('InvalidRepoState', 'Invalid snapshot state');
  }
  return { id, token, spaceRef, repoDid, epochId: row.epoch_id, generation: row.generation, rev: row.rev, data: spaceSetHashDigest(state) };
}

export async function readSpaceSnapshotPage(
  env: Env,
  lease: SpaceSnapshotLease,
  cursor: string | null,
  limit = MAXIMUM_PAGE_RECORDS,
): Promise<{ readonly records: readonly SpaceSnapshotRecord[]; readonly cursor: string | null }> {
  const { id, token, spaceRef, repoDid, epochId, generation } = lease;
  await assertLocalRepo(env, spaceRef, repoDid);
  if (!Number.isInteger(limit) || limit < 1 || limit > MAXIMUM_PAGE_RECORDS || (cursor !== null && !validPath(cursor))) {
    throw new SpaceStorageError('InvalidRequest', 'Invalid snapshot page');
  }
  const nonce = crypto.randomUUID();
  const identity = [id, token, spaceRef, repoDid, epochId, generation] as const;
  const [renewed, selected] = await env.ALTERAN_DB.batch([
    env.ALTERAN_DB.prepare(
      `UPDATE space_snapshot_lease SET renewal_nonce = ?, expires_at = MIN(unixepoch() + ?, maximum_expires_at)
       WHERE id = ? AND token = ? AND space_ref = ? AND repo_did = ? AND epoch_id = ? AND generation = ?
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
      `WITH valid_lease AS (
         SELECT 1 FROM space_snapshot_lease l JOIN space_epoch e ON e.id = l.epoch_id
           AND e.space_ref = l.space_ref AND e.repo_did = l.repo_did AND e.state = 'active'
         JOIN space_repo h ON h.space_ref = l.space_ref AND h.repo_did = l.repo_did AND h.active_epoch_id = l.epoch_id
         JOIN space s ON s.space_ref = l.space_ref AND s.deleted_at IS NULL
         WHERE l.id = ? AND l.token = ? AND l.space_ref = ? AND l.repo_did = ? AND l.epoch_id = ?
           AND l.generation = ? AND l.renewal_nonce = ? AND l.expires_at > unixepoch()
           AND l.maximum_expires_at > unixepoch()
       ), candidates AS (
         SELECT path, from_generation, value_size FROM space_record_version
         WHERE epoch_id = ? AND space_ref = ? AND repo_did = ? AND path > ? COLLATE BINARY
           AND from_generation <= ? AND (until_generation IS NULL OR until_generation > ?)
           AND EXISTS (SELECT 1 FROM valid_lease)
         ORDER BY path COLLATE BINARY LIMIT ?
       ), sized AS (
         SELECT path, from_generation, SUM(value_size) OVER (ORDER BY path COLLATE BINARY) AS total,
           ROW_NUMBER() OVER (ORDER BY path COLLATE BINARY) AS ordinal FROM candidates
       )
       SELECT v.path, v.collection, v.rkey, v.cid, v.value_cbor, v.value_size, v.repo_rev
       FROM sized p JOIN space_record_version v ON v.epoch_id = ? AND v.space_ref = ? AND v.repo_did = ?
         AND v.path = p.path AND v.from_generation = p.from_generation
       WHERE (p.total <= ? OR p.ordinal = 1)
       UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL FROM valid_lease
       ORDER BY 1`,
    ).bind(...identity, nonce, epochId, spaceRef, repoDid, cursor ?? '', generation, generation, limit,
      epochId, spaceRef, repoDid, MAXIMUM_PAGE_BYTES),
  ]);
  if (renewed.meta.changes !== 1 || !selected.results?.length) throw unavailable();
  const rows = (selected.results as (RecordRow | { path: null })[]).filter((row): row is RecordRow => row.path !== null);
  const records = rows.map((row) => {
    if (row.value_size > MAXIMUM_PAGE_BYTES || row.value_cbor.length !== row.value_size) {
      throw new SpaceStorageError('InvalidRepoState', 'Space snapshot record exceeds the page limit');
    }
    return { path: row.path, collection: row.collection, rkey: row.rkey, cid: row.cid, value: Uint8Array.from(row.value_cbor), rev: row.repo_rev };
  });
  return { records, cursor: records.at(-1)?.path ?? null };
}

export async function releaseSpaceSnapshot(env: Env, lease: SpaceSnapshotLease): Promise<void> {
  const { id, token, spaceRef, repoDid, epochId, generation } = lease;
  await assertLocalRepo(env, spaceRef, repoDid);
  await env.ALTERAN_DB.prepare(
    `DELETE FROM space_snapshot_lease
     WHERE id = ? AND token = ? AND space_ref = ? AND repo_did = ? AND epoch_id = ? AND generation = ?`,
  ).bind(id, token, spaceRef, repoDid, epochId, generation).run();
}

export async function pruneSpaceRecordVersions(
  env: Env,
  spaceRef: string,
  repoDid: string,
  limit = 100,
): Promise<number> {
  await assertLocalRepo(env, spaceRef, repoDid);
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
    throw new SpaceStorageError('InvalidRequest', 'Invalid pruning limit');
  }
  const id = crypto.randomUUID();
  const [, , selected] = await env.ALTERAN_DB.batch([
    env.ALTERAN_DB.prepare(
      `INSERT INTO space_gc_attempt (id, space_ref, repo_did, epoch_id)
       SELECT ?, h.space_ref, h.repo_did, h.active_epoch_id FROM space_repo h
       JOIN space_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
         AND e.repo_did = h.repo_did AND e.state = 'active'
       WHERE h.space_ref = ? AND h.repo_did = ?`,
    ).bind(id, spaceRef, repoDid),
    env.ALTERAN_DB.prepare(
    `DELETE FROM space_record_version WHERE rowid IN (
       SELECT v.rowid FROM space_record_version v
       JOIN space_repo h ON h.space_ref = v.space_ref AND h.repo_did = v.repo_did AND h.active_epoch_id = v.epoch_id
       JOIN space_epoch e ON e.id = v.epoch_id AND e.space_ref = v.space_ref AND e.repo_did = v.repo_did AND e.state = 'active'
       WHERE v.space_ref = ? AND v.repo_did = ? AND v.until_generation IS NOT NULL
         AND EXISTS (SELECT 1 FROM space_gc_attempt g WHERE g.id = ? AND g.space_ref = v.space_ref
           AND g.repo_did = v.repo_did AND g.epoch_id = v.epoch_id)
         AND NOT EXISTS (
           SELECT 1 FROM space_snapshot_lease l WHERE l.epoch_id = v.epoch_id AND l.space_ref = v.space_ref
             AND l.repo_did = v.repo_did AND l.expires_at > unixepoch() AND l.maximum_expires_at > unixepoch()
             AND l.generation >= v.from_generation AND l.generation < v.until_generation
         ) ORDER BY v.until_generation LIMIT ?
     )`,
    ).bind(spaceRef, repoDid, id, limit),
    env.ALTERAN_DB.prepare('SELECT changes() AS count'),
    env.ALTERAN_DB.prepare('DELETE FROM space_gc_attempt WHERE id = ?').bind(id),
    env.ALTERAN_DB.prepare(
      `SELECT CASE WHEN EXISTS (SELECT 1 FROM space_gc_attempt WHERE id = ?) THEN json('{') ELSE 1 END AS valid`,
    ).bind(id),
  ]);
  const count = (selected.results?.[0] as { count: number } | undefined)?.count;
  if (!Number.isSafeInteger(count) || count === undefined || count < 0) {
    throw new SpaceStorageError('InvalidRepoState', 'Invalid pruning result');
  }
  return count;
}

export async function pruneExpiredSpaceSnapshotLeases(
  env: Env,
  spaceRef: string,
  repoDid: string,
  limit = 100,
): Promise<number> {
  await assertLocalRepo(env, spaceRef, repoDid);
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
    throw new SpaceStorageError('InvalidRequest', 'Invalid pruning limit');
  }
  const result = await env.ALTERAN_DB.prepare(
    `DELETE FROM space_snapshot_lease WHERE id IN (
       SELECT id FROM space_snapshot_lease WHERE space_ref = ? AND repo_did = ?
         AND (expires_at <= unixepoch() OR maximum_expires_at <= unixepoch())
       ORDER BY expires_at LIMIT ?
     ) AND space_ref = ? AND repo_did = ?
       AND (expires_at <= unixepoch() OR maximum_expires_at <= unixepoch())`,
  ).bind(spaceRef, repoDid, limit, spaceRef, repoDid).run();
  return result.meta.changes;
}

async function assertLocalRepo(env: Env, spaceRef: string, repoDid: string): Promise<void> {
  parseSpaceRef(spaceRef);
  await assertLocalSpaceRepo(env, repoDid);
}

function validPath(path: string): boolean {
  const parts = path.split('/');
  return parts.length === 2 && isValidNsid(parts[0]) && isValidRecordKey(parts[1]);
}

function unavailable(): SpaceStorageError {
  return new SpaceStorageError('SpaceSnapshotUnavailable', 'Space snapshot is unavailable');
}
