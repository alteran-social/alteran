import { isValidNsid, isValidRecordKey, isValidTid } from '@atproto/syntax-spaces';
import type { Env } from '../env';
import { applySpaceSetHashChanges, spaceRecordHashElement } from '../lib/spaces/lthash';
import { copyPlainRecord } from '../lib/spaces/plain-values';
import { assertLocalSpaceRepo, parseSpaceRef } from './space-ref';
import { isSpaceOwnerIncarnation } from './space-owner-incarnation';
import { checkpointQuarantine, finishQuarantine } from './space-quarantine-checkpoint';
import { COMPLETE_QUARANTINE_CURSOR, COMPLETE_QUARANTINE_RESULT, FAILED_QUARANTINE_RESULT, LIVE_QUARANTINE_JOB, PINNED_QUARANTINE_JOB, QUARANTINE_CURRENT_PAGE, QUARANTINE_RECORD_BYTES, QUARANTINE_VERSION_PAGE } from './space-quarantine-sql';
import { quarantineJobArgs, type QuarantineJobRow, type SpaceQuarantineHandle, type SpaceQuarantineStep } from './space-quarantine-types';
import { verifySpaceRecordBlock } from './space-verify-record';

const LEASE_SECONDS = 60;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

type VersionRow = {
  path: string; collection: string; rkey: string; cid: string; repo_rev: string;
  from_generation: number; until_generation: number | null; space_ref: string; repo_did: string;
  value_size: number; actual_size: number; value_type: string; duplicate: number; valid: number; sentinel: number;
};

type CurrentRow = {
  path: string; collection: string; rkey: string; cid: string; repo_rev: string;
  actual_size: number; value_type: string; valid: number; sentinel: number;
};

/** Start or reclaim a job for a captured owner; the repo remains quarantined. */
export async function claimSpaceQuarantine(
  env: Env,
  spaceRef: string,
  repoDid: string,
  ownerIncarnation: string,
): Promise<SpaceQuarantineHandle | null> {
  const ref = parseSpaceRef(spaceRef);
  if (!isSpaceOwnerIncarnation(ownerIncarnation)) return null;
  await assertLocalSpaceRepo(env, repoDid);
  try {
    const existing = await env.ALTERAN_DB.prepare(
      `SELECT CASE WHEN typeof(j.id) = 'text' AND length(CAST(j.id AS BLOB)) = 36 THEN j.id END AS id
       FROM space_quarantine_job j JOIN space_repo h ON h.space_ref = j.space_ref
       AND h.repo_did = j.repo_did AND h.active_epoch_id = j.epoch_id
       JOIN space_owned_epoch e ON e.id = j.epoch_id AND e.space_ref = j.space_ref
         AND e.repo_did = j.repo_did AND e.state = 'quarantined'
       JOIN space s ON s.space_ref = j.space_ref AND s.deleted_at IS NULL
       WHERE j.space_ref = ? AND j.repo_did = ? AND e.owner_incarnation = ?`,
    ).bind(spaceRef, repoDid, ownerIncarnation).first<{ id: string | null }>();
    if (existing && !validUuid(existing.id)) return null;
    const id = existing?.id ?? crypto.randomUUID();
    const token = crypto.randomUUID();
    const nonce = crypto.randomUUID();
    const identity = [id, token, nonce, spaceRef, repoDid, ownerIncarnation] as const;
    const [, , selected] = await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(
        `INSERT INTO space_quarantine_job
         (id, token, renewal_nonce, space_ref, repo_did, epoch_id, authority_did, space_type, skey,
          generation, mutation_id, rev, expected_hash, accumulated_hash, cursor, sequence, record_count,
          lease_until, status, created_at)
         SELECT ?, ?, ?, h.space_ref, h.repo_did, h.active_epoch_id, s.authority_did, s.space_type, s.skey,
          h.generation, h.mutation_id, h.rev, h.set_hash, zeroblob(2048), '', 0, 0, unixepoch() + ?, 'running', unixepoch()
         FROM space_repo h JOIN space_owned_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
           AND e.repo_did = h.repo_did AND e.state = 'quarantined'
         JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL
         WHERE h.space_ref = ? AND h.repo_did = ? AND e.owner_incarnation = ?
           AND typeof(h.active_epoch_id) = 'text' AND length(CAST(h.active_epoch_id AS BLOB)) BETWEEN 1 AND 128
           AND typeof(h.generation) = 'integer' AND h.generation BETWEEN 1 AND 9007199254740991
           AND typeof(h.mutation_id) = 'text' AND length(CAST(h.mutation_id AS BLOB)) BETWEEN 1 AND 8192
           AND typeof(h.rev) = 'text' AND length(CAST(h.rev AS BLOB)) = 13
           AND typeof(h.set_hash) = 'blob' AND length(h.set_hash) = 2048
           AND s.authority_did = ? AND s.space_type = ? AND s.skey = ?
           AND NOT EXISTS (SELECT 1 FROM space_quarantine_job existing
             WHERE existing.id = ? OR (existing.space_ref = h.space_ref
               AND existing.repo_did = h.repo_did AND existing.epoch_id = h.active_epoch_id))
         ON CONFLICT(space_ref, repo_did, epoch_id) DO NOTHING`,
      ).bind(id, token, nonce, LEASE_SECONDS, spaceRef, repoDid, ownerIncarnation,
        ref.authorityDid, ref.spaceType, ref.skey, id),
      env.ALTERAN_DB.prepare(
        `UPDATE space_quarantine_job SET token = ?, renewal_nonce = ?, lease_until = unixepoch() + ?, sequence = sequence + 1
         WHERE id = ? AND space_ref = ? AND repo_did = ? AND status IN ('running', 'complete') AND lease_until <= unixepoch()
           AND sequence < ? AND EXISTS (
             SELECT 1 FROM space_repo h JOIN space_owned_epoch e ON e.id = h.active_epoch_id
               AND e.space_ref = h.space_ref AND e.repo_did = h.repo_did AND e.state = 'quarantined'
             JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL
             WHERE h.space_ref = space_quarantine_job.space_ref AND h.repo_did = space_quarantine_job.repo_did
               AND h.active_epoch_id = space_quarantine_job.epoch_id AND h.generation = space_quarantine_job.generation
               AND h.mutation_id = space_quarantine_job.mutation_id AND h.rev = space_quarantine_job.rev
               AND h.set_hash = space_quarantine_job.expected_hash AND s.authority_did = space_quarantine_job.authority_did
               AND s.space_type = space_quarantine_job.space_type AND s.skey = space_quarantine_job.skey
               AND e.owner_incarnation = ?
           )`,
      ).bind(token, nonce, LEASE_SECONDS, id, spaceRef, repoDid, MAX_SAFE, ownerIncarnation),
      env.ALTERAN_DB.prepare(`${PINNED_QUARANTINE_JOB} AND j.status IN ('running', 'complete')`).bind(...identity),
      env.ALTERAN_DB.prepare(`SELECT CASE WHEN EXISTS (${PINNED_QUARANTINE_JOB} AND j.status IN ('running', 'complete'))
        THEN 1 ELSE json('{') END AS valid`).bind(...identity),
    ]);
    if (selected.results?.length !== 1 || !validUuid(id)) return null;
    return Object.freeze({ id, token, spaceRef, repoDid, ownerIncarnation });
  } catch {
    return null;
  }
}

/** Verify at most one frozen record and checkpoint its accumulated set hash. */
export async function stepSpaceQuarantine(env: Env, input: SpaceQuarantineHandle): Promise<SpaceQuarantineStep> {
  const handle = copyQuarantineHandle(input);
  if (!handle) return { tag: 'invalid' };
  try {
    parseSpaceRef(handle.spaceRef);
    await assertLocalSpaceRepo(env, handle.repoDid);
  } catch {
    return { tag: 'invalid' };
  }
  const nonce = crypto.randomUUID();
  const identity = quarantineJobArgs(handle, nonce);
  let job: QuarantineJobRow;
  let version: VersionRow | null;
  let current: CurrentRow | null;
  try {
    const [, selected, completed, failed] = await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(
        `UPDATE space_quarantine_job SET renewal_nonce = ?, lease_until = unixepoch() + ?
         WHERE id = ? AND token = ? AND space_ref = ? AND repo_did = ? AND status = 'running' AND lease_until > unixepoch()
           AND EXISTS (
             SELECT 1 FROM space_repo h JOIN space_owned_epoch e ON e.id = h.active_epoch_id
               AND e.space_ref = h.space_ref AND e.repo_did = h.repo_did AND e.state = 'quarantined'
             JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL
             WHERE h.space_ref = space_quarantine_job.space_ref AND h.repo_did = space_quarantine_job.repo_did
               AND h.active_epoch_id = space_quarantine_job.epoch_id AND h.generation = space_quarantine_job.generation
               AND h.mutation_id = space_quarantine_job.mutation_id AND h.rev = space_quarantine_job.rev
               AND h.set_hash = space_quarantine_job.expected_hash AND s.authority_did = space_quarantine_job.authority_did
               AND s.space_type = space_quarantine_job.space_type AND s.skey = space_quarantine_job.skey
               AND e.owner_incarnation = ?
           )`,
      ).bind(nonce, LEASE_SECONDS, handle.id, handle.token, handle.spaceRef, handle.repoDid, handle.ownerIncarnation),
      env.ALTERAN_DB.prepare(LIVE_QUARANTINE_JOB).bind(...identity),
      env.ALTERAN_DB.prepare(COMPLETE_QUARANTINE_CURSOR)
        .bind(handle.id, handle.token, handle.spaceRef, handle.repoDid, handle.ownerIncarnation),
      env.ALTERAN_DB.prepare(FAILED_QUARANTINE_RESULT)
        .bind(handle.id, handle.token, handle.spaceRef, handle.repoDid, handle.ownerIncarnation),
      env.ALTERAN_DB.prepare(`SELECT CASE WHEN EXISTS (${LIVE_QUARANTINE_JOB})
        OR EXISTS (${COMPLETE_QUARANTINE_CURSOR}) OR EXISTS (${FAILED_QUARANTINE_RESULT})
        THEN 1 ELSE json('{') END AS valid`).bind(...identity,
          handle.id, handle.token, handle.spaceRef, handle.repoDid, handle.ownerIncarnation,
          handle.id, handle.token, handle.spaceRef, handle.repoDid, handle.ownerIncarnation),
    ]);
    const completedJob = completed.results?.[0] as { cursor: unknown } | undefined;
    if (completedJob) {
      if (typeof completedJob.cursor !== 'string' || !validCursor(completedJob.cursor)) return { tag: 'invalid' };
      return await readCompletedResult(env, handle, completedJob.cursor);
    }
    const failedJob = failed.results?.[0] as { failure_reason?: unknown } | undefined;
    if (failedJob) return failedResult(failedJob);
    if (selected.results?.length !== 1) return { tag: 'unavailable' };
    job = selected.results[0] as QuarantineJobRow;
    if (!validQuarantineJob(job)) return { tag: 'invalid' };
    const pageArgs = [...identity, job.cursor, job.sequence, Uint8Array.from(job.accumulated_hash), job.record_count, job.cursor] as const;
    const [versions, records] = await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(QUARANTINE_VERSION_PAGE).bind(...pageArgs),
      env.ALTERAN_DB.prepare(QUARANTINE_CURRENT_PAGE).bind(...pageArgs),
    ]);
    const versionPage = extractPage<VersionRow>(versions.results);
    const currentPage = extractPage<CurrentRow>(records.results);
    if (!versionPage || !currentPage) return { tag: 'unavailable' };
    version = versionPage.row;
    current = currentPage.row;
  } catch {
    return { tag: 'unavailable' };
  }
  if (!version && !current) return finish(env, handle, nonce, job);
  if (!version || !current || !matchingRows(version, current, job, handle)) return fail(env, handle, nonce, job, 'invalid');
  const read = await readRecord(env, handle, nonce, job, version);
  if (read.tag !== 'ok') {
    return read.tag === 'invalid' ? fail(env, handle, nonce, job, 'invalid') : { tag: 'unavailable' };
  }
  const verified = verifySpaceRecordBlock(version.collection, version.rkey, version.cid, read.bytes);
  if (verified !== 'valid') return fail(env, handle, nonce, job, verified);
  const nextHash = applySpaceSetHashChanges(Uint8Array.from(job.accumulated_hash), [{
    action: 'add', element: spaceRecordHashElement(version.collection, version.rkey, version.cid),
  }]);
  return await checkpointQuarantine(env, handle, nonce, job, version.path, nextHash)
    ? { tag: 'progress', records: job.record_count + 1 }
    : { tag: 'unavailable' };
}

function extractPage<T extends { sentinel: number }>(rows: unknown[] | undefined): { row: T | null } | null {
  if (!rows) return null;
  const sentinel = rows.filter((row) => row && typeof row === 'object' && 'sentinel' in row && row.sentinel === 1);
  const data = rows.filter((row) => row && typeof row === 'object' && 'sentinel' in row && row.sentinel === 0);
  if (sentinel.length !== 1 || data.length > 1 || sentinel.length + data.length !== rows.length) return null;
  return { row: (data[0] as T | undefined) ?? null };
}

export function validQuarantineJob(job: QuarantineJobRow): boolean {
  return typeof job.rev === 'string' && isValidTid(job.rev) && Number.isSafeInteger(job.generation) && job.generation >= 1 &&
    Number.isSafeInteger(job.sequence) && job.sequence >= 0 && job.sequence < MAX_SAFE &&
    Number.isSafeInteger(job.record_count) && job.record_count >= 0 && job.record_count < MAX_SAFE &&
    typeof job.cursor === 'string' && validCursor(job.cursor) && validBytes(job.expected_hash, 2048) && validBytes(job.accumulated_hash, 2048);
}

function matchingRows(version: VersionRow, current: CurrentRow, job: QuarantineJobRow, handle: SpaceQuarantineHandle): boolean {
  return version.valid === 1 && current.valid === 1 &&
    typeof version.collection === 'string' && isValidNsid(version.collection) &&
    typeof version.rkey === 'string' && isValidRecordKey(version.rkey) &&
    version.path === `${version.collection}/${version.rkey}` && version.path > job.cursor &&
    version.path === current.path && version.collection === current.collection && version.rkey === current.rkey &&
    version.cid === current.cid && typeof version.cid === 'string' &&
    version.repo_rev === current.repo_rev && typeof version.repo_rev === 'string' &&
    isValidTid(version.repo_rev) && version.repo_rev <= job.rev &&
    version.from_generation === job.generation && version.until_generation === null && version.duplicate === 0 &&
    version.space_ref === handle.spaceRef && version.repo_did === handle.repoDid &&
    Number.isSafeInteger(version.value_size) && version.value_size > 0 && version.value_size <= 1024 * 1024 &&
    version.actual_size === version.value_size && current.actual_size === version.value_size &&
    version.value_type === 'blob' && current.value_type === 'blob';
}

function validCursor(cursor: string): boolean {
  if (cursor === '') return true;
  if (cursor.length > 830) return false;
  const parts = cursor.split('/');
  return parts.length === 2 && isValidNsid(parts[0]) && isValidRecordKey(parts[1]);
}

async function readRecord(
  env: Env,
  handle: SpaceQuarantineHandle,
  nonce: string,
  job: QuarantineJobRow,
  version: VersionRow,
): Promise<{ tag: 'ok'; bytes: Uint8Array } | { tag: 'invalid' | 'unavailable' }> {
  const identity = quarantineJobArgs(handle, nonce);
  const oldHash = Uint8Array.from(job.accumulated_hash);
  try {
    const result = await env.ALTERAN_DB.prepare(QUARANTINE_RECORD_BYTES).bind(
      ...identity, job.sequence, job.cursor, oldHash, version.path, version.cid, version.repo_rev,
      version.from_generation, version.value_size, job.sequence, job.cursor, oldHash,
    ).all<{ value_cbor: number[] | null }>();
    const rows = (result.results ?? []) as { value_cbor: number[] | null }[];
    const data = rows.filter((row) => row.value_cbor !== null);
    if (rows.filter((row) => row.value_cbor === null).length !== 1) return { tag: 'unavailable' };
    const value = data[0]?.value_cbor;
    if (data.length !== 1 || !validBytes(value, version.value_size)) return { tag: 'invalid' };
    return { tag: 'ok', bytes: Uint8Array.from(value) };
  } catch {
    return { tag: 'unavailable' };
  }
}

async function finish(env: Env, handle: SpaceQuarantineHandle, nonce: string, job: QuarantineJobRow): Promise<SpaceQuarantineStep> {
  try {
    const hasBlob = await env.ALTERAN_DB.prepare(
      `WITH live AS (${LIVE_QUARANTINE_JOB}) SELECT EXISTS (
         SELECT 1 FROM space_blob_usage b JOIN live j ON b.space_ref = j.space_ref AND b.repo_did = j.repo_did
       ) AS present FROM live`,
    ).bind(...quarantineJobArgs(handle, nonce)).first<{ present: number }>();
    if (!hasBlob) return { tag: 'unavailable' };
    if (hasBlob.present) return fail(env, handle, nonce, job, 'unsupported');
    if (job.expected_hash.some((byte, index) => byte !== job.accumulated_hash[index])) return fail(env, handle, nonce, job, 'invalid');
    if (await finishQuarantine(env, handle, nonce, job, 'complete')) {
      return { tag: 'complete', records: job.record_count };
    }
    return await readCompletedResult(env, handle, job.cursor);
  } catch {
    return { tag: 'unavailable' };
  }
}

async function fail(
  env: Env,
  handle: SpaceQuarantineHandle,
  nonce: string,
  job: QuarantineJobRow,
  tag: 'invalid' | 'unsupported',
): Promise<SpaceQuarantineStep> {
  if (await finishQuarantine(env, handle, nonce, job, tag)) return { tag };
  try {
    const failed = await env.ALTERAN_DB.prepare(FAILED_QUARANTINE_RESULT)
      .bind(handle.id, handle.token, handle.spaceRef, handle.repoDid, handle.ownerIncarnation)
      .first<{ failure_reason?: unknown }>();
    return failed ? failedResult(failed) : { tag: 'unavailable' };
  } catch {
    return { tag: 'unavailable' };
  }
}

function completedResult(job: QuarantineJobRow): SpaceQuarantineStep {
  return validQuarantineJob(job) ? { tag: 'complete', records: job.record_count } : { tag: 'invalid' };
}

async function readCompletedResult(env: Env, handle: SpaceQuarantineHandle, cursor: string): Promise<SpaceQuarantineStep> {
  const completed = await env.ALTERAN_DB.prepare(COMPLETE_QUARANTINE_RESULT)
    .bind(handle.id, handle.token, handle.spaceRef, handle.repoDid, handle.ownerIncarnation, cursor, cursor, cursor)
    .first<QuarantineJobRow>();
  return completed ? completedResult(completed) : { tag: 'unavailable' };
}

function failedResult(job: { failure_reason?: unknown }): SpaceQuarantineStep {
  return job.failure_reason === 'invalid' || job.failure_reason === 'unsupported'
    ? { tag: job.failure_reason }
    : { tag: 'unavailable' };
}

function validBytes(value: unknown, length: number): value is number[] {
  return Array.isArray(value) && value.length === length && value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255);
}

export function copyQuarantineHandle(value: SpaceQuarantineHandle): SpaceQuarantineHandle | null {
  try {
    const fields = copyPlainRecord(value, ['id', 'token', 'spaceRef', 'repoDid', 'ownerIncarnation']);
    if (!fields) return null;
    const { id, token, spaceRef, repoDid, ownerIncarnation } = fields;
    if (!validUuid(id) || !validUuid(token) || typeof spaceRef !== 'string' || typeof repoDid !== 'string' ||
      !isSpaceOwnerIncarnation(ownerIncarnation)) return null;
    return { id, token, spaceRef, repoDid, ownerIncarnation };
  } catch {
    return null;
  }
}

function validUuid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
}
