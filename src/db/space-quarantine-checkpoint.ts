import type { Env } from '../env';
import { LIVE_QUARANTINE_JOB, PINNED_QUARANTINE_JOB } from './space-quarantine-sql';
import { quarantineJobArgs, quarantineJobKeyArgs, type QuarantineJobRow, type SpaceQuarantineHandle } from './space-quarantine-types';

const PREVIOUS = `id = ? AND token = ? AND renewal_nonce = ? AND space_ref = ? AND repo_did = ?
  AND sequence = ? AND cursor = ? AND accumulated_hash = ? AND lease_until > unixepoch()
  AND EXISTS (SELECT 1 FROM (${LIVE_QUARANTINE_JOB}) l WHERE l.id = space_quarantine_job.id)`;

export async function checkpointQuarantine(
  env: Env,
  handle: SpaceQuarantineHandle,
  nonce: string,
  job: QuarantineJobRow,
  path: string,
  nextHash: Uint8Array,
): Promise<boolean> {
  const identity = quarantineJobArgs(handle, nonce);
  const oldHash = Uint8Array.from(job.accumulated_hash);
  try {
    await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(
        `UPDATE space_quarantine_job SET cursor = ?, accumulated_hash = ?, sequence = sequence + 1,
           record_count = record_count + 1 WHERE ${PREVIOUS}`,
      ).bind(path, nextHash, ...quarantineJobKeyArgs(handle, nonce), job.sequence, job.cursor, oldHash, ...identity),
      env.ALTERAN_DB.prepare(
        `WITH live AS (${LIVE_QUARANTINE_JOB}) SELECT CASE WHEN EXISTS (
           SELECT 1 FROM live WHERE sequence = ? AND cursor = ? AND accumulated_hash = ? AND record_count = ?
         ) THEN 1 ELSE json('{') END AS valid`,
      ).bind(...identity, job.sequence + 1, path, nextHash, job.record_count + 1),
    ]);
    return true;
  } catch {
    return false;
  }
}

export async function finishQuarantine(
  env: Env,
  handle: SpaceQuarantineHandle,
  nonce: string,
  job: QuarantineJobRow,
  outcome: 'complete' | 'invalid' | 'unsupported',
): Promise<boolean> {
  const identity = quarantineJobArgs(handle, nonce);
  const oldHash = Uint8Array.from(job.accumulated_hash);
  const status = outcome === 'complete' ? 'complete' : 'failed';
  const failureReason = outcome === 'complete' ? null : outcome;
  const completion = outcome === 'complete'
    ? `AND accumulated_hash = expected_hash
       AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = space_quarantine_job.space_ref
         AND b.repo_did = space_quarantine_job.repo_did)
       AND NOT EXISTS (SELECT 1 FROM space_record_version v WHERE v.epoch_id = space_quarantine_job.epoch_id
         AND v.path COLLATE BINARY > ? COLLATE BINARY)
       AND NOT EXISTS (SELECT 1 FROM space_record r WHERE r.space_ref = space_quarantine_job.space_ref
         AND r.repo_did = space_quarantine_job.repo_did
         AND (r.collection || '/' || r.rkey) COLLATE BINARY > ? COLLATE BINARY)`
    : '';
  try {
    await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(
        `UPDATE space_quarantine_job SET status = ?, failure_reason = ?, sequence = sequence + 1 WHERE ${PREVIOUS} ${completion}`,
      ).bind(status, failureReason, ...quarantineJobKeyArgs(handle, nonce), job.sequence, job.cursor, oldHash, ...identity,
        ...(outcome === 'complete' ? [job.cursor, job.cursor] : [])),
      env.ALTERAN_DB.prepare(
        `WITH pinned AS (${PINNED_QUARANTINE_JOB}) SELECT CASE WHEN EXISTS (
           SELECT 1 FROM pinned WHERE status = ? AND failure_reason IS ? AND sequence = ?
             AND cursor = ? AND accumulated_hash = ? AND record_count = ?
         ) THEN 1 ELSE json('{') END AS valid`,
      ).bind(...identity, status, failureReason, job.sequence + 1, job.cursor, oldHash, job.record_count),
    ]);
    return true;
  } catch {
    return false;
  }
}
