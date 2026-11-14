import type { Env } from '../env';
import { assertLocalSpaceRepo, parseSpaceRef } from './space-ref';
import { ACTIVATED_JOB, ACTIVATING_JOB, ACTIVATION_PRECONDITIONS, ACTIVE_QUARANTINE_RECEIPT, COMPLETED_JOB } from './space-quarantine-activation-sql';
import { copyQuarantineHandle, validQuarantineJob } from './space-quarantine';
import { quarantineJobArgs, type QuarantineJobRow, type SpaceQuarantineHandle } from './space-quarantine-types';

/** Activate a completed internal verification job. The deployment guard remains closed. */
export async function activateSpaceQuarantine(
  env: Env,
  input: SpaceQuarantineHandle,
): Promise<'active' | 'invalid' | 'unavailable'> {
  const handle = copyQuarantineHandle(input);
  if (!handle) return 'invalid';
  let activationNonce: string | undefined;
  try {
    parseSpaceRef(handle.spaceRef);
    await assertLocalSpaceRepo(env, handle.repoDid);
    if (await hasActiveReceipt(env, handle)) return 'active';
    const selected = await env.ALTERAN_DB.prepare(
      `SELECT CASE WHEN typeof(j.renewal_nonce) = 'text' AND length(CAST(j.renewal_nonce AS BLOB)) = 36
         THEN j.renewal_nonce END AS renewal_nonce FROM space_quarantine_job j
       JOIN space_owned_epoch e ON e.id = j.epoch_id AND e.space_ref = j.space_ref
         AND e.repo_did = j.repo_did AND e.state = 'quarantined'
       JOIN space_repo h ON h.space_ref = j.space_ref AND h.repo_did = j.repo_did AND h.active_epoch_id = j.epoch_id
       JOIN space s ON s.space_ref = j.space_ref AND s.deleted_at IS NULL
       WHERE j.id = ? AND j.token = ? AND j.space_ref = ? AND j.repo_did = ? AND e.owner_incarnation = ?
         AND j.status = 'complete' AND j.lease_until > unixepoch()`,
    ).bind(handle.id, handle.token, handle.spaceRef, handle.repoDid, handle.ownerIncarnation)
      .first<{ renewal_nonce: string }>();
    if (!selected || typeof selected.renewal_nonce !== 'string') return 'unavailable';
    const identity = quarantineJobArgs(handle, selected.renewal_nonce);
    const job = await env.ALTERAN_DB.prepare(COMPLETED_JOB).bind(...identity).first<QuarantineJobRow>();
    if (!job || !validQuarantineJob(job) || job.sequence >= Number.MAX_SAFE_INTEGER - 2) return 'unavailable';
    const nonce = crypto.randomUUID();
    activationNonce = nonce;
    const hash = Uint8Array.from(job.expected_hash);
    const accumulated = Uint8Array.from(job.accumulated_hash);
    const snapshot = [job.sequence, job.cursor, hash, accumulated, job.record_count] as const;
    const eof = [job.cursor, job.cursor] as const;
    const exact = `j.sequence = ? AND j.cursor = ? AND j.expected_hash = ?
      AND j.accumulated_hash = ? AND j.record_count = ?`;
    const final = `SELECT 1 AS active FROM (${ACTIVATED_JOB}) j
      WHERE j.status = 'active' AND j.activation_nonce = ? AND j.sequence = ? AND j.cursor = ?
        AND j.expected_hash = ? AND j.accumulated_hash = ? AND j.record_count = ?
        AND ${ACTIVATION_PRECONDITIONS}`;
    const finalArgs = [...identity, nonce, job.sequence + 2, job.cursor, hash, accumulated, job.record_count, ...eof] as const;
    const result = await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(`
        UPDATE space_quarantine_job SET status = 'activating', activation_nonce = ?, sequence = sequence + 1
        WHERE id = ? AND EXISTS (
          SELECT 1 FROM (${COMPLETED_JOB}) j
          WHERE j.id = space_quarantine_job.id AND ${exact} AND ${ACTIVATION_PRECONDITIONS}
        )
      `).bind(nonce, handle.id, ...identity, ...snapshot, ...eof),
      env.ALTERAN_DB.prepare(`
        UPDATE space_epoch SET state = 'active', verified_job_id = ?, activation_nonce = ?
        WHERE id = ? AND space_ref = ? AND repo_did = ? AND state = 'quarantined' AND EXISTS (
          SELECT 1 FROM (${ACTIVATING_JOB}) j WHERE j.id = ? AND j.activation_nonce = ?
            AND j.sequence = ? AND j.cursor = ? AND j.expected_hash = ?
            AND j.accumulated_hash = ? AND j.record_count = ? AND ${ACTIVATION_PRECONDITIONS}
        )
      `).bind(handle.id, nonce, job.epoch_id, handle.spaceRef, handle.repoDid,
        ...identity, handle.id, nonce, job.sequence + 1, job.cursor, hash, accumulated, job.record_count, ...eof),
      env.ALTERAN_DB.prepare(`
        UPDATE space_quarantine_job SET status = 'active', sequence = sequence + 1
        WHERE id = ? AND EXISTS (
          SELECT 1 FROM (${ACTIVATED_JOB}) j WHERE j.id = space_quarantine_job.id
            AND j.status = 'activating' AND j.activation_nonce = ?
            AND j.sequence = ? AND j.cursor = ? AND j.expected_hash = ?
            AND j.accumulated_hash = ? AND j.record_count = ? AND ${ACTIVATION_PRECONDITIONS}
        )
      `).bind(handle.id, ...identity, nonce, job.sequence + 1, job.cursor, hash, accumulated, job.record_count, ...eof),
      env.ALTERAN_DB.prepare(`
        SELECT CASE WHEN EXISTS (${final}) THEN 1 ELSE json('{') END AS active
      `).bind(...finalArgs),
    ]);
    const observed = result[3]?.results?.[0] as { active?: unknown } | undefined;
    if (observed?.active !== 1) throw new Error('Activation postcondition unavailable');
    return 'active';
  } catch {
    if (activationNonce) {
      try {
        if (await hasActiveReceipt(env, handle, activationNonce)) return 'active';
      } catch {
        // The outcome remains unavailable until the stored job can be inspected.
      }
    }
    return 'unavailable';
  }
}

async function hasActiveReceipt(env: Env, handle: SpaceQuarantineHandle, nonce?: string): Promise<boolean> {
  const receipt = await env.ALTERAN_DB.prepare(ACTIVE_QUARANTINE_RECEIPT).bind(
    handle.id, handle.token, handle.spaceRef, handle.repoDid, handle.ownerIncarnation, nonce ?? null, nonce ?? null,
  ).first<{ activation_nonce: unknown }>();
  return typeof receipt?.activation_nonce === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(receipt.activation_nonce);
}
