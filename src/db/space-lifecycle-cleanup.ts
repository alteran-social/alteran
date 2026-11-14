import type { Env } from "../env";
import { getPersonalSpaceDeletion } from "./space-lifecycle-delete";
import {
  assertCleanupCandidates,
  CLEANUP_PHASES,
  type CleanupPhase,
  insertCleanupCandidates,
} from "./space-lifecycle-cleanup-sql";
import {
  captureDeletionHandle,
  invalidLifecycleRequest,
  type PersonalDeletionHandle,
  type PersonalDeletionStep,
  validLifecycleNonce,
} from "./space-lifecycle-types";

const MAXIMUM_BATCH_SIZE = 32;

/** Remove one bounded candidate page and persist a retryable step receipt. */
export async function stepPersonalSpaceDeletion(
  env: Env,
  input: PersonalDeletionHandle,
  expectedSequence: number,
  stepNonce: string,
  batchSize = MAXIMUM_BATCH_SIZE,
): Promise<PersonalDeletionStep> {
  const handle = captureDeletionHandle(input);
  if (
    !Number.isSafeInteger(expectedSequence) || expectedSequence < 0 ||
    expectedSequence >= Number.MAX_SAFE_INTEGER ||
    !validLifecycleNonce(stepNonce) || !Number.isInteger(batchSize) ||
    batchSize < 1 || batchSize > MAXIMUM_BATCH_SIZE
  ) {
    throw invalidLifecycleRequest();
  }
  const initial = await getPersonalSpaceDeletion(env, handle);
  if (!initial) return { tag: "unavailable" };
  if (
    initial.sequence === expectedSequence + 1 &&
    initial.lastStepNonce === stepNonce
  ) {
    return {
      tag: initial.status === "complete" ? "complete" : "progress",
      status: initial,
    };
  }
  if (initial.sequence !== expectedSequence) return { tag: "conflict" };
  if (initial.status === "complete") {
    return { tag: "complete", status: initial };
  }
  if (initial.phase === "done") return { tag: "unavailable" };
  const phase: CleanupPhase = initial.phase;
  const sql = CLEANUP_PHASES[phase];
  const scanArguments = phase === "versions"
    ? [stepNonce, batchSize] as const
    : [handle.spaceRef, handle.authorityDid, batchSize] as const;
  const remainingArguments = phase === "versions"
    ? [handle.nonce] as const
    : [handle.spaceRef, handle.authorityDid] as const;
  const removeArguments = phase === "versions"
    ? [stepNonce, handle.spaceRef, handle.authorityDid, stepNonce] as const
    : [stepNonce, handle.spaceRef, handle.authorityDid] as const;
  const terminalStatements = phase === "ops" ? [
    env.ALTERAN_DB.prepare(`UPDATE space_repo SET rev = NULL, generation = 0,
      mutation_id = ?, set_hash = zeroblob(2048)
      WHERE space_ref = ? AND repo_did = ? AND EXISTS (
        SELECT 1 FROM space_personal_deletion_job j
        JOIN space_personal_deletion_attempt a ON a.job_nonce = j.nonce
          AND a.nonce = ? AND a.sequence = j.sequence AND a.phase = 'ops' AND a.status = 'sealed'
        WHERE j.nonce = ? AND j.space_ref = space_repo.space_ref AND j.authority_did = space_repo.repo_did
          AND j.epoch_id = space_repo.active_epoch_id AND j.status = 'deleting' AND j.phase = 'ops'
          AND NOT EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = j.space_ref)
      )`).bind(handle.nonce, handle.spaceRef, handle.authorityDid, stepNonce, handle.nonce),
    env.ALTERAN_DB.prepare(`SELECT CASE WHEN EXISTS (
      SELECT 1 FROM space_personal_deletion_job j WHERE j.nonce = ? AND j.space_ref = ?
        AND j.authority_did = ? AND j.sequence = ? AND j.status = 'deleting' AND j.phase = 'ops'
        AND (EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = j.space_ref)
          OR (j.epoch_id IS NULL AND NOT EXISTS (SELECT 1 FROM space_repo h WHERE h.space_ref = j.space_ref))
          OR EXISTS (SELECT 1 FROM space_repo h WHERE h.space_ref = j.space_ref AND h.repo_did = j.authority_did
            AND h.active_epoch_id = j.epoch_id AND h.rev IS NULL AND h.generation = 0
            AND h.mutation_id IS j.nonce AND typeof(h.set_hash) = 'blob' AND h.set_hash = zeroblob(2048)))
    ) THEN 1 ELSE json('{') END AS valid`)
      .bind(handle.nonce, handle.spaceRef, handle.authorityDid, expectedSequence),
  ] : [];
  try {
    await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(`INSERT INTO space_personal_deletion_attempt
        (nonce, job_nonce, space_ref, authority_did, epoch_id, phase, sequence, status, maximum_count, expected_count, expected_bytes)
        SELECT ?, j.nonce, j.space_ref, j.authority_did, j.epoch_id, j.phase, j.sequence, 'building', ?, 0, 0
        FROM space_personal_deletion_job j JOIN space_personal_policy p
          ON p.space_ref = j.space_ref AND p.authority_did = j.authority_did
        JOIN account owner ON owner.did = p.authority_did AND owner.space_incarnation = p.authority_incarnation
        JOIN account_state state ON state.did = owner.did
        WHERE j.nonce = ? AND j.space_ref = ? AND j.authority_did = ?
          AND p.authority_incarnation = ? AND typeof(state.active) = 'integer' AND state.active = 1
          AND state.status IS NULL AND state.suspended_until IS NULL
          AND (j.epoch_id IS NULL OR EXISTS (SELECT 1 FROM space_owned_epoch e WHERE e.id = j.epoch_id
            AND e.space_ref = j.space_ref AND e.repo_did = j.authority_did
            AND e.owner_incarnation = p.authority_incarnation AND e.state = 'deleting'))
          AND j.status = 'deleting' AND j.phase = ? AND j.sequence = ?`)
        .bind(
          stepNonce,
          batchSize,
          handle.nonce,
          handle.spaceRef,
          handle.authorityDid,
          handle.ownerIncarnation,
          phase,
          expectedSequence,
        ),
      env.ALTERAN_DB.prepare(
        `SELECT CASE WHEN EXISTS (SELECT 1 FROM space_personal_deletion_attempt
        WHERE nonce = ? AND job_nonce = ? AND sequence = ? AND phase = ? AND status = 'building')
        THEN 1 ELSE json('{') END AS valid`,
      ).bind(stepNonce, handle.nonce, expectedSequence, phase),
      env.ALTERAN_DB.prepare(insertCleanupCandidates(sql.scan)).bind(
        ...scanArguments,
        stepNonce,
      ),
      env.ALTERAN_DB.prepare(assertCleanupCandidates(sql.scan)).bind(
        ...scanArguments,
        stepNonce,
        stepNonce,
        stepNonce,
      ),
      env.ALTERAN_DB.prepare(
        `SELECT CASE WHEN EXISTS (SELECT 1 FROM space_personal_deletion_candidate WHERE attempt_nonce = ?)
        OR NOT EXISTS (${sql.remaining}) THEN 1 ELSE json('{') END AS valid`,
      )
        .bind(stepNonce, ...remainingArguments),
      env.ALTERAN_DB.prepare(
        `UPDATE space_personal_deletion_attempt SET status = 'sealed',
        expected_count = (SELECT COUNT(*) FROM space_personal_deletion_candidate WHERE attempt_nonce = ?),
        expected_bytes = (SELECT COALESCE(SUM(byte_size), 0) FROM space_personal_deletion_candidate WHERE attempt_nonce = ?)
        WHERE nonce = ? AND job_nonce = ? AND status = 'building'`,
      )
        .bind(stepNonce, stepNonce, stepNonce, handle.nonce),
      env.ALTERAN_DB.prepare(
        `SELECT CASE WHEN EXISTS (SELECT 1 FROM space_personal_deletion_attempt
        WHERE nonce = ? AND job_nonce = ? AND status = 'sealed') THEN 1 ELSE json('{') END AS valid`,
      )
        .bind(stepNonce, handle.nonce),
      env.ALTERAN_DB.prepare(sql.remove).bind(...removeArguments),
      env.ALTERAN_DB.prepare(
        `SELECT CASE WHEN changes() = (SELECT expected_count FROM space_personal_deletion_attempt
        WHERE nonce = ? AND job_nonce = ? AND status = 'sealed') AND NOT EXISTS (
          SELECT 1 FROM space_personal_deletion_candidate c JOIN ${
          phase === "records"
            ? "space_record"
            : phase === "versions"
            ? "space_record_version"
            : "space_op"
        } target
            ON target.rowid = c.row_id WHERE c.attempt_nonce = ?
        ) THEN 1 ELSE json('{') END AS valid`,
      ).bind(stepNonce, handle.nonce, stepNonce),
      ...terminalStatements,
      env.ALTERAN_DB.prepare(
        `UPDATE space_personal_deletion_job SET sequence = sequence + 1,
        last_step_nonce = ?, last_step_phase = phase,
        last_step_count = (SELECT expected_count FROM space_personal_deletion_attempt WHERE nonce = ?),
        phase = CASE WHEN phase = 'records' AND NOT EXISTS (SELECT 1 FROM space_record r
            WHERE r.space_ref = space_personal_deletion_job.space_ref AND r.repo_did = space_personal_deletion_job.authority_did) THEN 'versions'
          WHEN phase = 'versions' AND NOT EXISTS (SELECT 1 FROM space_record_version v
            WHERE v.epoch_id = space_personal_deletion_job.epoch_id) THEN 'ops'
          WHEN phase = 'ops' AND NOT EXISTS (SELECT 1 FROM space_op o
            WHERE o.space_ref = space_personal_deletion_job.space_ref AND o.repo_did = space_personal_deletion_job.authority_did) THEN 'done'
          ELSE phase END,
        status = CASE WHEN phase = 'ops' AND NOT EXISTS (SELECT 1 FROM space_op o
          WHERE o.space_ref = space_personal_deletion_job.space_ref AND o.repo_did = space_personal_deletion_job.authority_did)
          THEN 'complete' ELSE 'deleting' END
        WHERE nonce = ? AND space_ref = ? AND authority_did = ? AND sequence = ? AND phase = ? AND status = 'deleting'
          AND EXISTS (SELECT 1 FROM space_personal_policy p JOIN account owner
            ON owner.did = p.authority_did AND owner.space_incarnation = p.authority_incarnation
            JOIN account_state state ON state.did = owner.did
            WHERE p.space_ref = space_personal_deletion_job.space_ref
              AND p.authority_did = space_personal_deletion_job.authority_did AND p.authority_incarnation = ?
              AND typeof(state.active) = 'integer' AND state.active = 1
              AND state.status IS NULL AND state.suspended_until IS NULL)
          AND EXISTS (SELECT 1 FROM space_personal_deletion_attempt WHERE nonce = ? AND job_nonce = ? AND status = 'sealed')`,
      )
        .bind(
          stepNonce,
          stepNonce,
          handle.nonce,
          handle.spaceRef,
          handle.authorityDid,
          expectedSequence,
          phase,
          handle.ownerIncarnation,
          stepNonce,
          handle.nonce,
        ),
      env.ALTERAN_DB.prepare(
        `SELECT CASE WHEN EXISTS (SELECT 1 FROM space_personal_deletion_job
        WHERE nonce = ? AND space_ref = ? AND authority_did = ? AND sequence = ? AND last_step_nonce = ? AND last_step_phase = ?)
        THEN 1 ELSE json('{') END AS valid`,
      )
        .bind(
          handle.nonce,
          handle.spaceRef,
          handle.authorityDid,
          expectedSequence + 1,
          stepNonce,
          phase,
        ),
      env.ALTERAN_DB.prepare(
        "DELETE FROM space_personal_deletion_candidate WHERE attempt_nonce = ?",
      ).bind(stepNonce),
      env.ALTERAN_DB.prepare(
        "DELETE FROM space_personal_deletion_attempt WHERE nonce = ? AND job_nonce = ?",
      )
        .bind(stepNonce, handle.nonce),
      env.ALTERAN_DB.prepare(
        `SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM space_personal_deletion_attempt WHERE nonce = ?)
        AND NOT EXISTS (SELECT 1 FROM space_personal_deletion_candidate WHERE attempt_nonce = ?)
        AND EXISTS (SELECT 1 FROM space_personal_deletion_job j JOIN space_personal_policy p
          ON p.space_ref = j.space_ref AND p.authority_did = j.authority_did
          JOIN account owner ON owner.did = p.authority_did AND owner.space_incarnation = p.authority_incarnation
          JOIN account_state state ON state.did = owner.did
          JOIN space s ON s.space_ref = j.space_ref AND s.authority_did = j.authority_did
          WHERE j.nonce = ? AND j.space_ref = ? AND j.authority_did = ? AND j.sequence = ?
            AND j.last_step_nonce = ? AND p.authority_incarnation = ?
            AND typeof(state.active) = 'integer' AND state.active = 1
            AND state.status IS NULL AND state.suspended_until IS NULL
            AND s.space_ref = 'at://' || s.authority_did || '/space/' || s.space_type || '/' || s.skey
            AND typeof(s.deleted_at) = 'integer'
            AND (j.epoch_id IS NULL OR EXISTS (SELECT 1 FROM space_owned_epoch e WHERE e.id = j.epoch_id
              AND e.space_ref = j.space_ref AND e.repo_did = j.authority_did
              AND e.owner_incarnation = p.authority_incarnation AND e.state = 'deleting')))
        THEN 1 ELSE json('{') END AS valid`,
      ).bind(stepNonce, stepNonce, handle.nonce, handle.spaceRef, handle.authorityDid,
        expectedSequence + 1, stepNonce, handle.ownerIncarnation),
    ]);
  } catch {
    const observed = await getPersonalSpaceDeletion(env, handle);
    if (
      observed?.sequence === expectedSequence + 1 &&
      observed.lastStepNonce === stepNonce
    ) {
      return {
        tag: observed.status === "complete" ? "complete" : "progress",
        status: observed,
      };
    }
    return observed && observed.sequence !== expectedSequence
      ? { tag: "conflict" }
      : { tag: "unavailable" };
  }
  const observed = await getPersonalSpaceDeletion(env, handle);
  if (
    !observed || observed.sequence !== expectedSequence + 1 ||
    observed.lastStepNonce !== stepNonce
  ) {
    return { tag: "unavailable" };
  }
  return {
    tag: observed.status === "complete" ? "complete" : "progress",
    status: observed,
  };
}
