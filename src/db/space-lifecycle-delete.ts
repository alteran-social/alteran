import type { Env } from "../env";
import { captureSpaceOwner } from "./space-owner";
import {
  assertPersonalAuthority,
  captureDeletionHandle,
  invalidLifecycleRequest,
  type PersonalDeletionHandle,
  type PersonalDeletionStatus,
  validLifecycleNonce,
} from "./space-lifecycle-types";

export type BeginPersonalDeletion =
  | { readonly tag: "started"; readonly handle: PersonalDeletionHandle }
  | { readonly tag: "unsupported" | "unavailable" };

/** Revoke current leases and tombstone a newly created personal Space atomically. */
export async function beginPersonalSpaceDeletion(
  env: Env,
  spaceRef: string,
  nonce: string,
  ownerIncarnation: string,
): Promise<BeginPersonalDeletion> {
  if (!validLifecycleNonce(nonce)) throw invalidLifecycleRequest();
  const ref = await assertPersonalAuthority(env, spaceRef);
  const owner = captureSpaceOwner(ref.authorityDid, ownerIncarnation);
  const handle = Object.freeze({
    spaceRef: ref.ref,
    authorityDid: ref.authorityDid,
    ownerIncarnation: owner.incarnation,
    nonce,
  });
  if (await getPersonalSpaceDeletion(env, handle)) {
    return { tag: "started", handle };
  }
  const eligibility = await env.ALTERAN_DB.prepare(`SELECT 1 AS personal,
    EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = s.space_ref) AS blobs
    FROM space s JOIN space_personal_policy p ON p.space_ref = s.space_ref AND p.authority_did = s.authority_did
    JOIN account a ON a.did = p.authority_did AND a.space_incarnation = p.authority_incarnation
    JOIN account_state state ON state.did = a.did
    WHERE s.space_ref = ? AND s.authority_did = ? AND p.authority_incarnation = ?
      AND s.space_ref = 'at://' || s.authority_did || '/space/' || s.space_type || '/' || s.skey
      AND s.deleted_at IS NULL AND p.policy_type = 'com.atproto.personalspace.policy'
      AND p.notification_state = 'none' AND typeof(state.active) = 'integer' AND state.active = 1
      AND state.status IS NULL AND state.suspended_until IS NULL`)
    .bind(ref.ref, ref.authorityDid, owner.incarnation).first<
    { personal: number; blobs: number }
  >();
  if (!eligibility || eligibility.personal !== 1 || eligibility.blobs !== 0) {
    if (await getPersonalSpaceDeletion(env, handle)) {
      return { tag: "started", handle };
    }
    return { tag: "unsupported" };
  }
  try {
    await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(`INSERT INTO space_personal_deletion_job
        (nonce, space_ref, authority_did, epoch_id, status, phase, sequence, last_step_nonce, last_step_phase, last_step_count, created_at)
        SELECT ?, s.space_ref, s.authority_did, h.active_epoch_id, 'deleting', 'records', 0, NULL, NULL, 0, unixepoch()
        FROM space s JOIN space_personal_policy p ON p.space_ref = s.space_ref AND p.authority_did = s.authority_did
        JOIN account a ON a.did = p.authority_did AND a.space_incarnation = p.authority_incarnation
        JOIN account_state state ON state.did = a.did
        LEFT JOIN space_repo h ON h.space_ref = s.space_ref AND h.repo_did = s.authority_did
        WHERE s.space_ref = ? AND s.authority_did = ? AND s.deleted_at IS NULL
          AND s.space_ref = 'at://' || s.authority_did || '/space/' || s.space_type || '/' || s.skey
          AND p.authority_incarnation = ? AND typeof(state.active) = 'integer' AND state.active = 1
          AND state.status IS NULL AND state.suspended_until IS NULL
          AND p.policy_type = 'com.atproto.personalspace.policy' AND p.notification_state = 'none'`)
        .bind(nonce, ref.ref, ref.authorityDid, owner.incarnation),
      env.ALTERAN_DB.prepare(`UPDATE space SET deleted_at = unixepoch() * 1000
        WHERE space_ref = ? AND authority_did = ? AND deleted_at IS NULL
          AND EXISTS (SELECT 1 FROM space_personal_deletion_job j
            WHERE j.nonce = ? AND j.space_ref = space.space_ref AND j.authority_did = space.authority_did
              AND j.status = 'deleting' AND j.sequence = 0 AND j.phase = 'records')`)
        .bind(ref.ref, ref.authorityDid, nonce),
      env.ALTERAN_DB.prepare(`UPDATE space_epoch SET state = 'deleting'
        WHERE id = (SELECT epoch_id FROM space_personal_deletion_job WHERE nonce = ?)
          AND space_ref = ? AND repo_did = ? AND state = 'active'`).bind(
        nonce,
        ref.ref,
        ref.authorityDid,
      ),
      env.ALTERAN_DB.prepare(
        `DELETE FROM space_snapshot_lease NOT INDEXED WHERE rowid IN (
        SELECT rowid FROM space_snapshot_lease INDEXED BY space_snapshot_lease_owner_expiry
        WHERE space_ref = ? AND repo_did = ? ORDER BY expires_at, id LIMIT 16
      ) AND EXISTS (SELECT 1 FROM space_personal_deletion_job j JOIN space s ON s.space_ref = j.space_ref
        WHERE j.nonce = ? AND j.space_ref = ? AND j.authority_did = ? AND s.deleted_at IS NOT NULL)`,
      )
        .bind(ref.ref, ref.authorityDid, nonce, ref.ref, ref.authorityDid),
      env.ALTERAN_DB.prepare(`SELECT CASE WHEN EXISTS (
        SELECT 1 FROM space_personal_deletion_job j JOIN space s ON s.space_ref = j.space_ref
        JOIN space_personal_policy p ON p.space_ref = j.space_ref AND p.authority_did = j.authority_did
        JOIN account a ON a.did = p.authority_did AND a.space_incarnation = p.authority_incarnation
        JOIN account_state state ON state.did = a.did
        WHERE j.nonce = ? AND j.space_ref = ? AND j.authority_did = ? AND j.status = 'deleting'
          AND p.authority_incarnation = ? AND typeof(state.active) = 'integer' AND state.active = 1
          AND state.status IS NULL AND state.suspended_until IS NULL
          AND j.phase = 'records' AND j.sequence = 0 AND typeof(s.deleted_at) = 'integer'
          AND (j.epoch_id IS NULL OR EXISTS (SELECT 1 FROM space_epoch e WHERE e.id = j.epoch_id
            AND e.space_ref = j.space_ref AND e.repo_did = j.authority_did AND e.state = 'deleting'))
          AND NOT EXISTS (SELECT 1 FROM space_snapshot_lease l WHERE l.space_ref = j.space_ref AND l.repo_did = j.authority_did)
          AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = j.space_ref)
          AND NOT EXISTS (SELECT 1 FROM space_quarantine_job q WHERE q.space_ref = j.space_ref)
          AND NOT EXISTS (SELECT 1 FROM space_mutation_attempt m WHERE m.space_ref = j.space_ref)
      ) THEN 1 ELSE json('{') END AS valid`).bind(
        nonce,
        ref.ref,
        ref.authorityDid,
        owner.incarnation,
      ),
    ]);
  } catch {
    return await getPersonalSpaceDeletion(env, handle)
      ? { tag: "started", handle }
      : { tag: "unavailable" };
  }
  return await getPersonalSpaceDeletion(env, handle)
    ? { tag: "started", handle }
    : { tag: "unavailable" };
}

export async function getPersonalSpaceDeletion(
  env: Env,
  input: PersonalDeletionHandle,
): Promise<PersonalDeletionStatus | null> {
  const handle = captureDeletionHandle(input);
  await assertPersonalAuthority(env, handle.spaceRef);
  const row = await env.ALTERAN_DB.prepare(`SELECT
      CASE WHEN typeof(j.status) = 'text' AND length(CAST(j.status AS BLOB)) <= 16 THEN j.status END AS status,
      CASE WHEN typeof(j.phase) = 'text' AND length(CAST(j.phase AS BLOB)) <= 16 THEN j.phase END AS phase,
      CASE WHEN typeof(j.sequence) = 'integer' AND j.sequence BETWEEN 0 AND 9007199254740991 THEN j.sequence END AS sequence,
      CASE WHEN typeof(j.last_step_nonce) = 'text' AND length(CAST(j.last_step_nonce AS BLOB)) = 36
        THEN j.last_step_nonce END AS last_step_nonce,
      CASE WHEN typeof(j.last_step_phase) = 'text' AND length(CAST(j.last_step_phase AS BLOB)) <= 16
        THEN j.last_step_phase END AS last_step_phase,
      CASE WHEN (j.last_step_nonce IS NULL OR (typeof(j.last_step_nonce) = 'text'
          AND length(CAST(j.last_step_nonce AS BLOB)) = 36))
        AND (j.last_step_phase IS NULL OR (typeof(j.last_step_phase) = 'text'
          AND length(CAST(j.last_step_phase AS BLOB)) <= 16)) THEN 1 ELSE 0 END AS receipt_valid,
      CASE WHEN typeof(j.last_step_count) = 'integer' AND j.last_step_count BETWEEN 0 AND 32
        THEN j.last_step_count END AS last_step_count,
      CASE WHEN j.epoch_id IS NULL OR (typeof(j.epoch_id) = 'text' AND length(CAST(j.epoch_id AS BLOB)) BETWEEN 1 AND 128)
        THEN 1 ELSE 0 END AS epoch_valid
    FROM space_personal_deletion_job j JOIN space s ON s.space_ref = j.space_ref AND s.authority_did = j.authority_did
    JOIN space_personal_policy p ON p.space_ref = j.space_ref AND p.authority_did = j.authority_did
    JOIN account a ON a.did = p.authority_did AND a.space_incarnation = p.authority_incarnation
    JOIN account_state state ON state.did = a.did
    WHERE j.nonce = ? AND j.space_ref = ? AND j.authority_did = ? AND typeof(s.deleted_at) = 'integer'
      AND p.authority_incarnation = ? AND typeof(state.active) = 'integer' AND state.active = 1
      AND state.status IS NULL AND state.suspended_until IS NULL
      AND s.space_ref = 'at://' || s.authority_did || '/space/' || s.space_type || '/' || s.skey
      AND p.policy_type = 'com.atproto.personalspace.policy' AND p.notification_state = 'none'
      AND (j.epoch_id IS NULL OR EXISTS (SELECT 1 FROM space_owned_epoch e WHERE e.id = j.epoch_id
        AND e.space_ref = j.space_ref AND e.repo_did = j.authority_did AND e.state = 'deleting'
        AND e.owner_incarnation = p.authority_incarnation))`)
    .bind(handle.nonce, handle.spaceRef, handle.authorityDid, handle.ownerIncarnation).first<{
    status: unknown;
    phase: unknown;
    sequence: unknown;
    last_step_nonce: unknown;
    last_step_phase: unknown;
    last_step_count: unknown;
    epoch_valid: unknown;
    receipt_valid: unknown;
  }>();
  if (!row) return null;
  if (
    row.epoch_valid !== 1 || row.receipt_valid !== 1 ||
    (row.status !== "deleting" && row.status !== "complete") ||
    (row.phase !== "records" && row.phase !== "versions" &&
      row.phase !== "ops" && row.phase !== "done") ||
    (row.status === "complete") !== (row.phase === "done") ||
    typeof row.sequence !== "number" ||
    !Number.isSafeInteger(row.sequence) ||
    typeof row.last_step_count !== "number" ||
    !Number.isSafeInteger(row.last_step_count) ||
    (row.sequence === 0
      ? row.last_step_nonce !== null || row.last_step_phase !== null ||
        row.last_step_count !== 0
      : !validLifecycleNonce(row.last_step_nonce) ||
        (row.last_step_phase !== "records" &&
          row.last_step_phase !== "versions" && row.last_step_phase !== "ops"))
  ) return null;
  return {
    status: row.status,
    phase: row.phase,
    sequence: row.sequence,
    lastStepNonce: row.last_step_nonce as string | null,
    lastStepPhase: row.last_step_phase as "records" | "versions" | "ops" | null,
    lastStepCount: row.last_step_count,
  };
}
