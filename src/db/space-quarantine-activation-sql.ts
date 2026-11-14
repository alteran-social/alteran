import { PINNED_QUARANTINE_JOB, QUARANTINE_JOB_COLUMNS, VALID_QUARANTINE_JOB_SQL } from './space-quarantine-sql';

export const ACTIVATION_PRECONDITIONS = `
  j.accumulated_hash = j.expected_hash
  AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = j.space_ref AND b.repo_did = j.repo_did)
  AND NOT EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = j.space_ref AND o.repo_did = j.repo_did)
  AND NOT EXISTS (SELECT 1 FROM space_record_version v WHERE v.epoch_id = j.epoch_id
    AND v.path COLLATE BINARY > ? COLLATE BINARY)
  AND NOT EXISTS (SELECT 1 FROM space_record r WHERE r.space_ref = j.space_ref AND r.repo_did = j.repo_did
    AND (r.collection || '/' || r.rkey) COLLATE BINARY > ? COLLATE BINARY)`;

export const COMPLETED_JOB = `${PINNED_QUARANTINE_JOB} AND j.status = 'complete' AND j.failure_reason IS NULL`;
export const ACTIVATING_JOB = `${PINNED_QUARANTINE_JOB} AND j.status = 'activating'`;
export const ACTIVATED_JOB = `SELECT ${QUARANTINE_JOB_COLUMNS} FROM space_quarantine_job j
  JOIN space_repo h ON h.space_ref = j.space_ref AND h.repo_did = j.repo_did
    AND h.active_epoch_id = j.epoch_id AND h.generation = j.generation
    AND h.mutation_id = j.mutation_id AND h.rev = j.rev AND h.set_hash = j.expected_hash
  JOIN space_epoch e ON e.id = j.epoch_id AND e.space_ref = j.space_ref AND e.repo_did = j.repo_did
    AND e.state = 'active' AND e.verified_job_id = j.id AND e.activation_nonce = j.activation_nonce
  JOIN space s ON s.space_ref = j.space_ref AND s.deleted_at IS NULL
    AND s.authority_did = j.authority_did AND s.space_type = j.space_type AND s.skey = j.skey
  WHERE j.id = ? AND j.token = ? AND j.renewal_nonce = ? AND j.space_ref = ? AND j.repo_did = ?
    AND j.lease_until > unixepoch() AND ${VALID_QUARANTINE_JOB_SQL}`;

export const ACTIVE_QUARANTINE_RECEIPT = `SELECT CASE WHEN typeof(j.activation_nonce) = 'text'
    AND length(CAST(j.activation_nonce AS BLOB)) = 36 THEN j.activation_nonce END AS activation_nonce FROM space_quarantine_job j
  JOIN space_repo h ON h.space_ref = j.space_ref AND h.repo_did = j.repo_did AND h.active_epoch_id = j.epoch_id
  JOIN space_epoch e ON e.id = j.epoch_id AND e.space_ref = j.space_ref AND e.repo_did = j.repo_did
    AND e.state = 'active' AND e.verified_job_id = j.id AND e.activation_nonce = j.activation_nonce
  JOIN space s ON s.space_ref = j.space_ref AND s.deleted_at IS NULL
    AND s.authority_did = j.authority_did AND s.space_type = j.space_type AND s.skey = j.skey
  WHERE j.id = ? AND j.token = ? AND j.space_ref = ? AND j.repo_did = ? AND j.status = 'active'
    AND j.failure_reason IS NULL AND j.expected_hash = j.accumulated_hash
    AND (? IS NULL OR j.activation_nonce = ?)`;
