CREATE TRIGGER space_personal_creation_attempt_insert BEFORE INSERT ON space_personal_creation_attempt
WHEN typeof(NEW.nonce) != 'text' OR length(CAST(NEW.nonce AS BLOB)) != 36
  OR EXISTS (SELECT 1 FROM space_personal_creation_attempt a WHERE a.nonce = NEW.nonce OR a.space_ref = NEW.space_ref)
  OR EXISTS (SELECT 1 FROM space s WHERE s.space_ref = NEW.space_ref)
  OR EXISTS (SELECT 1 FROM space_personal_policy p WHERE p.creation_nonce = NEW.nonce)
BEGIN SELECT RAISE(ABORT, 'personal creation must be new'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_creation_attempt_update BEFORE UPDATE ON space_personal_creation_attempt
BEGIN SELECT RAISE(ABORT, 'personal creation attempt is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_policy_insert BEFORE INSERT ON space_personal_policy
WHEN EXISTS (SELECT 1 FROM space_personal_policy p WHERE p.space_ref = NEW.space_ref OR p.creation_nonce = NEW.creation_nonce)
  OR NEW.policy_type != 'com.atproto.personalspace.policy' OR NEW.notification_state != 'none'
  OR NOT EXISTS (SELECT 1 FROM space_personal_creation_attempt a JOIN space s ON s.space_ref = a.space_ref
    AND s.authority_did = a.authority_did AND s.space_type = a.space_type AND s.skey = a.skey
    AND s.created_at = a.created_at AND s.deleted_at IS NULL
    WHERE a.nonce = NEW.creation_nonce AND a.space_ref = NEW.space_ref
      AND a.authority_did = NEW.authority_did AND a.created_at = NEW.created_at)
BEGIN SELECT RAISE(ABORT, 'personal policy requires creation'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_policy_update BEFORE UPDATE ON space_personal_policy
BEGIN SELECT RAISE(ABORT, 'personal policy is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_policy_delete BEFORE DELETE ON space_personal_policy
BEGIN SELECT RAISE(ABORT, 'personal policy must be retained'); END;
--> statement-breakpoint
CREATE TRIGGER space_lifecycle_insert BEFORE INSERT ON space
WHEN EXISTS (SELECT 1 FROM space s WHERE s.space_ref = NEW.space_ref AND s.deleted_at IS NOT NULL)
  OR EXISTS (SELECT 1 FROM space_personal_policy p WHERE p.space_ref = NEW.space_ref)
BEGIN SELECT RAISE(ABORT, 'personal Space cannot be replaced'); END;
--> statement-breakpoint
CREATE TRIGGER space_lifecycle_delete BEFORE DELETE ON space
WHEN OLD.deleted_at IS NOT NULL OR EXISTS (SELECT 1 FROM space_personal_policy p WHERE p.space_ref = OLD.space_ref)
BEGIN SELECT RAISE(ABORT, 'Space tombstone must be retained'); END;
--> statement-breakpoint
CREATE TRIGGER space_lifecycle_update BEFORE UPDATE ON space
WHEN OLD.deleted_at IS NOT NULL OR (EXISTS (SELECT 1 FROM space_personal_policy p WHERE p.space_ref = OLD.space_ref) AND (
  NEW.space_ref IS NOT OLD.space_ref OR NEW.authority_did IS NOT OLD.authority_did OR NEW.space_type IS NOT OLD.space_type
  OR NEW.skey IS NOT OLD.skey OR NEW.created_at IS NOT OLD.created_at OR NEW.deleted_at IS NULL
  OR NOT EXISTS (SELECT 1 FROM space_personal_deletion_job j WHERE j.space_ref = OLD.space_ref
    AND j.authority_did = OLD.authority_did AND j.status = 'deleting' AND j.sequence = 0 AND j.phase = 'records')
))
BEGIN SELECT RAISE(ABORT, 'personal Space update is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_deletion_job_insert BEFORE INSERT ON space_personal_deletion_job
WHEN typeof(NEW.nonce) != 'text' OR length(CAST(NEW.nonce AS BLOB)) != 36
  OR (NEW.epoch_id IS NOT NULL AND (typeof(NEW.epoch_id) != 'text' OR length(CAST(NEW.epoch_id AS BLOB)) NOT BETWEEN 1 AND 128))
  OR EXISTS (SELECT 1 FROM space_personal_deletion_job j WHERE j.nonce = NEW.nonce OR j.space_ref = NEW.space_ref)
  OR NEW.status != 'deleting' OR NEW.phase != 'records' OR NEW.sequence != 0
  OR NEW.last_step_nonce IS NOT NULL OR NEW.last_step_phase IS NOT NULL OR NEW.last_step_count != 0
  OR NOT EXISTS (SELECT 1 FROM space s JOIN space_personal_policy p ON p.space_ref = s.space_ref
    AND p.authority_did = s.authority_did AND p.policy_type = 'com.atproto.personalspace.policy'
    AND p.notification_state = 'none' WHERE s.space_ref = NEW.space_ref AND s.authority_did = NEW.authority_did
    AND s.deleted_at IS NULL)
  OR EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = NEW.space_ref)
  OR EXISTS (SELECT 1 FROM space_quarantine_job q WHERE q.space_ref = NEW.space_ref)
  OR EXISTS (SELECT 1 FROM space_mutation_attempt m WHERE m.space_ref = NEW.space_ref)
  OR EXISTS (SELECT 1 FROM space_repo h WHERE h.space_ref = NEW.space_ref AND h.repo_did < NEW.authority_did)
  OR EXISTS (SELECT 1 FROM space_repo h WHERE h.space_ref = NEW.space_ref AND h.repo_did > NEW.authority_did)
  OR EXISTS (SELECT 1 FROM space_epoch e INDEXED BY space_epoch_space_owner WHERE e.space_ref = NEW.space_ref
    LIMIT 1 OFFSET 1)
  OR (NEW.epoch_id IS NULL AND (EXISTS (SELECT 1 FROM space_repo h WHERE h.space_ref = NEW.space_ref)
    OR EXISTS (SELECT 1 FROM space_epoch e INDEXED BY space_epoch_space_owner WHERE e.space_ref = NEW.space_ref)
    OR EXISTS (SELECT 1 FROM space_record r WHERE r.space_ref = NEW.space_ref)
    OR EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = NEW.space_ref)
    OR EXISTS (SELECT 1 FROM space_record_version v INDEXED BY space_record_version_space_owner_epoch WHERE v.space_ref = NEW.space_ref)))
  OR (NEW.epoch_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM space_repo h JOIN space_epoch e
    ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref AND e.repo_did = h.repo_did AND e.state = 'active'
    WHERE h.space_ref = NEW.space_ref AND h.repo_did = NEW.authority_did AND h.active_epoch_id = NEW.epoch_id))
  OR EXISTS (SELECT 1 FROM space_record r WHERE r.space_ref = NEW.space_ref AND r.repo_did < NEW.authority_did)
  OR EXISTS (SELECT 1 FROM space_record r WHERE r.space_ref = NEW.space_ref AND r.repo_did > NEW.authority_did)
  OR EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = NEW.space_ref AND o.repo_did < NEW.authority_did)
  OR EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = NEW.space_ref AND o.repo_did > NEW.authority_did)
  OR EXISTS (SELECT 1 FROM space_record_version v INDEXED BY space_record_version_space_owner_epoch
    WHERE v.space_ref = NEW.space_ref AND v.repo_did < NEW.authority_did)
  OR EXISTS (SELECT 1 FROM space_record_version v INDEXED BY space_record_version_space_owner_epoch
    WHERE v.space_ref = NEW.space_ref AND v.repo_did > NEW.authority_did)
  OR (NEW.epoch_id IS NOT NULL AND EXISTS (SELECT 1 FROM space_record_version v INDEXED BY space_record_version_space_owner_epoch
    WHERE v.space_ref = NEW.space_ref AND v.repo_did = NEW.authority_did AND v.epoch_id < NEW.epoch_id))
  OR (NEW.epoch_id IS NOT NULL AND EXISTS (SELECT 1 FROM space_record_version v INDEXED BY space_record_version_space_owner_epoch
    WHERE v.space_ref = NEW.space_ref AND v.repo_did = NEW.authority_did AND v.epoch_id > NEW.epoch_id))
  OR EXISTS (SELECT 1 FROM space_snapshot_lease l INDEXED BY space_snapshot_lease_owner_expiry
    WHERE l.space_ref = NEW.space_ref AND l.repo_did < NEW.authority_did)
  OR EXISTS (SELECT 1 FROM space_snapshot_lease l INDEXED BY space_snapshot_lease_owner_expiry
    WHERE l.space_ref = NEW.space_ref AND l.repo_did > NEW.authority_did)
  OR EXISTS (SELECT 1 FROM space_snapshot_lease l INDEXED BY space_snapshot_lease_owner_expiry
    WHERE l.space_ref = NEW.space_ref AND l.repo_did = NEW.authority_did LIMIT 1 OFFSET 16)
  OR EXISTS (WITH checked AS MATERIALIZED (SELECT CASE WHEN l.epoch_id IS NEW.epoch_id
      AND typeof(l.id) = 'text' AND length(CAST(l.id AS BLOB)) BETWEEN 1 AND 128
      AND typeof(l.token) = 'text' AND length(CAST(l.token AS BLOB)) BETWEEN 1 AND 128
      AND typeof(l.renewal_nonce) = 'text' AND length(CAST(l.renewal_nonce AS BLOB)) BETWEEN 1 AND 128
      AND typeof(l.rev) = 'text' AND length(CAST(l.rev AS BLOB)) = 13
      AND typeof(l.set_hash) = 'blob' AND length(l.set_hash) = 2048
      AND typeof(l.generation) = 'integer' AND l.generation BETWEEN 1 AND 9007199254740991
      AND typeof(l.expires_at) = 'integer' AND typeof(l.maximum_expires_at) = 'integer' THEN 1 ELSE 0 END AS valid
    FROM space_snapshot_lease l INDEXED BY space_snapshot_lease_owner_expiry
    WHERE l.space_ref = NEW.space_ref AND l.repo_did = NEW.authority_did LIMIT 16)
    SELECT 1 FROM checked WHERE valid = 0)
BEGIN SELECT RAISE(ABORT, 'personal deletion precondition failed'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_deletion_job_delete BEFORE DELETE ON space_personal_deletion_job
BEGIN SELECT RAISE(ABORT, 'personal deletion receipt must be retained'); END;
--> statement-breakpoint
CREATE TRIGGER space_lifecycle_repo_insert BEFORE INSERT ON space_repo
WHEN EXISTS (SELECT 1 FROM space s WHERE s.space_ref = NEW.space_ref AND s.deleted_at IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'deleted Space repo is unavailable'); END;
--> statement-breakpoint
DROP TRIGGER space_repo_fence_update;
--> statement-breakpoint
CREATE TRIGGER space_repo_fence_update BEFORE UPDATE ON space_repo
WHEN (NEW.space_ref IS NOT OLD.space_ref OR NEW.repo_did IS NOT OLD.repo_did
  OR NEW.active_epoch_id IS NOT OLD.active_epoch_id OR NEW.generation != OLD.generation + 1
  OR NEW.rev IS NULL OR OLD.rev IS NULL OR NEW.rev <= OLD.rev
  OR NOT EXISTS (SELECT 1 FROM space_epoch e WHERE e.id = OLD.active_epoch_id AND e.space_ref = OLD.space_ref
    AND e.repo_did = OLD.repo_did AND e.state = 'active')
  OR NOT EXISTS (SELECT 1 FROM space_mutation_attempt a WHERE a.mutation_id = NEW.mutation_id
    AND a.space_ref = NEW.space_ref AND a.repo_did = NEW.repo_did AND a.epoch_id = NEW.active_epoch_id
    AND a.generation = NEW.generation AND a.rev = NEW.rev AND a.set_hash = NEW.set_hash))
  AND NOT EXISTS (SELECT 1 FROM space_personal_deletion_job j
  JOIN space_personal_deletion_attempt a ON a.job_nonce = j.nonce AND a.space_ref = j.space_ref
    AND a.authority_did = j.authority_did AND a.epoch_id IS j.epoch_id
    AND a.phase = 'ops' AND a.sequence = j.sequence AND a.status = 'sealed'
  JOIN space s ON s.space_ref = j.space_ref AND s.authority_did = j.authority_did AND s.deleted_at IS NOT NULL
  JOIN space_personal_policy p ON p.space_ref = j.space_ref AND p.authority_did = j.authority_did
    AND p.policy_type = 'com.atproto.personalspace.policy' AND p.notification_state = 'none'
  JOIN space_epoch e ON e.id = j.epoch_id AND e.space_ref = j.space_ref
    AND e.repo_did = j.authority_did AND e.state = 'deleting'
  WHERE j.space_ref = OLD.space_ref AND j.authority_did = OLD.repo_did AND j.epoch_id = OLD.active_epoch_id
    AND j.status = 'deleting' AND j.phase = 'ops'
    AND NEW.space_ref IS OLD.space_ref AND NEW.repo_did IS OLD.repo_did AND NEW.active_epoch_id IS OLD.active_epoch_id
    AND NEW.rev IS NULL AND typeof(NEW.generation) = 'integer' AND NEW.generation = 0
    AND NEW.mutation_id IS j.nonce AND typeof(NEW.set_hash) = 'blob' AND NEW.set_hash = zeroblob(2048)
    AND NOT EXISTS (SELECT 1 FROM space_record r WHERE r.space_ref = j.space_ref)
    AND NOT EXISTS (SELECT 1 FROM space_record_version v WHERE v.space_ref = j.space_ref)
    AND NOT EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = j.space_ref)
    AND NOT EXISTS (SELECT 1 FROM space_snapshot_lease l WHERE l.space_ref = j.space_ref)
    AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = j.space_ref)
    AND NOT EXISTS (SELECT 1 FROM space_quarantine_job q WHERE q.space_ref = j.space_ref)
    AND NOT EXISTS (SELECT 1 FROM space_mutation_attempt m WHERE m.space_ref = j.space_ref))
BEGIN SELECT RAISE(ABORT, 'space repo update is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_lifecycle_repo_update BEFORE UPDATE ON space_repo
WHEN EXISTS (SELECT 1 FROM space s WHERE s.space_ref = OLD.space_ref AND s.deleted_at IS NOT NULL)
  AND NOT EXISTS (SELECT 1 FROM space_personal_deletion_job j
  JOIN space_personal_deletion_attempt a ON a.job_nonce = j.nonce AND a.space_ref = j.space_ref
    AND a.authority_did = j.authority_did AND a.epoch_id IS j.epoch_id
    AND a.phase = 'ops' AND a.sequence = j.sequence AND a.status = 'sealed'
  JOIN space s ON s.space_ref = j.space_ref AND s.authority_did = j.authority_did AND s.deleted_at IS NOT NULL
  JOIN space_personal_policy p ON p.space_ref = j.space_ref AND p.authority_did = j.authority_did
    AND p.policy_type = 'com.atproto.personalspace.policy' AND p.notification_state = 'none'
  JOIN space_epoch e ON e.id = j.epoch_id AND e.space_ref = j.space_ref
    AND e.repo_did = j.authority_did AND e.state = 'deleting'
  WHERE j.space_ref = OLD.space_ref AND j.authority_did = OLD.repo_did AND j.epoch_id = OLD.active_epoch_id
    AND j.status = 'deleting' AND j.phase = 'ops'
    AND NEW.space_ref IS OLD.space_ref AND NEW.repo_did IS OLD.repo_did AND NEW.active_epoch_id IS OLD.active_epoch_id
    AND NEW.rev IS NULL AND typeof(NEW.generation) = 'integer' AND NEW.generation = 0
    AND NEW.mutation_id IS j.nonce AND typeof(NEW.set_hash) = 'blob' AND NEW.set_hash = zeroblob(2048)
    AND NOT EXISTS (SELECT 1 FROM space_record r WHERE r.space_ref = j.space_ref)
    AND NOT EXISTS (SELECT 1 FROM space_record_version v WHERE v.space_ref = j.space_ref)
    AND NOT EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = j.space_ref)
    AND NOT EXISTS (SELECT 1 FROM space_snapshot_lease l WHERE l.space_ref = j.space_ref)
    AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = j.space_ref)
    AND NOT EXISTS (SELECT 1 FROM space_quarantine_job q WHERE q.space_ref = j.space_ref)
    AND NOT EXISTS (SELECT 1 FROM space_mutation_attempt m WHERE m.space_ref = j.space_ref))
BEGIN SELECT RAISE(ABORT, 'deleted Space repo is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_lifecycle_quarantine_job_insert BEFORE INSERT ON space_quarantine_job
WHEN EXISTS (SELECT 1 FROM space s WHERE s.space_ref = NEW.space_ref AND s.deleted_at IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'deleted Space cannot be quarantined'); END;
--> statement-breakpoint
CREATE TRIGGER space_lifecycle_mutation_attempt_insert BEFORE INSERT ON space_mutation_attempt
WHEN EXISTS (SELECT 1 FROM space s WHERE s.space_ref = NEW.space_ref AND s.deleted_at IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'deleted Space cannot be mutated'); END;
--> statement-breakpoint
CREATE TRIGGER space_lifecycle_epoch_insert BEFORE INSERT ON space_epoch
WHEN EXISTS (SELECT 1 FROM space s WHERE s.space_ref = NEW.space_ref AND s.deleted_at IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'deleted Space cannot gain an epoch'); END;
--> statement-breakpoint
CREATE TRIGGER space_lifecycle_epoch_update BEFORE UPDATE OF state ON space_epoch
WHEN OLD.state = 'deleting' OR (NEW.state = 'deleting' AND NOT EXISTS (
  SELECT 1 FROM space_personal_deletion_job j JOIN space s ON s.space_ref = j.space_ref
  WHERE j.space_ref = OLD.space_ref AND j.authority_did = OLD.repo_did AND j.epoch_id = OLD.id
    AND j.status = 'deleting' AND j.phase = 'records' AND j.sequence = 0 AND s.deleted_at IS NOT NULL
)) OR (EXISTS (SELECT 1 FROM space s WHERE s.space_ref = OLD.space_ref AND s.deleted_at IS NOT NULL)
  AND NEW.state != 'deleting')
BEGIN SELECT RAISE(ABORT, 'Space epoch transition is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_lifecycle_lease_insert BEFORE INSERT ON space_snapshot_lease
WHEN EXISTS (SELECT 1 FROM space s WHERE s.space_ref = NEW.space_ref AND s.deleted_at IS NOT NULL)
  OR EXISTS (SELECT 1 FROM space_epoch e WHERE e.id = NEW.epoch_id AND e.state = 'deleting')
BEGIN SELECT RAISE(ABORT, 'deleted Space cannot be leased'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_deletion_attempt_insert BEFORE INSERT ON space_personal_deletion_attempt
WHEN typeof(NEW.nonce) != 'text' OR length(CAST(NEW.nonce AS BLOB)) != 36
  OR EXISTS (SELECT 1 FROM space_personal_deletion_attempt a WHERE a.nonce = NEW.nonce OR a.job_nonce = NEW.job_nonce)
  OR NEW.status != 'building' OR typeof(NEW.maximum_count) != 'integer' OR NEW.maximum_count NOT BETWEEN 1 AND 32
  OR NEW.expected_count != 0 OR NEW.expected_bytes != 0
  OR NOT EXISTS (SELECT 1 FROM space_personal_deletion_job j JOIN space s ON s.space_ref = j.space_ref
    JOIN space_personal_policy p ON p.space_ref = j.space_ref AND p.authority_did = j.authority_did
    WHERE j.nonce = NEW.job_nonce AND j.space_ref = NEW.space_ref AND j.authority_did = NEW.authority_did
      AND j.epoch_id IS NEW.epoch_id AND j.status = 'deleting' AND j.phase = NEW.phase AND j.sequence = NEW.sequence
      AND s.deleted_at IS NOT NULL AND p.notification_state = 'none'
      AND (j.epoch_id IS NULL OR EXISTS (SELECT 1 FROM space_epoch e WHERE e.id = j.epoch_id
        AND e.space_ref = j.space_ref AND e.repo_did = j.authority_did AND e.state = 'deleting'))
      AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = j.space_ref))
BEGIN SELECT RAISE(ABORT, 'personal deletion attempt is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_deletion_attempt_update BEFORE UPDATE ON space_personal_deletion_attempt
WHEN OLD.status != 'building' OR NEW.status != 'sealed' OR NEW.nonce IS NOT OLD.nonce OR NEW.job_nonce IS NOT OLD.job_nonce
  OR NEW.space_ref IS NOT OLD.space_ref OR NEW.authority_did IS NOT OLD.authority_did OR NEW.epoch_id IS NOT OLD.epoch_id
  OR NEW.phase IS NOT OLD.phase OR NEW.sequence IS NOT OLD.sequence OR NEW.maximum_count IS NOT OLD.maximum_count
  OR NEW.expected_count != (SELECT COUNT(*) FROM space_personal_deletion_candidate c WHERE c.attempt_nonce = OLD.nonce)
  OR NEW.expected_bytes != (SELECT COALESCE(SUM(c.byte_size), 0) FROM space_personal_deletion_candidate c WHERE c.attempt_nonce = OLD.nonce)
BEGIN SELECT RAISE(ABORT, 'personal deletion attempt cannot be sealed'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_deletion_candidate_update BEFORE UPDATE ON space_personal_deletion_candidate
BEGIN SELECT RAISE(ABORT, 'personal deletion candidate is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_deletion_candidate_delete BEFORE DELETE ON space_personal_deletion_candidate
WHEN NOT EXISTS (SELECT 1 FROM space_personal_deletion_attempt a JOIN space_personal_deletion_job j ON j.nonce = a.job_nonce
  WHERE a.nonce = OLD.attempt_nonce AND a.status = 'sealed' AND j.sequence = a.sequence + 1 AND j.last_step_nonce = a.nonce)
BEGIN SELECT RAISE(ABORT, 'personal deletion candidate is still in use'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_deletion_attempt_delete BEFORE DELETE ON space_personal_deletion_attempt
WHEN NOT EXISTS (SELECT 1 FROM space_personal_deletion_job j WHERE j.nonce = OLD.job_nonce
  AND j.sequence = OLD.sequence + 1 AND j.last_step_nonce = OLD.nonce)
  OR EXISTS (SELECT 1 FROM space_personal_deletion_candidate c WHERE c.attempt_nonce = OLD.nonce)
BEGIN SELECT RAISE(ABORT, 'personal deletion attempt is still in use'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_deletion_candidate_insert BEFORE INSERT ON space_personal_deletion_candidate
WHEN EXISTS (SELECT 1 FROM space_personal_deletion_candidate c WHERE c.attempt_nonce = NEW.attempt_nonce AND c.row_id = NEW.row_id)
 OR typeof(NEW.byte_size) != 'integer' OR NEW.byte_size NOT BETWEEN 0 AND 1048576
 OR (SELECT COUNT(*) FROM space_personal_deletion_candidate c WHERE c.attempt_nonce = NEW.attempt_nonce) >=
   (SELECT maximum_count FROM space_personal_deletion_attempt WHERE nonce = NEW.attempt_nonce)
 OR (SELECT COALESCE(SUM(c.byte_size), 0) FROM space_personal_deletion_candidate c WHERE c.attempt_nonce = NEW.attempt_nonce) + NEW.byte_size > 4194304
 OR NOT EXISTS (SELECT 1 FROM space_personal_deletion_attempt a WHERE a.nonce = NEW.attempt_nonce AND a.status = 'building' AND (
   (a.phase = 'records' AND EXISTS (SELECT 1 FROM space_record r WHERE r.rowid = NEW.row_id AND r.space_ref = a.space_ref AND r.repo_did = a.authority_did AND typeof(r.value_cbor) = 'blob' AND length(r.value_cbor) BETWEEN 1 AND 1048576 AND length(r.value_cbor) = NEW.byte_size AND typeof(r.collection) = 'text' AND length(CAST(r.collection AS BLOB)) BETWEEN 1 AND 317 AND typeof(r.rkey) = 'text' AND length(CAST(r.rkey AS BLOB)) BETWEEN 1 AND 512 AND typeof(r.cid) = 'text' AND length(CAST(r.cid AS BLOB)) BETWEEN 1 AND 128 AND typeof(r.repo_rev) = 'text' AND length(CAST(r.repo_rev AS BLOB)) = 13))
   OR (a.phase = 'versions' AND EXISTS (SELECT 1 FROM space_record_version v WHERE v.rowid = NEW.row_id AND v.epoch_id = a.epoch_id AND v.space_ref = a.space_ref AND v.repo_did = a.authority_did AND typeof(v.value_cbor) = 'blob' AND length(v.value_cbor) BETWEEN 1 AND 1048576 AND length(v.value_cbor) = NEW.byte_size AND typeof(v.value_size) = 'integer' AND v.value_size = NEW.byte_size AND typeof(v.path) = 'text' AND length(CAST(v.path AS BLOB)) BETWEEN 1 AND 830 AND typeof(v.collection) = 'text' AND length(CAST(v.collection AS BLOB)) BETWEEN 1 AND 317 AND typeof(v.rkey) = 'text' AND length(CAST(v.rkey AS BLOB)) BETWEEN 1 AND 512 AND typeof(v.cid) = 'text' AND length(CAST(v.cid AS BLOB)) BETWEEN 1 AND 128 AND typeof(v.repo_rev) = 'text' AND length(CAST(v.repo_rev AS BLOB)) = 13 AND typeof(v.from_generation) = 'integer' AND v.from_generation BETWEEN 1 AND 9007199254740991 AND (v.until_generation IS NULL OR (typeof(v.until_generation) = 'integer' AND v.until_generation BETWEEN 1 AND 9007199254740991 AND v.until_generation > v.from_generation))))
   OR (a.phase = 'ops' AND EXISTS (SELECT 1 FROM space_op o WHERE o.rowid = NEW.row_id AND o.space_ref = a.space_ref AND o.repo_did = a.authority_did AND NEW.byte_size = 0 AND typeof(o.rev) = 'text' AND length(CAST(o.rev AS BLOB)) = 13 AND typeof(o.ordinal) = 'integer' AND o.ordinal BETWEEN 0 AND 9007199254740991 AND typeof(o.collection) = 'text' AND length(CAST(o.collection AS BLOB)) BETWEEN 1 AND 317 AND typeof(o.rkey) = 'text' AND length(CAST(o.rkey AS BLOB)) BETWEEN 1 AND 512 AND (o.cid IS NULL OR (typeof(o.cid) = 'text' AND length(CAST(o.cid AS BLOB)) BETWEEN 1 AND 128)) AND (o.prev IS NULL OR (typeof(o.prev) = 'text' AND length(CAST(o.prev AS BLOB)) BETWEEN 1 AND 128))))
 ))
BEGIN SELECT RAISE(ABORT, 'invalid personal deletion candidate'); END;
--> statement-breakpoint
DROP TRIGGER space_record_fence_delete;
--> statement-breakpoint
CREATE TRIGGER space_record_fence_delete BEFORE DELETE ON space_record
WHEN NOT EXISTS (SELECT 1 FROM space_commit_winner w WHERE w.space_ref = OLD.space_ref AND w.repo_did = OLD.repo_did)
  AND NOT EXISTS (SELECT 1 FROM space_personal_deletion_candidate c
      JOIN space_personal_deletion_attempt a ON a.nonce = c.attempt_nonce AND a.status = 'sealed'
      JOIN space_personal_deletion_job j ON j.nonce = a.job_nonce AND j.sequence = a.sequence AND j.phase = a.phase AND j.status = 'deleting'
      JOIN space s ON s.space_ref = j.space_ref AND s.authority_did = j.authority_did AND s.deleted_at IS NOT NULL
      WHERE c.row_id = OLD.rowid AND a.phase = 'records' AND a.space_ref = OLD.space_ref
        AND a.authority_did = OLD.repo_did AND j.space_ref = OLD.space_ref AND j.authority_did = OLD.repo_did
        AND (j.epoch_id IS NULL OR EXISTS (SELECT 1 FROM space_epoch e WHERE e.id = j.epoch_id
          AND e.space_ref = j.space_ref AND e.repo_did = j.authority_did AND e.state = 'deleting'))
        AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = j.space_ref))
BEGIN SELECT RAISE(ABORT, 'space record delete is not fenced'); END;
--> statement-breakpoint
DROP TRIGGER space_record_version_delete_guard;
--> statement-breakpoint
CREATE TRIGGER space_record_version_delete_guard BEFORE DELETE ON space_record_version
WHEN (OLD.until_generation IS NULL OR EXISTS (SELECT 1 FROM space_epoch e WHERE e.id = OLD.epoch_id AND e.state = 'quarantined'))
  AND NOT EXISTS (SELECT 1 FROM space_personal_deletion_candidate c
      JOIN space_personal_deletion_attempt a ON a.nonce = c.attempt_nonce AND a.status = 'sealed'
      JOIN space_personal_deletion_job j ON j.nonce = a.job_nonce AND j.sequence = a.sequence AND j.phase = a.phase AND j.status = 'deleting'
      JOIN space s ON s.space_ref = j.space_ref AND s.authority_did = j.authority_did AND s.deleted_at IS NOT NULL
      WHERE c.row_id = OLD.rowid AND a.phase = 'versions' AND a.space_ref = OLD.space_ref
        AND a.authority_did = OLD.repo_did AND j.space_ref = OLD.space_ref AND j.authority_did = OLD.repo_did AND j.epoch_id = OLD.epoch_id
        AND (j.epoch_id IS NULL OR EXISTS (SELECT 1 FROM space_epoch e WHERE e.id = j.epoch_id
          AND e.space_ref = j.space_ref AND e.repo_did = j.authority_did AND e.state = 'deleting'))
        AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = j.space_ref))
BEGIN SELECT RAISE(ABORT, 'current or quarantined space record version'); END;
--> statement-breakpoint
DROP TRIGGER space_version_fence_delete;
--> statement-breakpoint
CREATE TRIGGER space_version_fence_delete BEFORE DELETE ON space_record_version
WHEN (OLD.until_generation IS NULL OR NOT EXISTS (
 SELECT 1 FROM space_gc_attempt g JOIN space_repo h ON h.space_ref = g.space_ref AND h.repo_did = g.repo_did AND h.active_epoch_id = g.epoch_id
 JOIN space_epoch e ON e.id = g.epoch_id AND e.space_ref = g.space_ref AND e.repo_did = g.repo_did AND e.state = 'active'
 WHERE g.epoch_id = OLD.epoch_id AND g.space_ref = OLD.space_ref AND g.repo_did = OLD.repo_did
 AND NOT EXISTS (SELECT 1 FROM space_snapshot_lease l WHERE l.epoch_id = OLD.epoch_id AND l.space_ref = OLD.space_ref
 AND l.repo_did = OLD.repo_did AND l.generation >= OLD.from_generation AND l.generation < OLD.until_generation)))
 AND NOT EXISTS (SELECT 1 FROM space_personal_deletion_candidate c
      JOIN space_personal_deletion_attempt a ON a.nonce = c.attempt_nonce AND a.status = 'sealed'
      JOIN space_personal_deletion_job j ON j.nonce = a.job_nonce AND j.sequence = a.sequence AND j.phase = a.phase AND j.status = 'deleting'
      JOIN space s ON s.space_ref = j.space_ref AND s.authority_did = j.authority_did AND s.deleted_at IS NOT NULL
      WHERE c.row_id = OLD.rowid AND a.phase = 'versions' AND a.space_ref = OLD.space_ref
        AND a.authority_did = OLD.repo_did AND j.space_ref = OLD.space_ref AND j.authority_did = OLD.repo_did AND j.epoch_id = OLD.epoch_id
        AND (j.epoch_id IS NULL OR EXISTS (SELECT 1 FROM space_epoch e WHERE e.id = j.epoch_id
          AND e.space_ref = j.space_ref AND e.repo_did = j.authority_did AND e.state = 'deleting'))
        AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = j.space_ref))
BEGIN SELECT RAISE(ABORT, 'space version pruning is not fenced'); END;
--> statement-breakpoint
DROP TRIGGER space_op_fence_delete;
--> statement-breakpoint
CREATE TRIGGER space_op_fence_delete BEFORE DELETE ON space_op
WHEN NOT EXISTS (SELECT 1 FROM space_personal_deletion_candidate c
      JOIN space_personal_deletion_attempt a ON a.nonce = c.attempt_nonce AND a.status = 'sealed'
      JOIN space_personal_deletion_job j ON j.nonce = a.job_nonce AND j.sequence = a.sequence AND j.phase = a.phase AND j.status = 'deleting'
      JOIN space s ON s.space_ref = j.space_ref AND s.authority_did = j.authority_did AND s.deleted_at IS NOT NULL
      WHERE c.row_id = OLD.rowid AND a.phase = 'ops' AND a.space_ref = OLD.space_ref
        AND a.authority_did = OLD.repo_did AND j.space_ref = OLD.space_ref AND j.authority_did = OLD.repo_did
        AND (j.epoch_id IS NULL OR EXISTS (SELECT 1 FROM space_epoch e WHERE e.id = j.epoch_id
          AND e.space_ref = j.space_ref AND e.repo_did = j.authority_did AND e.state = 'deleting'))
        AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = j.space_ref))
BEGIN SELECT RAISE(ABORT, 'space operation deletion is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_deletion_job_update BEFORE UPDATE ON space_personal_deletion_job
WHEN OLD.status != 'deleting' OR NEW.nonce IS NOT OLD.nonce OR NEW.space_ref IS NOT OLD.space_ref
 OR NEW.authority_did IS NOT OLD.authority_did OR NEW.epoch_id IS NOT OLD.epoch_id OR NEW.created_at IS NOT OLD.created_at
 OR NEW.sequence != OLD.sequence + 1 OR NEW.last_step_phase IS NOT OLD.phase
 OR NOT EXISTS (SELECT 1 FROM space_personal_deletion_attempt a WHERE a.nonce = NEW.last_step_nonce
   AND a.job_nonce = OLD.nonce AND a.space_ref = OLD.space_ref AND a.authority_did = OLD.authority_did
   AND a.epoch_id IS OLD.epoch_id AND a.phase = OLD.phase AND a.sequence = OLD.sequence AND a.status = 'sealed'
   AND a.expected_count = NEW.last_step_count
   AND NOT EXISTS (SELECT 1 FROM space_personal_deletion_candidate c WHERE c.attempt_nonce = a.nonce AND (
     (a.phase = 'records' AND EXISTS (SELECT 1 FROM space_record r WHERE r.rowid = c.row_id))
     OR (a.phase = 'versions' AND EXISTS (SELECT 1 FROM space_record_version v WHERE v.rowid = c.row_id))
     OR (a.phase = 'ops' AND EXISTS (SELECT 1 FROM space_op o WHERE o.rowid = c.row_id)))))
 OR (OLD.phase = 'records' AND (NEW.status != 'deleting' OR NEW.phase != CASE WHEN EXISTS (
   SELECT 1 FROM space_record r WHERE r.space_ref = OLD.space_ref AND r.repo_did = OLD.authority_did)
   THEN 'records' ELSE 'versions' END))
 OR (OLD.phase = 'versions' AND (NEW.status != 'deleting' OR NEW.phase != CASE WHEN EXISTS (
   SELECT 1 FROM space_record_version v WHERE v.epoch_id = OLD.epoch_id)
   THEN 'versions' ELSE 'ops' END))
 OR (OLD.phase = 'ops' AND (NEW.status != CASE WHEN EXISTS (SELECT 1 FROM space_op o
   WHERE o.space_ref = OLD.space_ref AND o.repo_did = OLD.authority_did) THEN 'deleting' ELSE 'complete' END
   OR NEW.phase != CASE WHEN EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = OLD.space_ref AND o.repo_did = OLD.authority_did)
   THEN 'ops' ELSE 'done' END))
 OR (NEW.status = 'complete' AND NOT (
   NOT EXISTS (SELECT 1 FROM space_record r WHERE r.space_ref = OLD.space_ref)
   AND NOT EXISTS (SELECT 1 FROM space_record_version v WHERE v.space_ref = OLD.space_ref)
   AND NOT EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = OLD.space_ref)
   AND NOT EXISTS (SELECT 1 FROM space_snapshot_lease l WHERE l.space_ref = OLD.space_ref)
   AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = OLD.space_ref)
   AND NOT EXISTS (SELECT 1 FROM space_quarantine_job q WHERE q.space_ref = OLD.space_ref)
   AND NOT EXISTS (SELECT 1 FROM space_mutation_attempt m WHERE m.space_ref = OLD.space_ref)
   AND ((OLD.epoch_id IS NULL AND NOT EXISTS (SELECT 1 FROM space_repo h WHERE h.space_ref = OLD.space_ref))
     OR (OLD.epoch_id IS NOT NULL AND EXISTS (SELECT 1 FROM space_repo h
       WHERE h.space_ref = OLD.space_ref AND h.repo_did = OLD.authority_did AND h.active_epoch_id = OLD.epoch_id
       AND h.rev IS NULL AND h.generation = 0 AND h.mutation_id IS OLD.nonce
       AND typeof(h.set_hash) = 'blob' AND h.set_hash = zeroblob(2048))))))
 OR OLD.phase = 'done'
BEGIN SELECT RAISE(ABORT, 'personal deletion progress is not fenced'); END;
