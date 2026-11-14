SELECT CASE WHEN
  NOT EXISTS (SELECT 1 FROM space_epoch INDEXED BY space_epoch_bound_incarnation WHERE owner_incarnation IS NOT NULL)
  AND NOT EXISTS (SELECT 1 FROM space_mutation_attempt INDEXED BY space_mutation_attempt_bound_incarnation WHERE owner_incarnation IS NOT NULL)
  AND NOT EXISTS (SELECT 1 FROM space_personal_policy INDEXED BY space_personal_policy_bound_incarnation WHERE authority_incarnation IS NOT NULL)
  AND NOT EXISTS (SELECT 1 FROM space_personal_creation_attempt INDEXED BY space_personal_creation_bound_incarnation WHERE authority_incarnation IS NOT NULL)
  THEN 1 ELSE json('{') END;
--> statement-breakpoint
CREATE VIEW space_owned_epoch AS
  SELECT e.id, e.space_ref, e.repo_did, e.state, e.owner_incarnation
  FROM space_epoch e JOIN account a ON a.did = e.repo_did AND a.space_incarnation = e.owner_incarnation
  JOIN space s ON s.space_ref = e.space_ref
    AND s.space_ref = 'at://' || s.authority_did || '/space/' || s.space_type || '/' || s.skey
  JOIN account_state state ON state.did = a.did AND typeof(state.active) = 'integer' AND state.active = 1
    AND state.status IS NULL AND state.suspended_until IS NULL
  WHERE e.owner_incarnation IS NOT NULL AND (s.authority_did != e.repo_did
    OR EXISTS (SELECT 1 FROM space_personal_policy p WHERE p.space_ref = e.space_ref
      AND p.authority_did = e.repo_did AND p.authority_incarnation = e.owner_incarnation)
  );
--> statement-breakpoint
CREATE TRIGGER space_personal_creation_owner_insert BEFORE INSERT ON space_personal_creation_attempt
WHEN typeof(NEW.authority_incarnation) != 'text' OR length(NEW.authority_incarnation) != 32
  OR length(CAST(NEW.authority_incarnation AS BLOB)) != 32 OR NEW.authority_incarnation GLOB '*[^0-9a-f]*'
  OR NEW.space_ref != 'at://' || NEW.authority_did || '/space/' || NEW.space_type || '/' || NEW.skey
  OR EXISTS (SELECT 1 FROM space_personal_creation_attempt a WHERE a.nonce = NEW.nonce OR a.space_ref = NEW.space_ref)
  OR EXISTS (SELECT 1 FROM space_personal_deletion_candidate c WHERE c.attempt_nonce = NEW.nonce)
  OR EXISTS (SELECT 1 FROM space_commit_assertion c
    WHERE c.mutation_id >= NEW.nonce || ':' AND c.mutation_id < NEW.nonce || ';')
  OR NOT EXISTS (SELECT 1 FROM account a JOIN account_state state ON state.did = a.did
    WHERE a.did = NEW.authority_did AND a.space_incarnation = NEW.authority_incarnation
      AND typeof(state.active) = 'integer' AND state.active = 1 AND state.status IS NULL AND state.suspended_until IS NULL)
BEGIN SELECT RAISE(ABORT, 'personal Space owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_policy_owner_insert BEFORE INSERT ON space_personal_policy
WHEN typeof(NEW.authority_incarnation) != 'text' OR length(NEW.authority_incarnation) != 32
  OR length(CAST(NEW.authority_incarnation AS BLOB)) != 32 OR NEW.authority_incarnation GLOB '*[^0-9a-f]*'
  OR NOT EXISTS (SELECT 1 FROM space_personal_creation_attempt c JOIN account a ON a.did = c.authority_did
    JOIN account_state state ON state.did = a.did
    WHERE c.nonce = NEW.creation_nonce AND c.space_ref = NEW.space_ref AND c.authority_did = NEW.authority_did
      AND c.authority_incarnation = NEW.authority_incarnation AND a.space_incarnation = NEW.authority_incarnation
      AND typeof(state.active) = 'integer' AND state.active = 1 AND state.status IS NULL AND state.suspended_until IS NULL)
BEGIN SELECT RAISE(ABORT, 'personal Space policy owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_owner_space_insert BEFORE INSERT ON space
WHEN EXISTS (SELECT 1 FROM space s WHERE s.space_ref = NEW.space_ref)
BEGIN SELECT RAISE(ABORT, 'Space identity already exists'); END;
--> statement-breakpoint
CREATE TRIGGER space_owner_space_update BEFORE UPDATE ON space
WHEN NEW.space_ref IS NOT OLD.space_ref OR NEW.authority_did IS NOT OLD.authority_did
  OR NEW.space_type IS NOT OLD.space_type OR NEW.skey IS NOT OLD.skey OR NEW.created_at IS NOT OLD.created_at
  OR (NEW.deleted_at IS NOT OLD.deleted_at AND NOT EXISTS (
    SELECT 1 FROM space_personal_deletion_job j JOIN space_personal_policy p
      ON p.space_ref = j.space_ref AND p.authority_did = j.authority_did
    JOIN account a ON a.did = p.authority_did AND a.space_incarnation = p.authority_incarnation
    JOIN account_state state ON state.did = a.did
    WHERE j.space_ref = OLD.space_ref AND j.authority_did = OLD.authority_did AND j.status = 'deleting'
      AND typeof(state.active) = 'integer' AND state.active = 1 AND state.status IS NULL AND state.suspended_until IS NULL
  ))
BEGIN SELECT RAISE(ABORT, 'Space identity is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER space_owner_space_delete BEFORE DELETE ON space
BEGIN SELECT RAISE(ABORT, 'Space identity must be retained'); END;
--> statement-breakpoint
CREATE TRIGGER space_mutation_owner_insert BEFORE INSERT ON space_mutation_attempt
WHEN typeof(NEW.owner_incarnation) != 'text' OR length(NEW.owner_incarnation) != 32
  OR length(CAST(NEW.owner_incarnation AS BLOB)) != 32 OR NEW.owner_incarnation GLOB '*[^0-9a-f]*'
  OR typeof(NEW.mutation_id) != 'text' OR length(NEW.mutation_id) != 36
  OR length(CAST(NEW.mutation_id AS BLOB)) != 36 OR substr(NEW.mutation_id, 9, 1) != '-'
  OR substr(NEW.mutation_id, 14, 1) != '-' OR substr(NEW.mutation_id, 19, 1) != '-'
  OR substr(NEW.mutation_id, 24, 1) != '-' OR length(replace(NEW.mutation_id, '-', '')) != 32
  OR replace(NEW.mutation_id, '-', '') GLOB '*[^0-9a-f]*'
  OR EXISTS (SELECT 1 FROM space_mutation_attempt a WHERE a.mutation_id = NEW.mutation_id
    OR (a.space_ref = NEW.space_ref AND a.repo_did = NEW.repo_did))
  OR EXISTS (SELECT 1 FROM space_commit_assertion c WHERE c.mutation_id >= NEW.mutation_id || ':'
    AND c.mutation_id < NEW.mutation_id || ';'
    AND c.mutation_id != NEW.mutation_id || ':baseline:' || CAST(total_changes() + 1 AS TEXT))
  OR EXISTS (SELECT 1 FROM space_personal_deletion_candidate c WHERE c.attempt_nonce = NEW.mutation_id)
  OR NOT EXISTS (SELECT 1 FROM account a JOIN account_state state ON state.did = a.did
    WHERE a.did = NEW.repo_did AND a.space_incarnation = NEW.owner_incarnation
      AND typeof(state.active) = 'integer' AND state.active = 1 AND state.status IS NULL AND state.suspended_until IS NULL)
  OR EXISTS (SELECT 1 FROM space s WHERE s.space_ref = NEW.space_ref
    AND s.space_ref != 'at://' || s.authority_did || '/space/' || s.space_type || '/' || s.skey)
  OR EXISTS (SELECT 1 FROM space s WHERE s.space_ref = NEW.space_ref AND s.authority_did = NEW.repo_did
    AND NOT EXISTS (SELECT 1 FROM space_personal_policy p WHERE p.space_ref = s.space_ref
      AND p.authority_did = NEW.repo_did AND p.authority_incarnation = NEW.owner_incarnation))
  OR EXISTS (SELECT 1 FROM space_repo h WHERE h.space_ref = NEW.space_ref AND h.repo_did = NEW.repo_did
    AND NOT EXISTS (SELECT 1 FROM space_epoch e WHERE e.id = h.active_epoch_id AND e.space_ref = h.space_ref
      AND e.repo_did = h.repo_did AND e.state = 'active'
      AND e.owner_incarnation = NEW.owner_incarnation))
  OR (NOT EXISTS (SELECT 1 FROM space_repo h WHERE h.space_ref = NEW.space_ref AND h.repo_did = NEW.repo_did) AND (
    EXISTS (SELECT 1 FROM space_epoch e INDEXED BY space_epoch_space_owner WHERE e.space_ref = NEW.space_ref AND e.repo_did = NEW.repo_did)
    OR EXISTS (SELECT 1 FROM space_record r WHERE r.space_ref = NEW.space_ref AND r.repo_did = NEW.repo_did)
    OR EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = NEW.space_ref AND o.repo_did = NEW.repo_did)
    OR EXISTS (SELECT 1 FROM space_record_version v INDEXED BY space_record_version_space_owner_epoch WHERE v.space_ref = NEW.space_ref AND v.repo_did = NEW.repo_did)
    OR EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = NEW.space_ref AND b.repo_did = NEW.repo_did)
    OR EXISTS (SELECT 1 FROM space_snapshot_lease l INDEXED BY space_snapshot_lease_owner_expiry WHERE l.space_ref = NEW.space_ref AND l.repo_did = NEW.repo_did)
    OR EXISTS (SELECT 1 FROM space_gc_attempt g INDEXED BY space_gc_attempt_owner WHERE g.space_ref = NEW.space_ref AND g.repo_did = NEW.repo_did)
    OR EXISTS (SELECT 1 FROM space_quarantine_job q INDEXED BY space_quarantine_job_owner_epoch WHERE q.space_ref = NEW.space_ref AND q.repo_did = NEW.repo_did)
    OR EXISTS (SELECT 1 FROM space_personal_creation_attempt c WHERE c.space_ref = NEW.space_ref)
    OR EXISTS (SELECT 1 FROM space_personal_deletion_job j WHERE j.space_ref = NEW.space_ref)
    OR EXISTS (SELECT 1 FROM space_personal_deletion_attempt d INDEXED BY space_personal_deletion_attempt_owner WHERE d.space_ref = NEW.space_ref)
  ))
BEGIN SELECT RAISE(ABORT, 'Space mutation owner or history is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_repo_owner_genesis BEFORE INSERT ON space_repo
WHEN NOT EXISTS (SELECT 1 FROM space_mutation_attempt attempt JOIN account a ON a.did = attempt.repo_did
    AND a.space_incarnation = attempt.owner_incarnation JOIN account_state state ON state.did = a.did
    WHERE attempt.mutation_id = NEW.mutation_id AND attempt.space_ref = NEW.space_ref AND attempt.repo_did = NEW.repo_did
      AND attempt.epoch_id = NEW.active_epoch_id AND typeof(state.active) = 'integer' AND state.active = 1
      AND state.status IS NULL AND state.suspended_until IS NULL)
  OR EXISTS (SELECT 1 FROM space_mutation_attempt a INDEXED BY space_mutation_attempt_owner
    WHERE a.space_ref = NEW.space_ref AND a.repo_did = NEW.repo_did AND a.mutation_id != NEW.mutation_id)
  OR EXISTS (SELECT 1 FROM space_epoch e INDEXED BY space_epoch_space_owner WHERE e.space_ref = NEW.space_ref AND e.repo_did = NEW.repo_did)
  OR EXISTS (SELECT 1 FROM space_record r WHERE r.space_ref = NEW.space_ref AND r.repo_did = NEW.repo_did)
  OR EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = NEW.space_ref AND o.repo_did = NEW.repo_did)
  OR EXISTS (SELECT 1 FROM space_record_version v INDEXED BY space_record_version_space_owner_epoch WHERE v.space_ref = NEW.space_ref AND v.repo_did = NEW.repo_did)
  OR EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = NEW.space_ref AND b.repo_did = NEW.repo_did)
  OR EXISTS (SELECT 1 FROM space_snapshot_lease l INDEXED BY space_snapshot_lease_owner_expiry WHERE l.space_ref = NEW.space_ref AND l.repo_did = NEW.repo_did)
  OR EXISTS (SELECT 1 FROM space_gc_attempt g INDEXED BY space_gc_attempt_owner WHERE g.space_ref = NEW.space_ref AND g.repo_did = NEW.repo_did)
  OR EXISTS (SELECT 1 FROM space_quarantine_job q INDEXED BY space_quarantine_job_owner_epoch WHERE q.space_ref = NEW.space_ref AND q.repo_did = NEW.repo_did)
  OR EXISTS (SELECT 1 FROM space_personal_creation_attempt c WHERE c.space_ref = NEW.space_ref)
  OR EXISTS (SELECT 1 FROM space_personal_deletion_job j WHERE j.space_ref = NEW.space_ref)
  OR EXISTS (SELECT 1 FROM space_personal_deletion_attempt d INDEXED BY space_personal_deletion_attempt_owner WHERE d.space_ref = NEW.space_ref)
BEGIN SELECT RAISE(ABORT, 'Space repo history is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_epoch_owner_insert BEFORE INSERT ON space_epoch
WHEN typeof(NEW.owner_incarnation) != 'text' OR length(NEW.owner_incarnation) != 32
  OR length(CAST(NEW.owner_incarnation AS BLOB)) != 32 OR NEW.owner_incarnation GLOB '*[^0-9a-f]*'
  OR typeof(NEW.id) != 'text' OR length(CAST(NEW.id AS BLOB)) NOT BETWEEN 1 AND 128 OR instr(NEW.id, char(0)) != 0
  OR EXISTS (SELECT 1 FROM space_epoch e WHERE e.id = NEW.id)
  OR NOT EXISTS (SELECT 1 FROM space_mutation_attempt attempt JOIN space_repo h
      ON h.space_ref = attempt.space_ref AND h.repo_did = attempt.repo_did AND h.active_epoch_id = attempt.epoch_id
    JOIN account a ON a.did = attempt.repo_did AND a.space_incarnation = attempt.owner_incarnation
    JOIN account_state state ON state.did = a.did
    WHERE attempt.epoch_id = NEW.id AND attempt.space_ref = NEW.space_ref AND attempt.repo_did = NEW.repo_did
      AND attempt.owner_incarnation = NEW.owner_incarnation AND h.mutation_id = attempt.mutation_id
      AND typeof(state.active) = 'integer' AND state.active = 1 AND state.status IS NULL AND state.suspended_until IS NULL)
BEGIN SELECT RAISE(ABORT, 'Space epoch owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_epoch_owner_immutable BEFORE UPDATE OF owner_incarnation ON space_epoch
WHEN NEW.owner_incarnation IS NOT OLD.owner_incarnation
BEGIN SELECT RAISE(ABORT, 'Space epoch owner is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER space_epoch_owner_state BEFORE UPDATE OF state ON space_epoch
WHEN NOT EXISTS (SELECT 1 FROM space_owned_epoch e WHERE e.id = OLD.id AND e.space_ref = OLD.space_ref AND e.repo_did = OLD.repo_did)
BEGIN SELECT RAISE(ABORT, 'Space epoch owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_repo_owner_update BEFORE UPDATE ON space_repo
WHEN NOT EXISTS (SELECT 1 FROM space_owned_epoch e WHERE e.id = OLD.active_epoch_id
  AND e.space_ref = OLD.space_ref AND e.repo_did = OLD.repo_did)
BEGIN SELECT RAISE(ABORT, 'Space repo owner is unavailable'); END;
--> statement-breakpoint
DROP VIEW space_commit_winner;
--> statement-breakpoint
DROP VIEW space_commit_head;
--> statement-breakpoint
CREATE VIEW space_commit_head AS
  SELECT attempt.mutation_id, attempt.space_ref, attempt.repo_did, attempt.epoch_id,
    attempt.generation, attempt.rev, attempt.owner_incarnation
  FROM space_mutation_attempt attempt
  JOIN space_commit_assertion marker ON marker.mutation_id = attempt.mutation_id || ':won'
  JOIN space_repo h ON h.space_ref = attempt.space_ref AND h.repo_did = attempt.repo_did
    AND h.active_epoch_id = attempt.epoch_id AND h.generation = attempt.generation
    AND h.mutation_id = attempt.mutation_id AND h.rev = attempt.rev AND h.set_hash = attempt.set_hash
  JOIN account a ON a.did = attempt.repo_did AND a.space_incarnation = attempt.owner_incarnation
  JOIN account_state state ON state.did = a.did AND typeof(state.active) = 'integer' AND state.active = 1
    AND state.status IS NULL AND state.suspended_until IS NULL
  WHERE NOT EXISTS (SELECT 1 FROM space s WHERE s.space_ref = attempt.space_ref)
    OR EXISTS (SELECT 1 FROM space s WHERE s.space_ref = attempt.space_ref
      AND s.space_ref = 'at://' || s.authority_did || '/space/' || s.space_type || '/' || s.skey
      AND (s.authority_did != attempt.repo_did OR EXISTS (SELECT 1 FROM space_personal_policy p
        WHERE p.space_ref = s.space_ref AND p.authority_did = attempt.repo_did
          AND p.authority_incarnation = attempt.owner_incarnation)));
--> statement-breakpoint
CREATE VIEW space_commit_winner AS
  SELECT h.mutation_id, h.space_ref, h.repo_did, h.epoch_id, h.generation, h.rev
  FROM space_commit_head h JOIN space_owned_epoch e ON e.id = h.epoch_id AND e.space_ref = h.space_ref
    AND e.repo_did = h.repo_did AND e.owner_incarnation = h.owner_incarnation AND e.state = 'active'
  JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL;
--> statement-breakpoint
CREATE TRIGGER space_record_owner_delete BEFORE DELETE ON space_record
WHEN NOT EXISTS (SELECT 1 FROM space_repo h JOIN space_owned_epoch e ON e.id = h.active_epoch_id
  AND e.space_ref = h.space_ref AND e.repo_did = h.repo_did WHERE h.space_ref = OLD.space_ref AND h.repo_did = OLD.repo_did)
BEGIN SELECT RAISE(ABORT, 'Space record owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_op_owner_delete BEFORE DELETE ON space_op
WHEN NOT EXISTS (SELECT 1 FROM space_repo h JOIN space_owned_epoch e ON e.id = h.active_epoch_id
  AND e.space_ref = h.space_ref AND e.repo_did = h.repo_did WHERE h.space_ref = OLD.space_ref AND h.repo_did = OLD.repo_did)
BEGIN SELECT RAISE(ABORT, 'Space operation owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_version_owner_delete BEFORE DELETE ON space_record_version
WHEN NOT EXISTS (SELECT 1 FROM space_owned_epoch e WHERE e.id = OLD.epoch_id
  AND e.space_ref = OLD.space_ref AND e.repo_did = OLD.repo_did)
BEGIN SELECT RAISE(ABORT, 'Space version owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_blob_usage_owner_delete BEFORE DELETE ON space_blob_usage
WHEN NOT EXISTS (SELECT 1 FROM space_repo h JOIN space_owned_epoch e ON e.id = h.active_epoch_id
  AND e.space_ref = h.space_ref AND e.repo_did = h.repo_did WHERE h.space_ref = OLD.space_ref AND h.repo_did = OLD.repo_did)
BEGIN SELECT RAISE(ABORT, 'Space blob owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_snapshot_owner_insert BEFORE INSERT ON space_snapshot_lease
WHEN NOT EXISTS (SELECT 1 FROM space_owned_epoch e WHERE e.id = NEW.epoch_id
  AND e.space_ref = NEW.space_ref AND e.repo_did = NEW.repo_did AND e.state = 'active')
BEGIN SELECT RAISE(ABORT, 'Space snapshot owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_snapshot_owner_update BEFORE UPDATE ON space_snapshot_lease
WHEN NOT EXISTS (SELECT 1 FROM space_owned_epoch e WHERE e.id = OLD.epoch_id
  AND e.space_ref = OLD.space_ref AND e.repo_did = OLD.repo_did AND e.state = 'active')
BEGIN SELECT RAISE(ABORT, 'Space snapshot owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_gc_owner_insert BEFORE INSERT ON space_gc_attempt
WHEN NOT EXISTS (SELECT 1 FROM space_owned_epoch e WHERE e.id = NEW.epoch_id
  AND e.space_ref = NEW.space_ref AND e.repo_did = NEW.repo_did AND e.state = 'active')
BEGIN SELECT RAISE(ABORT, 'Space GC owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_deletion_owner_insert BEFORE INSERT ON space_personal_deletion_job
WHEN NOT EXISTS (SELECT 1 FROM space_personal_policy p JOIN account a ON a.did = p.authority_did
  AND a.space_incarnation = p.authority_incarnation JOIN account_state state ON state.did = a.did
  WHERE p.space_ref = NEW.space_ref AND p.authority_did = NEW.authority_did
    AND typeof(state.active) = 'integer' AND state.active = 1 AND state.status IS NULL AND state.suspended_until IS NULL
    AND (NEW.epoch_id IS NULL OR EXISTS (SELECT 1 FROM space_owned_epoch e WHERE e.id = NEW.epoch_id
      AND e.space_ref = NEW.space_ref AND e.repo_did = NEW.authority_did)))
BEGIN SELECT RAISE(ABORT, 'personal Space deletion owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_deletion_step_owner_insert BEFORE INSERT ON space_personal_deletion_attempt
WHEN EXISTS (SELECT 1 FROM space_personal_deletion_candidate c WHERE c.attempt_nonce = NEW.nonce)
  OR EXISTS (SELECT 1 FROM space_mutation_attempt a WHERE a.mutation_id = NEW.nonce)
  OR EXISTS (SELECT 1 FROM space_commit_assertion c WHERE c.mutation_id >= NEW.nonce || ':' AND c.mutation_id < NEW.nonce || ';')
  OR NOT EXISTS (SELECT 1 FROM space_personal_deletion_job j JOIN space_personal_policy p
  ON p.space_ref = j.space_ref AND p.authority_did = j.authority_did JOIN account a
  ON a.did = p.authority_did AND a.space_incarnation = p.authority_incarnation JOIN account_state state ON state.did = a.did
  WHERE j.nonce = NEW.job_nonce AND j.space_ref = NEW.space_ref AND j.authority_did = NEW.authority_did
    AND typeof(state.active) = 'integer' AND state.active = 1 AND state.status IS NULL AND state.suspended_until IS NULL)
BEGIN SELECT RAISE(ABORT, 'personal Space deletion owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_quarantine_owner_insert BEFORE INSERT ON space_quarantine_job
WHEN NOT EXISTS (SELECT 1 FROM space_owned_epoch e
  JOIN space_repo h ON h.space_ref = e.space_ref AND h.repo_did = e.repo_did AND h.active_epoch_id = e.id
  JOIN space s ON s.space_ref = e.space_ref AND s.deleted_at IS NULL
  WHERE e.id = NEW.epoch_id AND e.space_ref = NEW.space_ref AND e.repo_did = NEW.repo_did
    AND e.state = 'quarantined' AND s.authority_did = NEW.authority_did
    AND s.space_type = NEW.space_type AND s.skey = NEW.skey)
BEGIN SELECT RAISE(ABORT, 'Space quarantine owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_quarantine_owner_update BEFORE UPDATE ON space_quarantine_job
WHEN NOT EXISTS (SELECT 1 FROM space_owned_epoch e
  JOIN space_repo h ON h.space_ref = e.space_ref AND h.repo_did = e.repo_did AND h.active_epoch_id = e.id
  JOIN space s ON s.space_ref = e.space_ref AND s.deleted_at IS NULL
  WHERE e.id = OLD.epoch_id AND e.space_ref = OLD.space_ref AND e.repo_did = OLD.repo_did
    AND s.authority_did = OLD.authority_did AND s.space_type = OLD.space_type AND s.skey = OLD.skey
    AND (e.state = 'quarantined' OR (e.state = 'active' AND OLD.status = 'activating' AND NEW.status = 'active')))
BEGIN SELECT RAISE(ABORT, 'Space quarantine owner is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_personal_deletion_owner_update BEFORE UPDATE ON space_personal_deletion_job
WHEN NOT EXISTS (SELECT 1 FROM space_personal_policy p JOIN account a ON a.did = p.authority_did
  AND a.space_incarnation = p.authority_incarnation JOIN account_state state ON state.did = a.did
  JOIN space s ON s.space_ref = p.space_ref AND s.authority_did = p.authority_did
    AND s.space_ref = 'at://' || s.authority_did || '/space/' || s.space_type || '/' || s.skey
  WHERE p.space_ref = OLD.space_ref AND p.authority_did = OLD.authority_did
    AND typeof(state.active) = 'integer' AND state.active = 1 AND state.status IS NULL AND state.suspended_until IS NULL
    AND (OLD.epoch_id IS NULL OR EXISTS (SELECT 1 FROM space_owned_epoch e WHERE e.id = OLD.epoch_id
      AND e.space_ref = OLD.space_ref AND e.repo_did = OLD.authority_did AND e.state = 'deleting')))
BEGIN SELECT RAISE(ABORT, 'personal Space deletion owner is unavailable'); END;
