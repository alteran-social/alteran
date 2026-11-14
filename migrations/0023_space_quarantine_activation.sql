CREATE TRIGGER space_quarantine_job_frozen_progress
BEFORE UPDATE OF cursor, accumulated_hash, record_count ON space_quarantine_job
WHEN OLD.status != 'running'
BEGIN SELECT RAISE(ABORT, 'completed quarantine progress is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER space_quarantine_job_activation_nonce
BEFORE UPDATE OF activation_nonce ON space_quarantine_job
WHEN OLD.status != 'complete' OR NEW.status != 'activating'
  OR OLD.activation_nonce IS NOT NULL OR NEW.activation_nonce IS NULL
BEGIN SELECT RAISE(ABORT, 'invalid quarantine activation nonce'); END;
--> statement-breakpoint
CREATE TRIGGER space_epoch_verified_activation
BEFORE UPDATE OF state ON space_epoch
WHEN OLD.state = 'quarantined' AND (
  NEW.state != 'active' OR NOT EXISTS (
    SELECT 1 FROM space_quarantine_job j
    JOIN space_repo h ON h.space_ref = j.space_ref AND h.repo_did = j.repo_did
      AND h.active_epoch_id = j.epoch_id AND h.generation = j.generation
      AND h.mutation_id = j.mutation_id AND h.rev = j.rev AND h.set_hash = j.expected_hash
    JOIN space s ON s.space_ref = j.space_ref AND s.deleted_at IS NULL
      AND s.authority_did = j.authority_did AND s.space_type = j.space_type AND s.skey = j.skey
    WHERE j.id = NEW.verified_job_id AND j.activation_nonce = NEW.activation_nonce
      AND j.epoch_id = OLD.id AND j.space_ref = OLD.space_ref AND j.repo_did = OLD.repo_did
      AND j.status = 'activating' AND j.lease_until > unixepoch()
      AND j.accumulated_hash = j.expected_hash
      AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = j.space_ref AND b.repo_did = j.repo_did)
      AND NOT EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = j.space_ref AND o.repo_did = j.repo_did)
      AND NOT EXISTS (SELECT 1 FROM space_record_version v WHERE v.epoch_id = j.epoch_id
        AND v.path COLLATE BINARY > j.cursor COLLATE BINARY)
      AND COALESCE((SELECT (r.collection || '/' || r.rkey) COLLATE BINARY
        FROM space_record r INDEXED BY space_record_path_idx
        WHERE r.space_ref = j.space_ref AND r.repo_did = j.repo_did
        ORDER BY (r.collection || '/' || r.rkey) COLLATE BINARY DESC LIMIT 1)
        > j.cursor COLLATE BINARY, 0) = 0
  )
)
BEGIN SELECT RAISE(ABORT, 'space epoch lacks a verified activation'); END;
--> statement-breakpoint
CREATE TRIGGER space_quarantine_job_activation_done
BEFORE UPDATE OF status ON space_quarantine_job
WHEN OLD.status = 'activating' AND NEW.status = 'active' AND NOT EXISTS (
  SELECT 1 FROM space_epoch e
  JOIN space_repo h ON h.space_ref = OLD.space_ref AND h.repo_did = OLD.repo_did
    AND h.active_epoch_id = OLD.epoch_id AND h.generation = OLD.generation
    AND h.mutation_id = OLD.mutation_id AND h.rev = OLD.rev AND h.set_hash = OLD.expected_hash
  JOIN space s ON s.space_ref = OLD.space_ref AND s.deleted_at IS NULL
    AND s.authority_did = OLD.authority_did AND s.space_type = OLD.space_type AND s.skey = OLD.skey
  WHERE e.id = OLD.epoch_id AND e.space_ref = OLD.space_ref AND e.repo_did = OLD.repo_did
    AND e.state = 'active' AND e.verified_job_id = OLD.id AND e.activation_nonce = OLD.activation_nonce
    AND OLD.lease_until > unixepoch() AND OLD.expected_hash = OLD.accumulated_hash
)
BEGIN SELECT RAISE(ABORT, 'space activation is incomplete'); END;
