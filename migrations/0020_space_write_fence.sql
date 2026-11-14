CREATE VIEW space_commit_head AS
  SELECT a.mutation_id, a.space_ref, a.repo_did, a.epoch_id, a.generation, a.rev
  FROM space_mutation_attempt a
  JOIN space_commit_assertion m ON m.mutation_id = a.mutation_id || ':won'
  JOIN space_repo h ON h.space_ref = a.space_ref AND h.repo_did = a.repo_did
    AND h.active_epoch_id = a.epoch_id AND h.generation = a.generation
    AND h.mutation_id = a.mutation_id AND h.rev = a.rev AND h.set_hash = a.set_hash;
--> statement-breakpoint
CREATE VIEW space_commit_winner AS
  SELECT h.mutation_id, h.space_ref, h.repo_did, h.epoch_id, h.generation, h.rev
  FROM space_commit_head h
  JOIN space_epoch e ON e.id = h.epoch_id AND e.space_ref = h.space_ref
    AND e.repo_did = h.repo_did AND e.state = 'active'
  JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL;
--> statement-breakpoint
CREATE TRIGGER space_mutation_attempt_immutable BEFORE UPDATE ON space_mutation_attempt
BEGIN SELECT RAISE(ABORT, 'space mutation attempt is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER space_repo_fence_insert BEFORE INSERT ON space_repo
WHEN EXISTS (SELECT 1 FROM space_repo h WHERE h.space_ref = NEW.space_ref AND h.repo_did = NEW.repo_did)
  OR EXISTS (SELECT 1 FROM space_epoch e WHERE e.space_ref = NEW.space_ref AND e.repo_did = NEW.repo_did)
  OR NEW.generation != 1 OR NOT EXISTS (
    SELECT 1 FROM space_mutation_attempt a WHERE a.mutation_id = NEW.mutation_id
      AND a.space_ref = NEW.space_ref AND a.repo_did = NEW.repo_did AND a.epoch_id = NEW.active_epoch_id
      AND a.generation = NEW.generation AND a.rev = NEW.rev AND a.set_hash = NEW.set_hash
  )
BEGIN SELECT RAISE(ABORT, 'space repo insert is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_repo_fence_update BEFORE UPDATE ON space_repo
WHEN NEW.space_ref IS NOT OLD.space_ref OR NEW.repo_did IS NOT OLD.repo_did
  OR NEW.active_epoch_id IS NOT OLD.active_epoch_id OR NEW.generation != OLD.generation + 1
  OR NEW.rev IS NULL OR OLD.rev IS NULL OR NEW.rev <= OLD.rev
  OR NOT EXISTS (
    SELECT 1 FROM space_epoch e WHERE e.id = OLD.active_epoch_id AND e.space_ref = OLD.space_ref
      AND e.repo_did = OLD.repo_did AND e.state = 'active'
  ) OR NOT EXISTS (
    SELECT 1 FROM space_mutation_attempt a WHERE a.mutation_id = NEW.mutation_id
      AND a.space_ref = NEW.space_ref AND a.repo_did = NEW.repo_did AND a.epoch_id = NEW.active_epoch_id
      AND a.generation = NEW.generation AND a.rev = NEW.rev AND a.set_hash = NEW.set_hash
  )
BEGIN SELECT RAISE(ABORT, 'space repo update is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_epoch_fence_insert BEFORE INSERT ON space_epoch
WHEN NEW.state != 'active' OR EXISTS (SELECT 1 FROM space_epoch e WHERE e.id = NEW.id)
  OR NOT EXISTS (
    SELECT 1 FROM space_commit_head h WHERE h.epoch_id = NEW.id AND h.space_ref = NEW.space_ref AND h.repo_did = NEW.repo_did
  )
BEGIN SELECT RAISE(ABORT, 'space epoch insert is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_record_fence_insert BEFORE INSERT ON space_record
WHEN EXISTS (SELECT 1 FROM space_record r WHERE r.space_ref = NEW.space_ref AND r.repo_did = NEW.repo_did
    AND r.collection = NEW.collection AND r.rkey = NEW.rkey)
  OR NOT EXISTS (SELECT 1 FROM space_commit_winner w WHERE w.space_ref = NEW.space_ref
    AND w.repo_did = NEW.repo_did AND w.rev = NEW.repo_rev)
BEGIN SELECT RAISE(ABORT, 'space record insert is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_record_fence_update BEFORE UPDATE ON space_record
WHEN NEW.space_ref IS NOT OLD.space_ref OR NEW.repo_did IS NOT OLD.repo_did
  OR NEW.collection IS NOT OLD.collection OR NEW.rkey IS NOT OLD.rkey
  OR NOT EXISTS (SELECT 1 FROM space_commit_winner w WHERE w.space_ref = OLD.space_ref
    AND w.repo_did = OLD.repo_did AND w.rev = NEW.repo_rev)
BEGIN SELECT RAISE(ABORT, 'space record update is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_record_fence_delete BEFORE DELETE ON space_record
WHEN NOT EXISTS (SELECT 1 FROM space_commit_winner w WHERE w.space_ref = OLD.space_ref AND w.repo_did = OLD.repo_did)
BEGIN SELECT RAISE(ABORT, 'space record delete is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_version_fence_insert BEFORE INSERT ON space_record_version
WHEN EXISTS (SELECT 1 FROM space_record_version v WHERE v.epoch_id = NEW.epoch_id
    AND v.path = NEW.path AND v.from_generation = NEW.from_generation)
  OR NOT EXISTS (SELECT 1 FROM space_commit_winner w WHERE w.epoch_id = NEW.epoch_id
    AND w.space_ref = NEW.space_ref AND w.repo_did = NEW.repo_did AND w.generation = NEW.from_generation AND w.rev = NEW.repo_rev)
BEGIN SELECT RAISE(ABORT, 'space version insert is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_version_fence_update BEFORE UPDATE ON space_record_version
WHEN NOT EXISTS (SELECT 1 FROM space_commit_winner w WHERE w.epoch_id = OLD.epoch_id
  AND w.space_ref = OLD.space_ref AND w.repo_did = OLD.repo_did AND w.generation = NEW.until_generation)
BEGIN SELECT RAISE(ABORT, 'space version update is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_version_fence_delete BEFORE DELETE ON space_record_version
WHEN OLD.until_generation IS NULL OR NOT EXISTS (
  SELECT 1 FROM space_gc_attempt g
  JOIN space_repo h ON h.space_ref = g.space_ref AND h.repo_did = g.repo_did AND h.active_epoch_id = g.epoch_id
  JOIN space_epoch e ON e.id = g.epoch_id AND e.space_ref = g.space_ref AND e.repo_did = g.repo_did AND e.state = 'active'
  WHERE g.epoch_id = OLD.epoch_id AND g.space_ref = OLD.space_ref AND g.repo_did = OLD.repo_did
    AND NOT EXISTS (
      SELECT 1 FROM space_snapshot_lease l WHERE l.epoch_id = OLD.epoch_id AND l.space_ref = OLD.space_ref
        AND l.repo_did = OLD.repo_did AND l.expires_at > unixepoch() AND l.maximum_expires_at > unixepoch()
        AND l.generation >= OLD.from_generation AND l.generation < OLD.until_generation
    )
)
BEGIN SELECT RAISE(ABORT, 'space version pruning is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_op_fence_insert BEFORE INSERT ON space_op
WHEN EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = NEW.space_ref AND o.repo_did = NEW.repo_did
    AND o.rev = NEW.rev AND o.ordinal = NEW.ordinal)
  OR NOT EXISTS (SELECT 1 FROM space_commit_winner w WHERE w.space_ref = NEW.space_ref
    AND w.repo_did = NEW.repo_did AND w.rev = NEW.rev)
BEGIN SELECT RAISE(ABORT, 'space operation insert is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_op_fence_update BEFORE UPDATE ON space_op
BEGIN SELECT RAISE(ABORT, 'space operation is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER space_op_fence_delete BEFORE DELETE ON space_op
BEGIN SELECT RAISE(ABORT, 'space operation deletion is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_blob_usage_fence_insert BEFORE INSERT ON space_blob_usage
WHEN EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = NEW.space_ref AND b.repo_did = NEW.repo_did
    AND b.collection = NEW.collection AND b.rkey = NEW.rkey AND b.cid = NEW.cid)
  OR NOT EXISTS (SELECT 1 FROM space_commit_winner w WHERE w.space_ref = NEW.space_ref AND w.repo_did = NEW.repo_did)
BEGIN SELECT RAISE(ABORT, 'space blob usage insert is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_blob_usage_fence_update BEFORE UPDATE ON space_blob_usage
WHEN NEW.space_ref IS NOT OLD.space_ref OR NEW.repo_did IS NOT OLD.repo_did
  OR NEW.collection IS NOT OLD.collection OR NEW.rkey IS NOT OLD.rkey OR NEW.cid IS NOT OLD.cid
  OR NOT EXISTS (SELECT 1 FROM space_commit_winner w WHERE w.space_ref = OLD.space_ref AND w.repo_did = OLD.repo_did)
BEGIN SELECT RAISE(ABORT, 'space blob usage update is not fenced'); END;
--> statement-breakpoint
CREATE TRIGGER space_blob_usage_fence_delete BEFORE DELETE ON space_blob_usage
WHEN NOT EXISTS (SELECT 1 FROM space_commit_winner w WHERE w.space_ref = OLD.space_ref AND w.repo_did = OLD.repo_did)
BEGIN SELECT RAISE(ABORT, 'space blob usage delete is not fenced'); END;
