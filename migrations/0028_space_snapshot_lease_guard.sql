DROP TRIGGER space_version_fence_delete;
--> statement-breakpoint
CREATE TRIGGER space_version_fence_delete BEFORE DELETE ON space_record_version
WHEN OLD.until_generation IS NULL OR NOT EXISTS (
  SELECT 1 FROM space_gc_attempt g
  JOIN space_repo h ON h.space_ref = g.space_ref AND h.repo_did = g.repo_did AND h.active_epoch_id = g.epoch_id
  JOIN space_epoch e ON e.id = g.epoch_id AND e.space_ref = g.space_ref AND e.repo_did = g.repo_did AND e.state = 'active'
  WHERE g.epoch_id = OLD.epoch_id AND g.space_ref = OLD.space_ref AND g.repo_did = OLD.repo_did
    AND NOT EXISTS (
      SELECT 1 FROM space_snapshot_lease l WHERE l.epoch_id = OLD.epoch_id AND l.space_ref = OLD.space_ref
        AND l.repo_did = OLD.repo_did
        AND l.generation >= OLD.from_generation AND l.generation < OLD.until_generation
    )
)
BEGIN SELECT RAISE(ABORT, 'space version pruning is not fenced'); END;
