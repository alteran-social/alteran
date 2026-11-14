CREATE TRIGGER space_snapshot_lease_quota BEFORE INSERT ON space_snapshot_lease
WHEN EXISTS (SELECT 1 FROM space_snapshot_lease WHERE id = NEW.id)
  OR EXISTS (
    SELECT 1 FROM space_snapshot_lease INDEXED BY space_snapshot_lease_owner_expiry
    WHERE space_ref = NEW.space_ref AND repo_did = NEW.repo_did LIMIT 1 OFFSET 15
  )
  OR EXISTS (SELECT 1 FROM space_snapshot_lease LIMIT 1 OFFSET 127)
BEGIN SELECT RAISE(ABORT, 'space snapshot lease quota exceeded'); END;
--> statement-breakpoint
CREATE TRIGGER space_snapshot_lease_identity_immutable BEFORE UPDATE ON space_snapshot_lease
WHEN NEW.id IS NOT OLD.id OR NEW.token IS NOT OLD.token OR NEW.space_ref IS NOT OLD.space_ref
  OR NEW.repo_did IS NOT OLD.repo_did OR NEW.epoch_id IS NOT OLD.epoch_id
  OR NEW.generation IS NOT OLD.generation OR NEW.rev IS NOT OLD.rev OR NEW.set_hash IS NOT OLD.set_hash
  OR NEW.maximum_expires_at IS NOT OLD.maximum_expires_at OR NEW.expires_at > OLD.maximum_expires_at
BEGIN SELECT RAISE(ABORT, 'space snapshot lease identity is immutable'); END;
