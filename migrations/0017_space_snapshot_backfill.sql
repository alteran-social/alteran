CREATE TABLE IF NOT EXISTS space_snapshot_backfill_guard (value integer NOT NULL);
--> statement-breakpoint
DROP TRIGGER IF EXISTS space_snapshot_backfill_run;
--> statement-breakpoint
CREATE TRIGGER space_snapshot_backfill_run AFTER INSERT ON space_snapshot_backfill_guard
BEGIN
  SELECT RAISE(ABORT, 'invalid legacy space repo') WHERE EXISTS (
    SELECT 1 FROM space_repo r LEFT JOIN space s ON s.space_ref = r.space_ref
    WHERE s.space_ref IS NULL OR r.rev IS NULL OR r.generation < 1
      OR r.generation > 9007199254740991 OR length(r.mutation_id) = 0
      OR length(r.set_hash) != 2048
  );
  SELECT RAISE(ABORT, 'orphan legacy space record') WHERE EXISTS (
    SELECT 1 FROM space_record r LEFT JOIN space_repo h
      ON h.space_ref = r.space_ref AND h.repo_did = r.repo_did
    WHERE h.space_ref IS NULL
  );
  SELECT RAISE(ABORT, 'orphan legacy space operation') WHERE EXISTS (
    SELECT 1 FROM space_op o LEFT JOIN space_repo h
      ON h.space_ref = o.space_ref AND h.repo_did = o.repo_did
    WHERE h.space_ref IS NULL
  );
  SELECT RAISE(ABORT, 'orphan legacy space blob usage') WHERE EXISTS (
    SELECT 1 FROM space_blob_usage b LEFT JOIN space_record r ON r.space_ref = b.space_ref
      AND r.repo_did = b.repo_did AND r.collection = b.collection AND r.rkey = b.rkey
    WHERE r.cid IS NULL
  );
  INSERT INTO space_epoch (id, space_ref, repo_did, state, created_at)
    SELECT lower(hex(randomblob(16))), space_ref, repo_did, 'quarantined', unixepoch()
    FROM space_repo WHERE active_epoch_id IS NULL;
  UPDATE space_repo SET active_epoch_id = (
    SELECT e.id FROM space_epoch e WHERE e.space_ref = space_repo.space_ref
      AND e.repo_did = space_repo.repo_did AND e.state = 'quarantined'
  ) WHERE active_epoch_id IS NULL;
  SELECT RAISE(ABORT, 'invalid legacy epoch') WHERE EXISTS (
    SELECT 1 FROM space_repo r LEFT JOIN space_epoch e
      ON e.id = r.active_epoch_id AND e.space_ref = r.space_ref AND e.repo_did = r.repo_did
    WHERE e.id IS NULL OR e.state != 'quarantined'
  );
  INSERT INTO space_record_version
    (epoch_id, space_ref, repo_did, path, collection, rkey, from_generation,
     until_generation, cid, value_cbor, value_size, repo_rev)
    SELECT h.active_epoch_id, r.space_ref, r.repo_did, r.collection || '/' || r.rkey,
      r.collection, r.rkey, h.generation, NULL, r.cid, r.value_cbor, length(r.value_cbor), r.repo_rev
    FROM space_record r JOIN space_repo h ON h.space_ref = r.space_ref AND h.repo_did = r.repo_did
    WHERE NOT EXISTS (SELECT 1 FROM space_record_version v WHERE v.epoch_id = h.active_epoch_id
      AND v.path = r.collection || '/' || r.rkey AND v.until_generation IS NULL);
  SELECT RAISE(ABORT, 'inconsistent legacy space record') WHERE EXISTS (
    SELECT 1 FROM space_record r JOIN space_repo h ON h.space_ref = r.space_ref AND h.repo_did = r.repo_did
    LEFT JOIN space_record_version v ON v.epoch_id = h.active_epoch_id
      AND v.path = r.collection || '/' || r.rkey AND v.until_generation IS NULL
    WHERE v.cid IS NOT r.cid OR v.value_cbor IS NOT r.value_cbor OR v.repo_rev IS NOT r.repo_rev
      OR v.from_generation IS NOT h.generation
  );
END;
--> statement-breakpoint
INSERT INTO space_snapshot_backfill_guard (value) VALUES (1);
--> statement-breakpoint
DROP TRIGGER space_snapshot_backfill_run;
--> statement-breakpoint
DROP TABLE space_snapshot_backfill_guard;
--> statement-breakpoint
CREATE TRIGGER IF NOT EXISTS space_epoch_preserve_owner BEFORE UPDATE OF id, space_ref, repo_did ON space_epoch
BEGIN SELECT RAISE(ABORT, 'space epoch identity is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER IF NOT EXISTS space_epoch_preserve_tombstone BEFORE DELETE ON space_epoch
BEGIN SELECT RAISE(ABORT, 'space epoch tombstone must be retained'); END;
--> statement-breakpoint
CREATE TRIGGER IF NOT EXISTS space_epoch_quarantine_guard BEFORE UPDATE OF state ON space_epoch
WHEN OLD.state = 'quarantined' AND NEW.state != 'quarantined'
BEGIN SELECT RAISE(ABORT, 'quarantined space epoch requires verification'); END;
--> statement-breakpoint
CREATE TRIGGER IF NOT EXISTS space_repo_preserve_tombstone BEFORE DELETE ON space_repo
BEGIN SELECT RAISE(ABORT, 'space repo tombstone must be retained'); END;
--> statement-breakpoint
CREATE TRIGGER IF NOT EXISTS space_record_version_insert_guard BEFORE INSERT ON space_record_version
WHEN NEW.until_generation IS NOT NULL OR NOT EXISTS (
  SELECT 1 FROM space_epoch e JOIN space_repo h ON h.active_epoch_id = e.id
    AND h.space_ref = e.space_ref AND h.repo_did = e.repo_did AND h.generation = NEW.from_generation
  WHERE e.id = NEW.epoch_id AND e.space_ref = NEW.space_ref AND e.repo_did = NEW.repo_did AND e.state = 'active'
) OR EXISTS (
  SELECT 1 FROM space_record_version v WHERE v.epoch_id = NEW.epoch_id AND v.path = NEW.path
    AND NEW.from_generation < COALESCE(v.until_generation, 9223372036854775807)
    AND v.from_generation < COALESCE(NEW.until_generation, 9223372036854775807)
)
BEGIN SELECT RAISE(ABORT, 'invalid or overlapping space record version'); END;
--> statement-breakpoint
CREATE TRIGGER IF NOT EXISTS space_record_version_update_guard BEFORE UPDATE ON space_record_version
WHEN OLD.until_generation IS NOT NULL OR NEW.until_generation IS NULL
  OR NEW.epoch_id IS NOT OLD.epoch_id OR NEW.space_ref IS NOT OLD.space_ref
  OR NEW.repo_did IS NOT OLD.repo_did OR NEW.path IS NOT OLD.path
  OR NEW.collection IS NOT OLD.collection OR NEW.rkey IS NOT OLD.rkey
  OR NEW.from_generation IS NOT OLD.from_generation OR NEW.cid IS NOT OLD.cid
  OR NEW.value_cbor IS NOT OLD.value_cbor OR NEW.value_size IS NOT OLD.value_size
  OR NEW.repo_rev IS NOT OLD.repo_rev OR NOT EXISTS (
    SELECT 1 FROM space_epoch e JOIN space_repo h ON h.active_epoch_id = e.id
      AND h.space_ref = e.space_ref AND h.repo_did = e.repo_did AND h.generation = NEW.until_generation
    WHERE e.id = OLD.epoch_id AND e.space_ref = OLD.space_ref AND e.repo_did = OLD.repo_did AND e.state = 'active'
  )
BEGIN SELECT RAISE(ABORT, 'space record version is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER IF NOT EXISTS space_record_version_delete_guard BEFORE DELETE ON space_record_version
WHEN OLD.until_generation IS NULL OR EXISTS (
  SELECT 1 FROM space_epoch e WHERE e.id = OLD.epoch_id AND e.state = 'quarantined'
)
BEGIN SELECT RAISE(ABORT, 'current or quarantined space record version'); END;
