CREATE TRIGGER space_quarantine_job_identity BEFORE UPDATE OF id, space_ref, repo_did, epoch_id,
  authority_did, space_type, skey, generation, mutation_id, rev, expected_hash, created_at ON space_quarantine_job
BEGIN SELECT RAISE(ABORT, 'quarantine job identity is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER space_quarantine_job_preserve BEFORE DELETE ON space_quarantine_job
BEGIN SELECT RAISE(ABORT, 'quarantine job must be retained'); END;
--> statement-breakpoint
CREATE TRIGGER space_quarantine_job_status BEFORE UPDATE OF status ON space_quarantine_job
WHEN NOT (
  OLD.status = NEW.status OR (OLD.status = 'running' AND NEW.status IN ('complete', 'failed'))
  OR (OLD.status = 'complete' AND NEW.status = 'activating')
  OR (OLD.status = 'activating' AND NEW.status = 'active')
)
BEGIN SELECT RAISE(ABORT, 'invalid quarantine job transition'); END;
--> statement-breakpoint
CREATE TRIGGER space_quarantined_update BEFORE UPDATE ON space
WHEN EXISTS (SELECT 1 FROM space_epoch e WHERE e.state = 'quarantined'
  AND (e.space_ref = OLD.space_ref OR e.space_ref = NEW.space_ref))
BEGIN SELECT RAISE(ABORT, 'space identity is quarantined'); END;
--> statement-breakpoint
CREATE TRIGGER space_quarantined_delete BEFORE DELETE ON space
WHEN EXISTS (SELECT 1 FROM space_epoch e WHERE e.state = 'quarantined' AND e.space_ref = OLD.space_ref)
BEGIN SELECT RAISE(ABORT, 'space identity is quarantined'); END;
--> statement-breakpoint
CREATE TRIGGER space_quarantined_replace BEFORE INSERT ON space
WHEN EXISTS (SELECT 1 FROM space s JOIN space_epoch e ON e.space_ref = s.space_ref AND e.state = 'quarantined'
  WHERE s.space_ref = NEW.space_ref)
BEGIN SELECT RAISE(ABORT, 'space identity is quarantined'); END;
--> statement-breakpoint
CREATE TRIGGER space_epoch_verification_metadata BEFORE UPDATE OF verified_job_id, activation_nonce ON space_epoch
WHEN OLD.state != 'quarantined' OR NEW.state != 'active'
BEGIN SELECT RAISE(ABORT, 'space epoch verification metadata is immutable'); END;
