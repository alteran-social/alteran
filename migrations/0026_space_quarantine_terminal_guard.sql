CREATE TRIGGER space_quarantine_job_insert_guard BEFORE INSERT ON space_quarantine_job
WHEN NEW.status != 'running' OR NEW.failure_reason IS NOT NULL OR NEW.activation_nonce IS NOT NULL
  OR EXISTS (SELECT 1 FROM space_quarantine_job j WHERE j.id = NEW.id
    OR (j.space_ref = NEW.space_ref AND j.repo_did = NEW.repo_did AND j.epoch_id = NEW.epoch_id))
BEGIN SELECT RAISE(ABORT, 'quarantine job must be new and running'); END;
--> statement-breakpoint
CREATE TRIGGER space_quarantine_job_failure_reason BEFORE UPDATE OF failure_reason ON space_quarantine_job
WHEN NOT (OLD.status = 'running' AND OLD.failure_reason IS NULL AND (
  (NEW.status = 'complete' AND NEW.failure_reason IS NULL)
  OR (NEW.status = 'failed' AND (NEW.failure_reason IS 'invalid' OR NEW.failure_reason IS 'unsupported'))
))
BEGIN SELECT RAISE(ABORT, 'invalid quarantine failure reason'); END;
--> statement-breakpoint
CREATE TRIGGER space_quarantine_job_status_reason BEFORE UPDATE OF status ON space_quarantine_job
WHEN (NEW.status = 'failed' AND NEW.failure_reason IS NOT 'invalid' AND NEW.failure_reason IS NOT 'unsupported')
  OR (NEW.status != 'failed' AND NEW.failure_reason IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'quarantine status requires a matching reason'); END;
--> statement-breakpoint
CREATE TRIGGER space_quarantine_job_terminal_immutable BEFORE UPDATE ON space_quarantine_job
WHEN OLD.status IN ('active', 'failed')
BEGIN SELECT RAISE(ABORT, 'quarantine result is immutable'); END;
