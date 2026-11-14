// `t` is a materialized target with space_ref and repo_did columns.
export const SPACE_GENESIS_EMPTY = `
  NOT EXISTS (SELECT 1 FROM space_repo h WHERE h.space_ref = t.space_ref AND h.repo_did = t.repo_did)
  AND NOT EXISTS (SELECT 1 FROM space_epoch e INDEXED BY space_epoch_space_owner WHERE e.space_ref = t.space_ref AND e.repo_did = t.repo_did)
  AND NOT EXISTS (SELECT 1 FROM space_record r WHERE r.space_ref = t.space_ref AND r.repo_did = t.repo_did)
  AND NOT EXISTS (SELECT 1 FROM space_op o WHERE o.space_ref = t.space_ref AND o.repo_did = t.repo_did)
  AND NOT EXISTS (SELECT 1 FROM space_record_version v INDEXED BY space_record_version_space_owner_epoch WHERE v.space_ref = t.space_ref AND v.repo_did = t.repo_did)
  AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = t.space_ref AND b.repo_did = t.repo_did)
  AND NOT EXISTS (SELECT 1 FROM space_snapshot_lease l INDEXED BY space_snapshot_lease_owner_expiry WHERE l.space_ref = t.space_ref AND l.repo_did = t.repo_did)
  AND NOT EXISTS (SELECT 1 FROM space_gc_attempt g INDEXED BY space_gc_attempt_owner WHERE g.space_ref = t.space_ref AND g.repo_did = t.repo_did)
  AND NOT EXISTS (SELECT 1 FROM space_quarantine_job q INDEXED BY space_quarantine_job_owner_epoch WHERE q.space_ref = t.space_ref AND q.repo_did = t.repo_did)
  AND NOT EXISTS (SELECT 1 FROM space_mutation_attempt m INDEXED BY space_mutation_attempt_owner WHERE m.space_ref = t.space_ref AND m.repo_did = t.repo_did)
  AND NOT EXISTS (SELECT 1 FROM space_personal_creation_attempt c WHERE c.space_ref = t.space_ref)
  AND NOT EXISTS (SELECT 1 FROM space_personal_deletion_job j WHERE j.space_ref = t.space_ref)
  AND NOT EXISTS (SELECT 1 FROM space_personal_deletion_attempt d INDEXED BY space_personal_deletion_attempt_owner WHERE d.space_ref = t.space_ref)
`;
