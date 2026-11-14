export type CleanupPhase = "records" | "versions" | "ops";

type PhaseSql = {
  readonly scan: string;
  readonly remaining: string;
  readonly remove: string;
};

export const CLEANUP_PHASES: Record<CleanupPhase, PhaseSql> = {
  records: {
    scan: `SELECT r.rowid AS row_id, CASE WHEN typeof(r.value_cbor) = 'blob'
      AND length(r.value_cbor) BETWEEN 1 AND 1048576 THEN length(r.value_cbor) ELSE -1 END AS byte_size
      FROM space_record r INDEXED BY sqlite_autoindex_space_record_1 WHERE r.space_ref = ? AND r.repo_did = ?
      ORDER BY r.collection, r.rkey LIMIT ?`,
    remaining:
      "SELECT 1 FROM space_record WHERE space_ref = ? AND repo_did = ? LIMIT 1",
    remove: `DELETE FROM space_record NOT INDEXED WHERE rowid IN (
      SELECT row_id FROM space_personal_deletion_candidate WHERE attempt_nonce = ?
    ) AND space_ref = ? AND repo_did = ?`,
  },
  versions: {
    scan: `SELECT v.rowid AS row_id, CASE WHEN typeof(v.value_cbor) = 'blob'
      AND length(v.value_cbor) BETWEEN 1 AND 1048576 THEN length(v.value_cbor) ELSE -1 END AS byte_size
      FROM space_record_version v INDEXED BY sqlite_autoindex_space_record_version_1
      WHERE v.epoch_id = (SELECT epoch_id FROM space_personal_deletion_attempt WHERE nonce = ?)
      ORDER BY v.path, v.from_generation LIMIT ?`,
    remaining: `SELECT 1 FROM space_record_version v WHERE v.epoch_id =
      (SELECT epoch_id FROM space_personal_deletion_job WHERE nonce = ?) LIMIT 1`,
    remove: `DELETE FROM space_record_version NOT INDEXED WHERE rowid IN (
      SELECT row_id FROM space_personal_deletion_candidate WHERE attempt_nonce = ?
    ) AND space_ref = ? AND repo_did = ? AND epoch_id =
      (SELECT epoch_id FROM space_personal_deletion_attempt WHERE nonce = ?)`,
  },
  ops: {
    scan:
      `SELECT o.rowid AS row_id, 0 AS byte_size FROM space_op o INDEXED BY sqlite_autoindex_space_op_1
      WHERE o.space_ref = ? AND o.repo_did = ? ORDER BY o.rev, o.ordinal LIMIT ?`,
    remaining:
      "SELECT 1 FROM space_op WHERE space_ref = ? AND repo_did = ? LIMIT 1",
    remove: `DELETE FROM space_op NOT INDEXED WHERE rowid IN (
      SELECT row_id FROM space_personal_deletion_candidate WHERE attempt_nonce = ?
    ) AND space_ref = ? AND repo_did = ?`,
  },
};

function cleanupCandidatePage(scan: string): string {
  return `WITH candidates AS MATERIALIZED (${scan}), numbered AS MATERIALIZED (
    SELECT row_id, byte_size, ROW_NUMBER() OVER (ORDER BY row_id) AS ordinal FROM candidates
  ), sized AS (
    SELECT row_id, byte_size,
      SUM(CASE WHEN byte_size BETWEEN 0 AND 1048576 THEN byte_size ELSE 0 END) OVER (ORDER BY ordinal) AS total,
      SUM(CASE WHEN byte_size BETWEEN 0 AND 1048576 THEN 0 ELSE 1 END) OVER (ORDER BY ordinal) AS invalid
    FROM numbered
  )`;
}

export function insertCleanupCandidates(scan: string): string {
  return `${
    cleanupCandidatePage(scan)
  } INSERT INTO space_personal_deletion_candidate (attempt_nonce, row_id, byte_size)
    SELECT ?, row_id, byte_size FROM sized WHERE invalid = 0 AND total <= 4194304`;
}

export function assertCleanupCandidates(scan: string): string {
  return `${cleanupCandidatePage(scan)} SELECT CASE WHEN
    changes() = (SELECT COUNT(*) FROM sized WHERE invalid = 0 AND total <= 4194304)
    AND changes() = (SELECT COUNT(*) FROM space_personal_deletion_candidate WHERE attempt_nonce = ?)
    AND NOT EXISTS (
      SELECT row_id, byte_size FROM sized WHERE invalid = 0 AND total <= 4194304
      EXCEPT SELECT row_id, byte_size FROM space_personal_deletion_candidate WHERE attempt_nonce = ?
    )
    AND NOT EXISTS (
      SELECT row_id, byte_size FROM space_personal_deletion_candidate WHERE attempt_nonce = ?
      EXCEPT SELECT row_id, byte_size FROM sized WHERE invalid = 0 AND total <= 4194304
    )
    THEN 1 ELSE json('{') END AS valid`;
}
