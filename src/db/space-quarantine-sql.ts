const MAX_SAFE = 9007199254740991;

const boundedText = (column: string, maximum: number, minimum = 1) =>
  `typeof(${column}) = 'text' AND length(CAST(${column} AS BLOB)) BETWEEN ${minimum} AND ${maximum}`;
const boundedField = (column: string, maximum: number) =>
  `CASE WHEN ${boundedText(column, maximum)} THEN ${column} END`;

// The same projection is used inside checkpoint and activation transactions.
export const QUARANTINE_JOB_COLUMNS = `j.id, j.token, j.renewal_nonce, j.space_ref, j.repo_did, j.epoch_id,
  j.generation, j.rev, j.cursor, j.sequence, j.record_count, j.expected_hash, j.accumulated_hash,
  j.status, j.failure_reason, j.activation_nonce`;
export const VALID_QUARANTINE_JOB_SQL = `
  ${boundedText('j.id', 36, 36)} AND ${boundedText('j.token', 36, 36)} AND ${boundedText('j.renewal_nonce', 36, 36)}
  AND ${boundedText('j.space_ref', 8192)} AND ${boundedText('j.repo_did', 2048)} AND ${boundedText('j.epoch_id', 128)}
  AND ${boundedText('j.rev', 13, 13)} AND ${boundedText('j.cursor', 830, 0)}
  AND typeof(j.generation) = 'integer' AND j.generation BETWEEN 1 AND ${MAX_SAFE}
  AND typeof(j.sequence) = 'integer' AND j.sequence BETWEEN 0 AND ${MAX_SAFE - 1}
  AND typeof(j.record_count) = 'integer' AND j.record_count BETWEEN 0 AND ${MAX_SAFE - 1}
  AND typeof(j.lease_until) = 'integer'
  AND typeof(j.expected_hash) = 'blob' AND length(j.expected_hash) = 2048
  AND typeof(j.accumulated_hash) = 'blob' AND length(j.accumulated_hash) = 2048
  AND j.status IN ('running', 'complete', 'activating', 'active', 'failed')
  AND (j.failure_reason IS NULL OR j.failure_reason IN ('invalid', 'unsupported'))
  AND (j.activation_nonce IS NULL OR (${boundedText('j.activation_nonce', 36, 36)}))`;

export const PINNED_QUARANTINE_JOB = `SELECT ${QUARANTINE_JOB_COLUMNS} FROM space_quarantine_job j
  JOIN space_repo h ON h.space_ref = j.space_ref AND h.repo_did = j.repo_did
    AND h.active_epoch_id = j.epoch_id AND h.generation = j.generation
    AND h.mutation_id = j.mutation_id AND h.rev = j.rev AND h.set_hash = j.expected_hash
  JOIN space_epoch e ON e.id = j.epoch_id AND e.space_ref = j.space_ref
    AND e.repo_did = j.repo_did AND e.state = 'quarantined'
  JOIN space s ON s.space_ref = j.space_ref AND s.deleted_at IS NULL
    AND s.authority_did = j.authority_did AND s.space_type = j.space_type AND s.skey = j.skey
  WHERE j.id = ? AND j.token = ? AND j.renewal_nonce = ? AND j.space_ref = ? AND j.repo_did = ?
    AND j.lease_until > unixepoch() AND ${VALID_QUARANTINE_JOB_SQL}`;

export const LIVE_QUARANTINE_JOB = `${PINNED_QUARANTINE_JOB} AND j.status = 'running'`;
const PAGE_QUARANTINE_JOB = `${LIVE_QUARANTINE_JOB}
  AND j.cursor = ? AND j.sequence = ? AND j.accumulated_hash = ? AND j.record_count = ?`;

export const COMPLETE_QUARANTINE_CURSOR = `SELECT CASE WHEN ${boundedText('cursor', 830, 0)} THEN cursor END AS cursor
  FROM space_quarantine_job WHERE id = ? AND token = ? AND space_ref = ? AND repo_did = ?
    AND status = 'complete' AND lease_until > unixepoch()`;

export const COMPLETE_QUARANTINE_RESULT = `SELECT ${QUARANTINE_JOB_COLUMNS} FROM space_quarantine_job j
  JOIN space_repo h ON h.space_ref = j.space_ref AND h.repo_did = j.repo_did
    AND h.active_epoch_id = j.epoch_id AND h.generation = j.generation
    AND h.mutation_id = j.mutation_id AND h.rev = j.rev AND h.set_hash = j.expected_hash
  JOIN space_epoch e ON e.id = j.epoch_id AND e.space_ref = j.space_ref
    AND e.repo_did = j.repo_did AND e.state = 'quarantined'
  JOIN space s ON s.space_ref = j.space_ref AND s.deleted_at IS NULL
    AND s.authority_did = j.authority_did AND s.space_type = j.space_type AND s.skey = j.skey
  WHERE j.id = ? AND j.token = ? AND j.space_ref = ? AND j.repo_did = ?
    AND j.cursor = ?
    AND ${VALID_QUARANTINE_JOB_SQL}
    AND j.status = 'complete' AND j.failure_reason IS NULL AND j.lease_until > unixepoch()
    AND j.expected_hash = j.accumulated_hash
    AND NOT EXISTS (SELECT 1 FROM space_blob_usage b WHERE b.space_ref = j.space_ref AND b.repo_did = j.repo_did)
    AND NOT EXISTS (SELECT 1 FROM space_record_version v WHERE v.epoch_id = j.epoch_id
      AND v.path COLLATE BINARY > ? COLLATE BINARY)
    AND NOT EXISTS (SELECT 1 FROM space_record r WHERE r.space_ref = j.space_ref AND r.repo_did = j.repo_did
      AND (r.collection || '/' || r.rkey) COLLATE BINARY > ? COLLATE BINARY)`;

export const FAILED_QUARANTINE_RESULT = `SELECT failure_reason FROM space_quarantine_job
  WHERE id = ? AND token = ? AND space_ref = ? AND repo_did = ? AND status = 'failed'
    AND failure_reason IN ('invalid', 'unsupported')`;

const validVersion = `${boundedText('v.path', 830)} AND ${boundedText('v.collection', 317)}
  AND ${boundedText('v.rkey', 512)} AND ${boundedText('v.cid', 128)} AND ${boundedText('v.repo_rev', 13, 13)}
  AND ${boundedText('v.space_ref', 8192)} AND ${boundedText('v.repo_did', 2048)}
  AND typeof(v.from_generation) = 'integer' AND v.from_generation BETWEEN 1 AND ${MAX_SAFE}
  AND (v.until_generation IS NULL OR (typeof(v.until_generation) = 'integer' AND v.until_generation BETWEEN 1 AND ${MAX_SAFE}))
  AND typeof(v.value_size) = 'integer' AND v.value_size BETWEEN 1 AND 1048576`;

// Select the indexed raw key first. Invalid projections remain data rows, not EOF.
export const QUARANTINE_VERSION_PAGE = `WITH live AS (${PAGE_QUARANTINE_JOB}), candidate AS MATERIALIZED (
  SELECT v.rowid AS row_id FROM space_record_version v JOIN live j ON v.epoch_id = j.epoch_id
  WHERE v.path COLLATE BINARY > ? COLLATE BINARY
  ORDER BY v.path COLLATE BINARY, v.from_generation LIMIT 1
)
SELECT ${boundedField('v.path', 830)} AS path, ${boundedField('v.collection', 317)} AS collection,
  ${boundedField('v.rkey', 512)} AS rkey, ${boundedField('v.cid', 128)} AS cid,
  ${boundedField('v.repo_rev', 13)} AS repo_rev,
  CASE WHEN typeof(v.from_generation) = 'integer' AND v.from_generation BETWEEN 1 AND ${MAX_SAFE} THEN v.from_generation END AS from_generation,
  CASE WHEN typeof(v.until_generation) = 'integer' AND v.until_generation BETWEEN 1 AND ${MAX_SAFE} THEN v.until_generation END AS until_generation,
  ${boundedField('v.space_ref', 8192)} AS space_ref, ${boundedField('v.repo_did', 2048)} AS repo_did,
  CASE WHEN typeof(v.value_size) = 'integer' AND v.value_size BETWEEN 1 AND 1048576 THEN v.value_size END AS value_size,
  CASE WHEN typeof(v.value_cbor) = 'blob' THEN length(v.value_cbor) END AS actual_size, typeof(v.value_cbor) AS value_type,
  EXISTS (SELECT 1 FROM space_record_version x WHERE x.epoch_id = v.epoch_id AND x.path = v.path
    AND x.from_generation != v.from_generation) AS duplicate,
  CASE WHEN ${validVersion} THEN 1 ELSE 0 END AS valid, 0 AS sentinel
FROM candidate c JOIN space_record_version v ON v.rowid = c.row_id
UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1, 1 FROM live`;

const validCurrent = `${boundedText('r.collection', 317)} AND ${boundedText('r.rkey', 512)}
  AND ${boundedText('r.cid', 128)} AND ${boundedText('r.repo_rev', 13, 13)}`;
export const QUARANTINE_CURRENT_PAGE = `WITH live AS (${PAGE_QUARANTINE_JOB}), candidate AS MATERIALIZED (
  SELECT r.rowid AS row_id FROM space_record r JOIN live j ON r.space_ref = j.space_ref AND r.repo_did = j.repo_did
  WHERE (r.collection || '/' || r.rkey) COLLATE BINARY > ? COLLATE BINARY
  ORDER BY (r.collection || '/' || r.rkey) COLLATE BINARY LIMIT 1
)
SELECT CASE WHEN ${boundedText('r.collection', 317)} AND ${boundedText('r.rkey', 512)}
    THEN r.collection || '/' || r.rkey END AS path,
  ${boundedField('r.collection', 317)} AS collection, ${boundedField('r.rkey', 512)} AS rkey,
  ${boundedField('r.cid', 128)} AS cid, ${boundedField('r.repo_rev', 13)} AS repo_rev,
  CASE WHEN typeof(r.value_cbor) = 'blob' THEN length(r.value_cbor) END AS actual_size, typeof(r.value_cbor) AS value_type,
  CASE WHEN ${validCurrent} THEN 1 ELSE 0 END AS valid, 0 AS sentinel
FROM candidate c JOIN space_record r ON r.rowid = c.row_id
UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1, 1 FROM live`;

export const QUARANTINE_RECORD_BYTES = `WITH live AS (${LIVE_QUARANTINE_JOB})
SELECT v.value_cbor FROM live j
JOIN space_record_version v ON v.epoch_id = j.epoch_id AND v.space_ref = j.space_ref AND v.repo_did = j.repo_did
JOIN space_record r ON r.space_ref = v.space_ref AND r.repo_did = v.repo_did
  AND r.collection = v.collection AND r.rkey = v.rkey AND r.cid = v.cid AND r.repo_rev = v.repo_rev
  AND r.value_cbor IS v.value_cbor
WHERE j.sequence = ? AND j.cursor = ? AND j.accumulated_hash = ?
  AND v.path = ? AND v.cid = ? AND v.repo_rev = ? AND v.from_generation = ? AND v.until_generation IS NULL
  AND v.value_size = ? AND v.value_size = length(v.value_cbor) AND v.value_size = length(r.value_cbor)
  AND typeof(v.value_cbor) = 'blob' AND typeof(r.value_cbor) = 'blob' AND v.value_size > 0 AND v.value_size <= 1048576
UNION ALL SELECT NULL FROM live j WHERE j.sequence = ? AND j.cursor = ? AND j.accumulated_hash = ?`;
