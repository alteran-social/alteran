import { MAX_RECORD_SIZE } from '@atproto/space';

/** Maximum existing record bytes compared for a single mutation. */
export const MAX_SPACE_MUTATION_SNAPSHOT_BYTES = 4 * 1024 * 1024;

export const SPACE_MUTATION_SNAPSHOT_SQL = `WITH requested AS MATERIALIZED (
  SELECT json_extract(value, '$[0]') AS collection, json_extract(value, '$[1]') AS rkey FROM json_each(?)
), target AS MATERIALIZED (SELECT ? AS space_ref, ? AS repo_did), budget AS MATERIALIZED (
  SELECT COALESCE(SUM(CASE WHEN typeof(r.value_cbor) = 'blob' AND length(r.value_cbor) <= ${MAX_RECORD_SIZE}
    THEN length(r.value_cbor) ELSE 0 END), 0) AS bytes
  FROM requested p CROSS JOIN target t LEFT JOIN space_record r ON r.space_ref = t.space_ref AND r.repo_did = t.repo_did
    AND r.collection = p.collection AND r.rkey = p.rkey
)
SELECT path.collection, path.rkey, (budget.bytes > ${MAX_SPACE_MUTATION_SNAPSHOT_BYTES}) AS over_budget,
  CASE WHEN typeof(r.cid) = 'text' AND length(CAST(r.cid AS BLOB)) BETWEEN 1 AND 128 THEN r.cid END AS cid,
  CASE WHEN typeof(v.cid) = 'text' AND length(CAST(v.cid AS BLOB)) BETWEEN 1 AND 128 THEN v.cid END AS version_cid,
  CASE WHEN typeof(v.from_generation) = 'integer' AND v.from_generation BETWEEN 1 AND 9007199254740991
    THEN v.from_generation END AS from_generation,
  CASE WHEN typeof(r.repo_rev) = 'text' AND length(CAST(r.repo_rev AS BLOB)) = 13 THEN r.repo_rev END AS record_rev,
  CASE WHEN budget.bytes <= ${MAX_SPACE_MUTATION_SNAPSHOT_BYTES} AND typeof(r.value_cbor) = 'blob'
    AND length(r.value_cbor) BETWEEN 1 AND ${MAX_RECORD_SIZE} THEN r.value_cbor END AS value_cbor,
  CASE WHEN budget.bytes > ${MAX_SPACE_MUTATION_SNAPSHOT_BYTES} THEN 0
    WHEN r.rowid IS NULL AND v.rowid IS NULL THEN 1
    WHEN r.rowid IS NULL OR v.rowid IS NULL OR typeof(r.cid) <> 'text' OR typeof(v.cid) <> 'text'
      OR length(CAST(r.cid AS BLOB)) NOT BETWEEN 1 AND 128 OR length(CAST(v.cid AS BLOB)) NOT BETWEEN 1 AND 128
      OR typeof(r.value_cbor) <> 'blob' OR length(r.value_cbor) NOT BETWEEN 1 AND ${MAX_RECORD_SIZE}
      OR typeof(v.value_cbor) <> 'blob' OR length(v.value_cbor) NOT BETWEEN 1 AND ${MAX_RECORD_SIZE}
      OR typeof(v.value_size) <> 'integer' OR v.value_size <> length(v.value_cbor)
      OR typeof(r.repo_rev) <> 'text' OR length(CAST(r.repo_rev AS BLOB)) <> 13
      OR typeof(v.repo_rev) <> 'text' OR length(CAST(v.repo_rev AS BLOB)) <> 13
      OR typeof(h.rev) <> 'text' OR length(CAST(h.rev AS BLOB)) <> 13
      OR typeof(h.generation) <> 'integer' OR h.generation NOT BETWEEN 1 AND 9007199254740991
      OR typeof(v.from_generation) <> 'integer' OR v.from_generation NOT BETWEEN 1 AND h.generation THEN 0
    WHEN r.cid IS v.cid AND r.value_cbor IS v.value_cbor AND r.repo_rev IS v.repo_rev AND r.repo_rev <= h.rev
      THEN 1 ELSE 0 END AS consistent
FROM requested path CROSS JOIN target t CROSS JOIN budget
LEFT JOIN space_record r ON r.space_ref = t.space_ref AND r.repo_did = t.repo_did
  AND r.collection = path.collection AND r.rkey = path.rkey
LEFT JOIN space_repo h ON h.space_ref = t.space_ref AND h.repo_did = t.repo_did
LEFT JOIN space_record_version v ON v.epoch_id = h.active_epoch_id AND v.space_ref = h.space_ref
  AND v.repo_did = h.repo_did AND v.path = path.collection || '/' || path.rkey AND v.until_generation IS NULL`;
