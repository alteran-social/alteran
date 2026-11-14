import { MAX_RECORD_SIZE } from '@atproto/space';
import { SPACE_GENESIS_EMPTY } from './space-genesis-sql';

/** Maximum existing record bytes compared for a single mutation. */
export const MAX_SPACE_MUTATION_SNAPSHOT_BYTES = 4 * 1024 * 1024;

export const SPACE_MUTATION_SNAPSHOT_SQL = `WITH requested AS MATERIALIZED (
  SELECT json_extract(value, '$[0]') AS collection, json_extract(value, '$[1]') AS rkey FROM json_each(?)
), input AS MATERIALIZED (SELECT ? AS space_ref, ? AS repo_did, ? AS owner_incarnation),
target AS MATERIALIZED (
  SELECT t.* FROM input t JOIN account a ON a.did = t.repo_did AND a.space_incarnation = t.owner_incarnation
  JOIN account_state state ON state.did = a.did AND typeof(state.active) = 'integer' AND state.active = 1
    AND state.status IS NULL AND state.suspended_until IS NULL
  WHERE EXISTS (SELECT 1 FROM space_repo h JOIN space_owned_epoch e ON e.id = h.active_epoch_id
      AND e.space_ref = h.space_ref AND e.repo_did = h.repo_did AND e.state = 'active'
    JOIN space s ON s.space_ref = h.space_ref AND s.deleted_at IS NULL
    WHERE h.space_ref = t.space_ref AND h.repo_did = t.repo_did AND e.owner_incarnation = t.owner_incarnation)
    OR ((${SPACE_GENESIS_EMPTY}) AND NOT EXISTS (SELECT 1 FROM space s WHERE s.space_ref = t.space_ref
      AND (s.deleted_at IS NOT NULL OR s.space_ref != 'at://' || s.authority_did || '/space/' || s.space_type || '/' || s.skey
        OR (s.authority_did = t.repo_did AND NOT EXISTS (SELECT 1 FROM space_personal_policy p
          WHERE p.space_ref = s.space_ref AND p.authority_did = t.repo_did AND p.authority_incarnation = t.owner_incarnation)))))
), budget AS MATERIALIZED (
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
