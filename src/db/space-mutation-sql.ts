export const GUARD = `EXISTS (
  SELECT 1 FROM space_repo
  WHERE space_ref = ? AND repo_did = ? AND generation = ? AND mutation_id = ? AND active_epoch_id = ?
    AND rev = ? AND set_hash = ?
)`;

export const WON_GUARD = `(${GUARD} AND EXISTS (
  SELECT 1 FROM space_commit_assertion WHERE mutation_id = ?
))`;

export const EFFECT_GUARD = `(${WON_GUARD} AND EXISTS (
  SELECT 1 FROM space_epoch e WHERE e.id = ? AND e.space_ref = ? AND e.repo_did = ? AND e.state = 'active'
))`;

export const RECORDS_MATCH = `NOT EXISTS (
  SELECT 1 FROM json_each(?) requested
  LEFT JOIN space_record r ON r.space_ref = ? AND r.repo_did = ?
    AND r.collection = json_extract(requested.value, '$.collection') AND r.rkey = json_extract(requested.value, '$.rkey')
  LEFT JOIN space_record_version v ON v.epoch_id = ? AND v.space_ref = ? AND v.repo_did = ?
    AND v.path = json_extract(requested.value, '$.path') AND v.until_generation IS NULL
  WHERE r.cid IS NOT json_extract(requested.value, '$.cid')
    OR v.cid IS NOT json_extract(requested.value, '$.cid')
    OR v.from_generation IS NOT json_extract(requested.value, '$.fromGeneration')
    OR (r.cid IS NOT NULL AND (r.value_cbor IS NOT v.value_cbor OR r.repo_rev IS NOT v.repo_rev))
)`;

export const SPACE_AVAILABLE = `(
  EXISTS (SELECT 1 FROM space WHERE space_ref = ? AND deleted_at IS NULL)
  OR (? <> ? AND NOT EXISTS (SELECT 1 FROM space WHERE space_ref = ?))
)`;
