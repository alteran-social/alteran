import { MAX_RECORD_SIZE } from '@atproto/space';
import { MAX_SPACE_MUTATION_SNAPSHOT_BYTES } from './space-mutation-snapshot-sql';

export const GUARD = `EXISTS (
  SELECT 1 FROM space_repo
  WHERE space_ref = ? AND repo_did = ? AND generation = ? AND mutation_id = ? AND active_epoch_id = ?
    AND rev = ? AND set_hash = ?
    AND EXISTS (SELECT 1 FROM space_mutation_attempt a JOIN account owner ON owner.did = a.repo_did
      AND owner.space_incarnation = a.owner_incarnation JOIN account_state state ON state.did = owner.did
      WHERE a.mutation_id = space_repo.mutation_id AND a.space_ref = space_repo.space_ref AND a.repo_did = space_repo.repo_did
        AND typeof(state.active) = 'integer' AND state.active = 1 AND state.status IS NULL AND state.suspended_until IS NULL)
)`;

export const WON_GUARD = `(${GUARD} AND EXISTS (
  SELECT 1 FROM space_commit_assertion WHERE mutation_id = ?
))`;

export const EFFECT_GUARD = `(${WON_GUARD} AND EXISTS (
  SELECT 1 FROM space_owned_epoch e WHERE e.id = ? AND e.space_ref = ? AND e.repo_did = ? AND e.state = 'active'
))`;

// A foreign Space row may be installed after its first local epoch is created.
export const BOOTSTRAP_GUARD = `(${WON_GUARD} AND EXISTS (
  SELECT 1 FROM space_epoch e JOIN account owner ON owner.did = e.repo_did
    AND owner.space_incarnation = e.owner_incarnation JOIN account_state state ON state.did = owner.did
  WHERE e.id = ? AND e.space_ref = ? AND e.repo_did = ? AND e.state = 'active'
    AND typeof(state.active) = 'integer' AND state.active = 1 AND state.status IS NULL AND state.suspended_until IS NULL
))`;

export const RECORDS_MATCH = `NOT EXISTS (
  WITH requested AS MATERIALIZED (
    SELECT json_extract(value, '$.path') AS path, json_extract(value, '$.collection') AS collection,
      json_extract(value, '$.rkey') AS rkey, json_extract(value, '$.cid') AS cid,
      json_extract(value, '$.fromGeneration') AS from_generation, json_extract(value, '$.repoRev') AS repo_rev FROM json_each(?)
  ), target AS MATERIALIZED (SELECT ? AS space_ref, ? AS repo_did, ? AS epoch_id, ? AS version_space, ? AS version_repo),
  budget AS MATERIALIZED (
    SELECT COALESCE(SUM(CASE WHEN typeof(r.value_cbor) = 'blob' AND length(r.value_cbor) <= ${MAX_RECORD_SIZE}
      THEN length(r.value_cbor) ELSE 0 END), 0) AS bytes
    FROM requested p CROSS JOIN target t LEFT JOIN space_record r ON r.space_ref = t.space_ref AND r.repo_did = t.repo_did
      AND r.collection = p.collection AND r.rkey = p.rkey
  )
  SELECT 1 FROM requested p CROSS JOIN target t CROSS JOIN budget
  LEFT JOIN space_record r ON r.space_ref = t.space_ref AND r.repo_did = t.repo_did
    AND r.collection = p.collection AND r.rkey = p.rkey
  LEFT JOIN space_record_version v ON v.epoch_id = t.epoch_id AND v.space_ref = t.version_space AND v.repo_did = t.version_repo
    AND v.path = p.path AND v.until_generation IS NULL
  WHERE CASE WHEN budget.bytes > ${MAX_SPACE_MUTATION_SNAPSHOT_BYTES} THEN 1
    WHEN p.cid IS NULL AND (r.rowid IS NOT NULL OR v.rowid IS NOT NULL) THEN 1
    WHEN p.cid IS NOT NULL AND (r.rowid IS NULL OR v.rowid IS NULL) THEN 1
    WHEN r.rowid IS NULL THEN 0
    WHEN typeof(r.cid) <> 'text' OR typeof(v.cid) <> 'text'
      OR length(CAST(r.cid AS BLOB)) NOT BETWEEN 1 AND 128 OR length(CAST(v.cid AS BLOB)) NOT BETWEEN 1 AND 128
      OR typeof(r.value_cbor) <> 'blob' OR length(r.value_cbor) NOT BETWEEN 1 AND ${MAX_RECORD_SIZE}
      OR typeof(v.value_cbor) <> 'blob' OR length(v.value_cbor) NOT BETWEEN 1 AND ${MAX_RECORD_SIZE}
      OR typeof(v.value_size) <> 'integer' OR v.value_size <> length(v.value_cbor)
      OR typeof(r.repo_rev) <> 'text' OR length(CAST(r.repo_rev AS BLOB)) <> 13
      OR typeof(v.repo_rev) <> 'text' OR length(CAST(v.repo_rev AS BLOB)) <> 13 THEN 1
    WHEN r.cid IS NOT p.cid OR v.cid IS NOT p.cid OR v.from_generation IS NOT p.from_generation
      OR r.value_cbor IS NOT v.value_cbor OR r.repo_rev IS NOT p.repo_rev OR v.repo_rev IS NOT p.repo_rev THEN 1
    ELSE 0 END = 1
)`;

export const SPACE_AVAILABLE = `(
  EXISTS (SELECT 1 FROM space WHERE space_ref = ? AND deleted_at IS NULL)
  OR (? <> ? AND NOT EXISTS (SELECT 1 FROM space WHERE space_ref = ?))
)`;
