import { SPACE_GENESIS_EMPTY } from './space-genesis-sql';
import { authorizationSql } from './space-read-auth';

/** Select bounded candidates before joining or projecting their metadata. */
export function ownerSpacePageSql(hasCursor: boolean): string {
  return `${authorizationSql('nonce')}, candidates AS MATERIALIZED (
    SELECT l.space_ref FROM space_owner_listing l INDEXED BY space_owner_listing_owner_type
    WHERE l.authority_did = CASE WHEN EXISTS (SELECT 1 FROM authorized) THEN ? END
      AND l.authority_incarnation = ? AND l.space_type = ?
      ${hasCursor ? 'AND l.space_ref > ? COLLATE BINARY' : ''}
      AND CASE WHEN EXISTS (SELECT 1 FROM authorized) THEN NOT EXISTS (
        SELECT 1 FROM space_owner_quarantine_global global_quarantine WHERE global_quarantine.id = 1) AND NOT EXISTS (
        SELECT 1 FROM space_owner_unclassified q INDEXED BY space_owner_unclassified_authority_type
        WHERE q.authority_did = '') AND NOT EXISTS (
        SELECT 1 FROM space_owner_unclassified q INDEXED BY space_owner_unclassified_authority_type
        WHERE q.authority_did = ? AND q.space_type IN ('', ?)) ELSE 0 END
    ORDER BY l.space_ref COLLATE BINARY ASC LIMIT ?
  ), targets AS MATERIALIZED (
    SELECT l.space_ref, l.authority_did AS repo_did,
      l.authority_did, l.authority_incarnation, l.space_type, l.creation_nonce
    FROM candidates c CROSS JOIN space_owner_listing l WHERE l.space_ref = c.space_ref COLLATE BINARY
  ), page AS MATERIALIZED (
    SELECT CASE WHEN typeof(t.space_ref) = 'text' AND length(CAST(t.space_ref AS BLOB)) BETWEEN 1 AND 8192
        THEN t.space_ref END AS space_ref,
      CASE WHEN typeof(t.creation_nonce) = 'text' AND length(CAST(t.creation_nonce AS BLOB)) = 36
        THEN t.creation_nonce END AS creation_nonce,
      CASE WHEN typeof(p.created_at) = 'integer' AND p.created_at BETWEEN 0 AND 9007199254740991
        THEN p.created_at END AS created_at,
      CASE WHEN typeof(s.authority_did) = 'text' AND length(CAST(s.authority_did AS BLOB)) BETWEEN 1 AND 2048
        AND typeof(s.space_type) = 'text' AND length(CAST(s.space_type AS BLOB)) BETWEEN 5 AND 317
        AND typeof(s.skey) = 'text' AND length(CAST(s.skey AS BLOB)) BETWEEN 1 AND 512
        AND typeof(s.space_ref) = 'text' AND length(CAST(s.space_ref AS BLOB)) BETWEEN 1 AND 8192
        AND typeof(s.created_at) = 'integer' AND s.created_at BETWEEN 0 AND 9007199254740991
        AND typeof(p.created_at) = 'integer' AND p.created_at = s.created_at
        AND typeof(p.creation_nonce) = 'text' AND length(CAST(p.creation_nonce AS BLOB)) = 36
        AND typeof(p.authority_incarnation) = 'text' AND length(CAST(p.authority_incarnation AS BLOB)) = 32
        THEN CASE WHEN s.space_ref = 'at://' || s.authority_did || '/space/' || s.space_type || '/' || s.skey
          AND s.authority_did = t.authority_did AND s.space_type = t.space_type AND s.deleted_at IS NULL
          AND p.authority_did = t.authority_did AND p.authority_incarnation = t.authority_incarnation
          AND p.creation_nonce = t.creation_nonce AND p.policy_type = 'com.atproto.personalspace.policy'
          AND p.notification_state = 'none'
          AND NOT EXISTS (SELECT 1 FROM space_owner_unclassified q WHERE q.space_ref = s.space_ref COLLATE BINARY)
          THEN 1 ELSE 0 END ELSE 0 END AS valid,
      CASE WHEN h.space_ref IS NULL THEN CASE WHEN ${SPACE_GENESIS_EMPTY} THEN 0 ELSE 2 END
        WHEN e.id IS NOT NULL AND typeof(h.rev) = 'text' AND length(CAST(h.rev AS BLOB)) = 13
          AND typeof(h.set_hash) = 'blob' AND length(h.set_hash) = 2048
          AND typeof(h.generation) = 'integer' AND h.generation BETWEEN 1 AND 9007199254740991
          AND typeof(h.mutation_id) = 'text' AND length(CAST(h.mutation_id AS BLOB)) BETWEEN 1 AND 128
          AND typeof(e.id) = 'text' AND length(CAST(e.id AS BLOB)) BETWEEN 1 AND 128
          THEN 1 ELSE 2 END AS repo_status,
      CASE WHEN typeof(h.rev) = 'text' AND length(CAST(h.rev AS BLOB)) = 13 THEN h.rev END AS repo_rev,
      CASE WHEN typeof(h.set_hash) = 'blob' AND length(h.set_hash) = 2048 THEN h.set_hash END AS set_hash,
      CASE WHEN typeof(h.generation) = 'integer' AND h.generation BETWEEN 1 AND 9007199254740991
        THEN h.generation END AS generation,
      CASE WHEN typeof(h.mutation_id) = 'text' AND length(CAST(h.mutation_id AS BLOB)) BETWEEN 1 AND 128
        THEN h.mutation_id END AS mutation_id,
      CASE WHEN typeof(e.id) = 'text' AND length(CAST(e.id AS BLOB)) BETWEEN 1 AND 128 THEN e.id END AS epoch_id,
      0 AS sentinel, NULL AS session_expires_at, NULL AS quarantined
    FROM targets t LEFT JOIN space s ON s.space_ref = t.space_ref
    LEFT JOIN space_personal_policy p ON p.space_ref = t.space_ref
    LEFT JOIN space_repo h ON h.space_ref = t.space_ref AND h.repo_did = t.repo_did
    LEFT JOIN space_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
      AND e.repo_did = h.repo_did AND e.state = 'active' AND e.owner_incarnation = t.authority_incarnation
  ) SELECT * FROM page
  UNION ALL SELECT NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, 1,
    session_expires_at, CASE WHEN EXISTS (SELECT 1 FROM space_owner_quarantine_global global_quarantine
      WHERE global_quarantine.id = 1) OR EXISTS (SELECT 1 FROM space_owner_unclassified q
      INDEXED BY space_owner_unclassified_authority_type WHERE q.authority_did = '') OR EXISTS (
      SELECT 1 FROM space_owner_unclassified q INDEXED BY space_owner_unclassified_authority_type
      WHERE q.authority_did = CASE WHEN authorized.session_expires_at IS NOT NULL THEN ? END
        AND q.space_type IN ('', ?)) THEN 1 ELSE 0 END FROM authorized`;
}
