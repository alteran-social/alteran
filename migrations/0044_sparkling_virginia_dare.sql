SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM space NOT INDEXED LIMIT 1 OFFSET 4096)
  AND NOT EXISTS (SELECT 1 FROM space_personal_policy NOT INDEXED LIMIT 1 OFFSET 4096)
  THEN 1 ELSE json('{') END;
--> statement-breakpoint
SELECT CASE WHEN
  (SELECT COALESCE(SUM(
    MIN(COALESCE(length(CAST(space_ref AS BLOB)), 0), 8193)
    + MIN(COALESCE(length(CAST(authority_did AS BLOB)), 0), 2049)
    + MIN(COALESCE(length(CAST(space_type AS BLOB)), 0), 318)
    + MIN(COALESCE(length(CAST(skey AS BLOB)), 0), 513)), 0) FROM space NOT INDEXED)
  + (SELECT COALESCE(SUM(
    MIN(COALESCE(length(CAST(space_ref AS BLOB)), 0), 8193)
    + MIN(COALESCE(length(CAST(authority_did AS BLOB)), 0), 2049)
    + MIN(COALESCE(length(CAST(authority_incarnation AS BLOB)), 0), 33)
    + MIN(COALESCE(length(CAST(policy_type AS BLOB)), 0), 129)
    + MIN(COALESCE(length(CAST(creation_nonce AS BLOB)), 0), 37)
    + MIN(COALESCE(length(CAST(notification_state AS BLOB)), 0), 17)), 0) FROM space_personal_policy NOT INDEXED)
  <= 16777216 THEN 1 ELSE json('{') END;
--> statement-breakpoint
SELECT CASE WHEN (SELECT COALESCE(SUM(CASE WHEN typeof(authority_did) = 'text'
  AND length(CAST(authority_did AS BLOB)) BETWEEN 7 AND 2048
  THEN length(CAST(authority_did AS BLOB)) * (length(authority_did) - length(replace(authority_did, '%', '')))
  ELSE 0 END), 0) FROM space NOT INDEXED) <= 8388608 THEN 1 ELSE json('{') END;
--> statement-breakpoint
SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM space_personal_policy p
  WHERE NOT EXISTS (SELECT 1 FROM space s WHERE s.space_ref = p.space_ref))
  AND NOT EXISTS (SELECT 1 FROM space s WHERE s.deleted_at IS NOT NULL
    AND (typeof(s.deleted_at) != 'integer' OR s.deleted_at NOT BETWEEN 0 AND 9007199254740991))
  THEN 1 ELSE json('{') END;
--> statement-breakpoint
CREATE TABLE `space_owner_listing` (
	`space_ref` text PRIMARY KEY NOT NULL,
	`authority_did` text NOT NULL,
	`authority_incarnation` text NOT NULL,
	`space_type` text NOT NULL,
	`creation_nonce` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `space_owner_listing_owner_type` ON `space_owner_listing` (`authority_did`,`authority_incarnation`,`space_type`,`space_ref`);--> statement-breakpoint
CREATE TABLE `space_owner_quarantine_global` (
	`id` integer PRIMARY KEY NOT NULL,
	CONSTRAINT "space_owner_quarantine_global_singleton" CHECK("space_owner_quarantine_global"."id" = 1)
);
--> statement-breakpoint
CREATE TABLE `space_owner_unclassified` (
	`space_ref` text PRIMARY KEY NOT NULL,
	`authority_did` text NOT NULL,
	`space_type` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `space_owner_unclassified_authority_type` ON `space_owner_unclassified` (`authority_did`,`space_type`,`space_ref`);
--> statement-breakpoint
CREATE VIEW space_owner_classification AS
WITH normalized AS (
  SELECT s.space_ref, s.authority_did, s.space_type, s.skey, s.created_at,
    CASE WHEN typeof(s.authority_did) = 'text'
      AND length(CAST(s.authority_did AS BLOB)) BETWEEN 7 AND 2048
      AND length(s.authority_did) = length(CAST(s.authority_did AS BLOB))
      THEN CASE WHEN s.authority_did NOT GLOB '*[^a-zA-Z0-9._:%-]*'
      AND substr(s.authority_did, 1, 4) = 'did:' AND instr(substr(s.authority_did, 5), ':') > 1
      AND substr(s.authority_did, 5, instr(substr(s.authority_did, 5), ':') - 1) NOT GLOB '*[^a-z]*'
      AND length(substr(s.authority_did, 5 + instr(substr(s.authority_did, 5), ':'))) >= 1
      AND substr(s.authority_did, -1) GLOB '[a-zA-Z0-9._-]'
      AND NOT EXISTS (WITH RECURSIVE percent(part) AS (
        SELECT substr(s.authority_did, instr(s.authority_did, '%')) WHERE instr(s.authority_did, '%') > 0
        UNION ALL SELECT substr(substr(part, 4), instr(substr(part, 4), '%')) FROM percent
          WHERE instr(substr(part, 4), '%') > 0
      ) SELECT 1 FROM percent WHERE length(part) < 3 OR substr(part, 2, 2) NOT GLOB '[a-fA-F0-9][a-fA-F0-9]')
      THEN s.authority_did ELSE '' END ELSE '' END AS safe_authority,
    CASE WHEN typeof(s.space_type) = 'text' AND length(CAST(s.space_type AS BLOB)) BETWEEN 5 AND 317
      AND length(s.space_type) = length(CAST(s.space_type AS BLOB))
      THEN CASE WHEN s.space_type NOT GLOB '*[^a-zA-Z0-9.-]*' AND substr(s.space_type, 1, 1) GLOB '[a-zA-Z]'
      AND (SELECT COUNT(*) FROM json_each('[' || '"' || replace(CASE
        WHEN typeof(s.space_type) = 'text' AND s.space_type NOT GLOB '*[^a-zA-Z0-9.-]*'
          AND instr(s.space_type, char(0)) = 0 THEN s.space_type ELSE '' END, '.', '","') || '"' || ']')) >= 3
      AND NOT EXISTS (SELECT 1 FROM json_each('[' || '"' || replace(CASE
        WHEN typeof(s.space_type) = 'text' AND s.space_type NOT GLOB '*[^a-zA-Z0-9.-]*'
          AND instr(s.space_type, char(0)) = 0 THEN s.space_type ELSE '' END, '.', '","') || '"' || ']') part
        WHERE length(part.value) NOT BETWEEN 1 AND 63 OR substr(part.value, 1, 1) = '-'
          OR substr(part.value, -1) = '-'
          OR (CAST(part.key AS INTEGER) = (length(s.space_type) - length(replace(s.space_type, '.', '')))
            AND (substr(part.value, 1, 1) NOT GLOB '[a-zA-Z]' OR part.value GLOB '*[^a-zA-Z0-9]*')))
      THEN s.space_type ELSE '' END ELSE '' END AS safe_type
  FROM space s WHERE s.deleted_at IS NULL
), validated AS (
  SELECT s.*, CASE WHEN s.safe_authority != '' AND s.safe_type != ''
    AND typeof(s.skey) = 'text' AND length(CAST(s.skey AS BLOB)) BETWEEN 1 AND 512
    AND length(s.skey) = length(CAST(s.skey AS BLOB))
    AND typeof(s.space_ref) = 'text' AND length(CAST(s.space_ref AS BLOB)) BETWEEN 1 AND 8192
    THEN CASE WHEN s.skey NOT IN ('.', '..') AND s.skey NOT GLOB '*[^a-zA-Z0-9_~.:-]*'
      AND s.space_ref = 'at://' || s.authority_did || '/space/' || s.space_type || '/' || s.skey COLLATE BINARY
      THEN 1 ELSE 0 END ELSE 0 END AS indexable
  FROM normalized s
)
SELECT s.space_ref,
  CASE WHEN s.indexable = 1 AND (p.space_ref IS NULL OR p.authority_did = s.authority_did COLLATE BINARY)
    THEN s.safe_authority ELSE '' END AS authority_did,
  s.safe_type AS space_type, s.indexable,
  CASE WHEN s.indexable = 1 AND typeof(s.created_at) = 'integer' AND s.created_at BETWEEN 0 AND 9007199254740991
    AND typeof(p.authority_incarnation) = 'text' AND length(p.authority_incarnation) = 32
    AND length(CAST(p.authority_incarnation AS BLOB)) = 32
    AND typeof(p.creation_nonce) = 'text' AND length(p.creation_nonce) = 36
    AND length(CAST(p.creation_nonce AS BLOB)) = 36
    THEN CASE WHEN typeof(p.authority_did) = 'text' AND p.authority_did = s.authority_did COLLATE BINARY
    AND p.authority_incarnation NOT GLOB '*[^0-9a-f]*'
    AND p.policy_type = 'com.atproto.personalspace.policy' AND p.notification_state = 'none'
    AND typeof(p.created_at) = 'integer' AND p.created_at = s.created_at
    AND substr(p.creation_nonce, 9, 1) = '-'
    AND substr(p.creation_nonce, 14, 1) = '-' AND substr(p.creation_nonce, 15, 1) = '4'
    AND substr(p.creation_nonce, 19, 1) = '-' AND substr(p.creation_nonce, 20, 1) GLOB '[89ab]'
    AND substr(p.creation_nonce, 24, 1) = '-' AND length(replace(p.creation_nonce, '-', '')) = 32
    AND replace(p.creation_nonce, '-', '') NOT GLOB '*[^0-9a-f]*'
    THEN 1 ELSE 0 END ELSE 0 END AS classified,
  p.authority_incarnation, p.creation_nonce
FROM validated s LEFT JOIN space_personal_policy p ON p.space_ref = s.space_ref COLLATE BINARY;
--> statement-breakpoint
INSERT INTO space_owner_listing (space_ref, authority_did, authority_incarnation, space_type, creation_nonce)
SELECT space_ref, authority_did, authority_incarnation, space_type, creation_nonce
FROM space_owner_classification WHERE indexable = 1 AND classified = 1;
--> statement-breakpoint
INSERT INTO space_owner_unclassified (space_ref, authority_did, space_type)
SELECT space_ref, authority_did, space_type FROM space_owner_classification WHERE indexable = 1 AND classified = 0;
--> statement-breakpoint
INSERT INTO space_owner_quarantine_global (id)
SELECT 1 WHERE EXISTS (SELECT 1 FROM space_owner_classification WHERE indexable = 0);
--> statement-breakpoint
SELECT CASE WHEN NOT EXISTS (
  SELECT 1 FROM space_owner_classification c WHERE
    (c.indexable = 0 AND NOT EXISTS (SELECT 1 FROM space_owner_quarantine_global g WHERE g.id = 1))
    OR (c.indexable = 1 AND c.classified = 1 AND (
      NOT EXISTS (SELECT 1 FROM space_owner_listing l WHERE l.space_ref = c.space_ref COLLATE BINARY
        AND l.authority_did = c.authority_did COLLATE BINARY AND l.authority_incarnation = c.authority_incarnation
        AND l.space_type = c.space_type COLLATE BINARY AND l.creation_nonce = c.creation_nonce)
      OR EXISTS (SELECT 1 FROM space_owner_unclassified u WHERE u.space_ref = c.space_ref COLLATE BINARY)))
    OR (c.indexable = 1 AND c.classified = 0 AND (
      NOT EXISTS (SELECT 1 FROM space_owner_unclassified u WHERE u.space_ref = c.space_ref COLLATE BINARY
        AND u.authority_did = c.authority_did COLLATE BINARY AND u.space_type = c.space_type COLLATE BINARY)
      OR EXISTS (SELECT 1 FROM space_owner_listing l WHERE l.space_ref = c.space_ref COLLATE BINARY)))
) AND NOT EXISTS (SELECT 1 FROM space_owner_listing l WHERE NOT EXISTS (
  SELECT 1 FROM space_owner_classification c WHERE c.indexable = 1 AND c.classified = 1
    AND c.space_ref = l.space_ref COLLATE BINARY AND c.authority_did = l.authority_did COLLATE BINARY
    AND c.authority_incarnation = l.authority_incarnation AND c.space_type = l.space_type COLLATE BINARY
    AND c.creation_nonce = l.creation_nonce))
AND NOT EXISTS (SELECT 1 FROM space_owner_unclassified u WHERE NOT EXISTS (
  SELECT 1 FROM space_owner_classification c WHERE c.indexable = 1 AND c.classified = 0
    AND c.space_ref = u.space_ref COLLATE BINARY AND c.authority_did = u.authority_did COLLATE BINARY
    AND c.space_type = u.space_type COLLATE BINARY))
AND (NOT EXISTS (SELECT 1 FROM space_owner_quarantine_global) OR EXISTS (
  SELECT 1 FROM space_owner_classification c WHERE c.indexable = 0))
THEN 1 ELSE json('{') END;
--> statement-breakpoint
CREATE TRIGGER space_owner_listing_insert BEFORE INSERT ON space_owner_listing
WHEN NOT EXISTS (SELECT 1 FROM space_owner_classification c WHERE c.indexable = 1 AND c.classified = 1
  AND c.space_ref = NEW.space_ref COLLATE BINARY AND c.authority_did = NEW.authority_did COLLATE BINARY
  AND c.authority_incarnation = NEW.authority_incarnation AND c.space_type = NEW.space_type COLLATE BINARY
  AND c.creation_nonce = NEW.creation_nonce)
  OR EXISTS (SELECT 1 FROM space_owner_listing l WHERE l.space_ref = NEW.space_ref COLLATE BINARY)
BEGIN SELECT RAISE(ABORT, 'Space listing identity is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_owner_listing_update BEFORE UPDATE ON space_owner_listing
BEGIN SELECT RAISE(ABORT, 'Space listing identity is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER space_owner_listing_delete BEFORE DELETE ON space_owner_listing
WHEN NOT EXISTS (SELECT 1 FROM space s WHERE s.space_ref = OLD.space_ref COLLATE BINARY AND s.deleted_at IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'Space listing identity remains active'); END;
--> statement-breakpoint
CREATE TRIGGER space_owner_unclassified_insert BEFORE INSERT ON space_owner_unclassified
WHEN NOT EXISTS (SELECT 1 FROM space_owner_classification c WHERE c.indexable = 1 AND c.classified = 0
  AND c.space_ref = NEW.space_ref COLLATE BINARY AND c.authority_did = NEW.authority_did COLLATE BINARY
  AND c.space_type = NEW.space_type COLLATE BINARY)
  OR EXISTS (SELECT 1 FROM space_owner_unclassified u WHERE u.space_ref = NEW.space_ref COLLATE BINARY)
BEGIN SELECT RAISE(ABORT, 'Space quarantine identity is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_owner_unclassified_update BEFORE UPDATE ON space_owner_unclassified
BEGIN SELECT RAISE(ABORT, 'Space quarantine identity is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER space_owner_unclassified_delete BEFORE DELETE ON space_owner_unclassified
WHEN NOT EXISTS (SELECT 1 FROM space_owner_classification c
  JOIN space_owner_listing l ON l.space_ref = c.space_ref COLLATE BINARY AND l.authority_did = c.authority_did COLLATE BINARY
    AND l.authority_incarnation = c.authority_incarnation AND l.space_type = c.space_type COLLATE BINARY
    AND l.creation_nonce = c.creation_nonce
  WHERE c.space_ref = OLD.space_ref COLLATE BINARY AND c.indexable = 1 AND c.classified = 1
    AND c.authority_did = OLD.authority_did COLLATE BINARY AND c.space_type = OLD.space_type COLLATE BINARY)
BEGIN SELECT RAISE(ABORT, 'Space quarantine identity remains unclassified'); END;
--> statement-breakpoint
CREATE TRIGGER space_owner_quarantine_global_insert BEFORE INSERT ON space_owner_quarantine_global
WHEN NEW.id != 1 OR EXISTS (SELECT 1 FROM space_owner_quarantine_global)
BEGIN SELECT RAISE(ABORT, 'Space global quarantine is unavailable'); END;
--> statement-breakpoint
CREATE TRIGGER space_owner_quarantine_global_update BEFORE UPDATE ON space_owner_quarantine_global
BEGIN SELECT RAISE(ABORT, 'Space global quarantine is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER space_owner_quarantine_global_delete BEFORE DELETE ON space_owner_quarantine_global
BEGIN SELECT RAISE(ABORT, 'Space global quarantine requires offline reconciliation'); END;
--> statement-breakpoint
CREATE TRIGGER space_owner_quarantine_after_insert AFTER INSERT ON space
BEGIN
  INSERT INTO space_owner_unclassified (space_ref, authority_did, space_type)
    SELECT c.space_ref, c.authority_did, c.space_type FROM space_owner_classification c
      WHERE c.space_ref IS NEW.space_ref COLLATE BINARY AND c.indexable = 1 AND c.classified = 0;
  INSERT INTO space_owner_quarantine_global (id)
    SELECT 1 WHERE EXISTS (SELECT 1 FROM space_owner_classification c
      WHERE c.space_ref IS NEW.space_ref COLLATE BINARY AND c.indexable = 0)
      AND NOT EXISTS (SELECT 1 FROM space_owner_quarantine_global);
  SELECT RAISE(ABORT, 'Space quarantine insertion failed') WHERE NOT EXISTS (
    SELECT 1 FROM space_owner_classification c WHERE c.space_ref IS NEW.space_ref COLLATE BINARY AND c.classified = 0
      AND ((c.indexable = 1 AND EXISTS (SELECT 1 FROM space_owner_unclassified u
        WHERE u.space_ref = c.space_ref COLLATE BINARY AND u.authority_did = c.authority_did COLLATE BINARY
          AND u.space_type = c.space_type COLLATE BINARY))
        OR (c.indexable = 0 AND EXISTS (SELECT 1 FROM space_owner_quarantine_global g WHERE g.id = 1))));
END;
--> statement-breakpoint
CREATE TRIGGER space_owner_listing_after_policy AFTER INSERT ON space_personal_policy
BEGIN
  INSERT INTO space_owner_listing (space_ref, authority_did, authority_incarnation, space_type, creation_nonce)
    SELECT c.space_ref, c.authority_did, c.authority_incarnation, c.space_type, c.creation_nonce
      FROM space_owner_classification c WHERE c.space_ref = NEW.space_ref COLLATE BINARY
        AND c.indexable = 1 AND c.classified = 1;
  SELECT RAISE(ABORT, 'Space listing insertion failed') WHERE changes() != 1
    OR NOT EXISTS (SELECT 1 FROM space_owner_classification c JOIN space_owner_listing l
      ON l.space_ref = c.space_ref COLLATE BINARY AND l.authority_did = c.authority_did COLLATE BINARY
        AND l.authority_incarnation = c.authority_incarnation AND l.space_type = c.space_type COLLATE BINARY
        AND l.creation_nonce = c.creation_nonce WHERE c.space_ref = NEW.space_ref COLLATE BINARY
        AND c.indexable = 1 AND c.classified = 1);
  DELETE FROM space_owner_unclassified WHERE space_ref = NEW.space_ref COLLATE BINARY;
  SELECT RAISE(ABORT, 'Space quarantine classification failed') WHERE changes() != 1
    OR EXISTS (SELECT 1 FROM space_owner_unclassified WHERE space_ref = NEW.space_ref COLLATE BINARY);
END;
--> statement-breakpoint
CREATE TRIGGER space_owner_listing_after_delete AFTER UPDATE OF deleted_at ON space
WHEN OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL
BEGIN
  DELETE FROM space_owner_listing WHERE space_ref = NEW.space_ref COLLATE BINARY;
  SELECT RAISE(ABORT, 'Space listing deletion failed') WHERE changes() != 1
    OR EXISTS (SELECT 1 FROM space_owner_listing WHERE space_ref = NEW.space_ref COLLATE BINARY)
    OR EXISTS (SELECT 1 FROM space_owner_unclassified WHERE space_ref = NEW.space_ref COLLATE BINARY);
END;
