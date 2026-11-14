SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM private_blob_staging) THEN 1 ELSE json('{') END;
--> statement-breakpoint
CREATE TRIGGER private_blob_staging_insert BEFORE INSERT ON private_blob_staging
WHEN typeof(NEW.id) IS NOT 'text' OR length(NEW.id) IS NOT 32
  OR length(CAST(NEW.id AS BLOB)) IS NOT 32 OR NEW.id GLOB '*[^0-9a-f]*'
  OR typeof(NEW.token) IS NOT 'text' OR length(NEW.token) IS NOT 32
  OR length(CAST(NEW.token AS BLOB)) IS NOT 32 OR NEW.token GLOB '*[^0-9a-f]*'
  OR typeof(NEW.repo_did) IS NOT 'text' OR length(CAST(NEW.repo_did AS BLOB)) NOT BETWEEN 1 AND 2048
  OR instr(NEW.repo_did, char(0)) != 0 OR NEW.repo_did GLOB '*[^A-Za-z0-9._:%-]*'
  OR typeof(NEW.account_incarnation) IS NOT 'text' OR length(NEW.account_incarnation) IS NOT 32
  OR length(CAST(NEW.account_incarnation AS BLOB)) IS NOT 32 OR NEW.account_incarnation GLOB '*[^0-9a-f]*'
  OR typeof(NEW.object_key) IS NOT 'text' OR NEW.object_key IS NOT ('space-staging/' || NEW.id)
  OR NEW.state IS NOT 'reserved' OR NEW.reserved_bytes IS NOT 5242880
  OR NEW.claim_nonce IS NOT NULL OR NEW.cid IS NOT NULL OR NEW.digest IS NOT NULL
  OR NEW.size IS NOT NULL OR NEW.mime_type IS NOT NULL OR NEW.r2_version IS NOT NULL OR NEW.etag IS NOT NULL
  OR EXISTS (SELECT 1 FROM private_blob_staging p WHERE p.id = NEW.id OR p.object_key = NEW.object_key)
  OR NOT EXISTS (SELECT 1 FROM account a JOIN account_state s ON s.did = a.did
    WHERE a.did = NEW.repo_did AND a.space_incarnation IS NEW.account_incarnation
      AND typeof(s.active) = 'integer' AND s.active = 1 AND s.status IS NULL AND s.suspended_until IS NULL)
  OR EXISTS (SELECT 1 FROM private_blob_staging INDEXED BY private_blob_staging_owner
    WHERE repo_did = NEW.repo_did LIMIT 1 OFFSET 63)
  OR EXISTS (SELECT 1 FROM private_blob_staging LIMIT 1 OFFSET 255)
BEGIN SELECT RAISE(ABORT, 'invalid private blob reservation'); END;
--> statement-breakpoint
CREATE TRIGGER private_blob_staging_update BEFORE UPDATE ON private_blob_staging
WHEN NEW.id IS NOT OLD.id OR NEW.token IS NOT OLD.token OR NEW.repo_did IS NOT OLD.repo_did
  OR NEW.account_incarnation IS NOT OLD.account_incarnation OR NEW.object_key IS NOT OLD.object_key
  OR NEW.reserved_bytes IS NOT OLD.reserved_bytes OR NOT COALESCE((
    (OLD.state = 'reserved' AND NEW.state = 'putting'
      AND typeof(NEW.claim_nonce) = 'text' AND length(NEW.claim_nonce) = 32
      AND length(CAST(NEW.claim_nonce AS BLOB)) = 32 AND NEW.claim_nonce NOT GLOB '*[^0-9a-f]*'
      AND typeof(NEW.cid) = 'text' AND length(NEW.cid) = 59 AND length(CAST(NEW.cid AS BLOB)) = 59
      AND NEW.cid GLOB 'bafkrei*' AND NEW.cid NOT GLOB '*[^a-z2-7]*'
      AND typeof(NEW.digest) = 'text' AND length(NEW.digest) = 64 AND length(CAST(NEW.digest AS BLOB)) = 64
      AND NEW.digest NOT GLOB '*[^0-9a-f]*'
      AND typeof(NEW.size) = 'integer' AND NEW.size BETWEEN 0 AND 5242880
      AND typeof(NEW.mime_type) = 'text' AND length(CAST(NEW.mime_type AS BLOB)) BETWEEN 3 AND 255
      AND length(NEW.mime_type) = length(CAST(NEW.mime_type AS BLOB))
      AND NEW.mime_type NOT GLOB '*[^A-Za-z0-9!#$%&''+.^_`|~/-]*'
      AND instr(NEW.mime_type, '/') BETWEEN 2 AND length(NEW.mime_type) - 1
      AND length(NEW.mime_type) - length(replace(NEW.mime_type, '/', '')) = 1
      AND NEW.r2_version IS NULL AND NEW.etag IS NULL
      AND EXISTS (SELECT 1 FROM account a JOIN account_state s ON s.did = a.did
        WHERE a.did = OLD.repo_did AND a.space_incarnation IS OLD.account_incarnation
          AND typeof(s.active) = 'integer' AND s.active = 1 AND s.status IS NULL AND s.suspended_until IS NULL))
    OR (OLD.state = 'putting' AND NEW.state IN ('ready', 'uncertain')
      AND NEW.claim_nonce IS OLD.claim_nonce AND NEW.cid IS OLD.cid AND NEW.digest IS OLD.digest
      AND NEW.size IS OLD.size AND NEW.mime_type IS OLD.mime_type
      AND ((NEW.state = 'uncertain' AND NEW.r2_version IS NULL AND NEW.etag IS NULL)
        OR (NEW.state = 'ready' AND typeof(NEW.r2_version) = 'text'
          AND length(CAST(NEW.r2_version AS BLOB)) BETWEEN 1 AND 512 AND instr(NEW.r2_version, char(0)) = 0
          AND typeof(NEW.etag) = 'text' AND length(CAST(NEW.etag AS BLOB)) BETWEEN 1 AND 512
          AND instr(NEW.etag, char(0)) = 0)))
  ), 0)
BEGIN SELECT RAISE(ABORT, 'invalid private blob transition'); END;
--> statement-breakpoint
CREATE TRIGGER private_blob_staging_delete BEFORE DELETE ON private_blob_staging
BEGIN SELECT RAISE(ABORT, 'private blob reservation is permanent'); END;
