SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM oauth_space_grant LIMIT 1)
  THEN 1 ELSE json('{') END;
--> statement-breakpoint
CREATE TRIGGER oauth_space_grant_insert BEFORE INSERT ON oauth_space_grant
WHEN typeof(NEW.session_id) != 'text' OR length(CAST(NEW.session_id AS BLOB)) NOT BETWEEN 1 AND 128
  OR typeof(NEW.snapshot) != 'text' OR length(CAST(NEW.snapshot AS BLOB)) NOT BETWEEN 1 AND 65536
  OR typeof(NEW.digest) != 'text' OR length(NEW.digest) != 64 OR length(CAST(NEW.digest AS BLOB)) != 64
  OR NEW.digest GLOB '*[^0-9a-f]*'
  OR NOT EXISTS (SELECT 1 FROM oauth_session WHERE id = NEW.session_id)
  OR EXISTS (SELECT 1 FROM oauth_space_grant WHERE session_id = NEW.session_id)
BEGIN SELECT RAISE(ABORT, 'Space consent grant cannot be replaced'); END;
--> statement-breakpoint
CREATE TRIGGER oauth_space_grant_update BEFORE UPDATE ON oauth_space_grant
BEGIN SELECT RAISE(ABORT, 'Space consent grant is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER oauth_space_grant_delete BEFORE DELETE ON oauth_space_grant
BEGIN SELECT RAISE(ABORT, 'Space consent grant must be retained'); END;
