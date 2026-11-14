SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM account WHERE space_incarnation IS NOT NULL)
  AND NOT EXISTS (SELECT 1 FROM account_space_incarnation_init)
  THEN 1 ELSE json('{') END;
--> statement-breakpoint
UPDATE account SET space_incarnation = lower(hex(randomblob(16))) WHERE space_incarnation IS NULL;
--> statement-breakpoint
SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM account WHERE typeof(space_incarnation) != 'text'
  OR length(space_incarnation) != 32 OR length(CAST(space_incarnation AS BLOB)) != 32
  OR space_incarnation GLOB '*[^0-9a-f]*') THEN 1 ELSE json('{') END;
--> statement-breakpoint
CREATE TRIGGER account_space_incarnation_init_insert BEFORE INSERT ON account_space_incarnation_init
WHEN NEW.id != 1 OR EXISTS (SELECT 1 FROM account_space_incarnation_init)
  OR typeof(NEW.did) != 'text' OR length(CAST(NEW.did AS BLOB)) NOT BETWEEN 1 AND 2048
  OR typeof(NEW.incarnation) != 'text' OR length(NEW.incarnation) != 32
  OR length(CAST(NEW.incarnation AS BLOB)) != 32 OR NEW.incarnation GLOB '*[^0-9a-f]*'
  OR NOT EXISTS (SELECT 1 FROM account WHERE did = NEW.did AND space_incarnation IS NULL)
BEGIN SELECT RAISE(ABORT, 'invalid account incarnation initialization'); END;
--> statement-breakpoint
CREATE TRIGGER account_space_incarnation_init_update BEFORE UPDATE ON account_space_incarnation_init
BEGIN SELECT RAISE(ABORT, 'account incarnation initialization is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER account_space_incarnation_init_delete BEFORE DELETE ON account_space_incarnation_init
WHEN NOT EXISTS (SELECT 1 FROM account WHERE did = OLD.did AND space_incarnation IS OLD.incarnation)
BEGIN SELECT RAISE(ABORT, 'account incarnation initialization is incomplete'); END;
--> statement-breakpoint
CREATE TRIGGER account_space_incarnation_insert BEFORE INSERT ON account
WHEN NEW.space_incarnation IS NOT NULL OR EXISTS (SELECT 1 FROM account_space_incarnation_init)
BEGIN SELECT RAISE(ABORT, 'account incarnation must be generated'); END;
--> statement-breakpoint
CREATE TRIGGER account_space_incarnation_update BEFORE UPDATE ON account
WHEN NEW.did IS NOT OLD.did OR (NEW.space_incarnation IS NOT OLD.space_incarnation AND (
  OLD.space_incarnation IS NOT NULL OR typeof(NEW.space_incarnation) != 'text'
  OR length(NEW.space_incarnation) != 32 OR length(CAST(NEW.space_incarnation AS BLOB)) != 32
  OR NEW.space_incarnation GLOB '*[^0-9a-f]*'
  OR NOT EXISTS (SELECT 1 FROM account_space_incarnation_init i
    WHERE i.id = 1 AND i.did = OLD.did AND i.incarnation IS NEW.space_incarnation)
  OR EXISTS (SELECT 1 FROM account other WHERE other.space_incarnation IS NEW.space_incarnation AND other.did IS NOT OLD.did)
))
BEGIN SELECT RAISE(ABORT, 'account incarnation is immutable'); END;
--> statement-breakpoint
CREATE TRIGGER account_space_incarnation_created AFTER INSERT ON account
BEGIN
  INSERT INTO account_space_incarnation_init (id, did, incarnation)
    VALUES (1, NEW.did, lower(hex(randomblob(16))));
  SELECT RAISE(ABORT, 'account incarnation initialization unavailable') WHERE changes() != 1
    OR NOT EXISTS (SELECT 1 FROM account_space_incarnation_init WHERE id = 1 AND did = NEW.did);
  UPDATE account SET space_incarnation = (SELECT incarnation FROM account_space_incarnation_init WHERE id = 1 AND did = NEW.did)
    WHERE did = NEW.did AND space_incarnation IS NULL;
  SELECT RAISE(ABORT, 'account incarnation initialization failed') WHERE changes() != 1
    OR NOT EXISTS (SELECT 1 FROM account a JOIN account_space_incarnation_init i ON i.id = 1 AND i.did = a.did
      AND a.space_incarnation IS i.incarnation WHERE a.did = NEW.did AND typeof(a.space_incarnation) = 'text'
      AND length(a.space_incarnation) = 32 AND length(CAST(a.space_incarnation AS BLOB)) = 32
      AND a.space_incarnation NOT GLOB '*[^0-9a-f]*');
  DELETE FROM account_space_incarnation_init WHERE id = 1 AND did = NEW.did;
  SELECT RAISE(ABORT, 'account incarnation initialization cleanup failed') WHERE changes() != 1
    OR EXISTS (SELECT 1 FROM account_space_incarnation_init);
END;
