PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_blob_usage` (
	`did` text NOT NULL,
	`record_uri` text NOT NULL,
	`key` text NOT NULL,
	`cid` text NOT NULL,
	`repo_rev` text NOT NULL,
	PRIMARY KEY(`did`, `record_uri`, `key`)
);
--> statement-breakpoint
INSERT INTO `__new_blob_usage`("did", "record_uri", "key", "cid", "repo_rev")
SELECT
	`blob_usage`.`did`,
	`blob_usage`.`record_uri`,
	`blob_usage`.`key`,
	`blob`.`cid`,
	COALESCE(`repo_root`.`rev`, '')
FROM `blob_usage`
INNER JOIN `blob`
	ON `blob`.`did` = `blob_usage`.`did`
	AND `blob`.`key` = `blob_usage`.`key`
LEFT JOIN `repo_root`
	ON `repo_root`.`did` = `blob_usage`.`did`
WHERE `blob`.`cid` IS NOT NULL
	AND `blob`.`cid` <> '';--> statement-breakpoint
DROP TABLE `blob_usage`;--> statement-breakpoint
ALTER TABLE `__new_blob_usage` RENAME TO `blob_usage`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE INDEX `blob_usage_record_uri_idx` ON `blob_usage` (`did`,`record_uri`);--> statement-breakpoint
CREATE INDEX `blob_usage_did_key_idx` ON `blob_usage` (`did`,`key`);--> statement-breakpoint
CREATE INDEX `blob_usage_did_repo_rev_cid_idx` ON `blob_usage` (`did`,`repo_rev`,`cid`);
