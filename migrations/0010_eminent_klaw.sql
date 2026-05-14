PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_blob_usage` (
	`did` text NOT NULL,
	`record_uri` text NOT NULL,
	`key` text NOT NULL,
	PRIMARY KEY(`did`, `record_uri`, `key`)
);
--> statement-breakpoint
INSERT INTO `__new_blob_usage`("did", "record_uri", "key")
SELECT
	COALESCE(
		`record`.`did`,
		substr(`blob_usage`.`record_uri`, 6, instr(substr(`blob_usage`.`record_uri`, 6), '/') - 1)
	),
	`blob_usage`.`record_uri`,
	`blob_usage`.`key`
FROM `blob_usage`
LEFT JOIN `record` ON `record`.`uri` = `blob_usage`.`record_uri`;--> statement-breakpoint
DROP TABLE `blob_usage`;--> statement-breakpoint
ALTER TABLE `__new_blob_usage` RENAME TO `blob_usage`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE INDEX `blob_usage_record_uri_idx` ON `blob_usage` (`did`,`record_uri`);--> statement-breakpoint
CREATE INDEX `blob_usage_did_key_idx` ON `blob_usage` (`did`,`key`);--> statement-breakpoint
CREATE TABLE `__new_blob` (
	`cid` text NOT NULL,
	`did` text NOT NULL,
	`key` text NOT NULL,
	`mime` text NOT NULL,
	`size` integer NOT NULL,
	`uploaded_at` integer DEFAULT 0 NOT NULL,
	PRIMARY KEY(`did`, `cid`)
);
--> statement-breakpoint
INSERT INTO `__new_blob`("cid", "did", "key", "mime", "size", "uploaded_at") SELECT "cid", "did", "key", "mime", "size", 0 FROM `blob`;--> statement-breakpoint
DROP TABLE `blob`;--> statement-breakpoint
ALTER TABLE `__new_blob` RENAME TO `blob`;--> statement-breakpoint
CREATE INDEX `blob_key_idx` ON `blob` (`key`);
