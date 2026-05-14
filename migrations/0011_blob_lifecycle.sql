ALTER TABLE `blob` ADD `created_at` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `blob` ADD `state` text DEFAULT 'temp' NOT NULL;--> statement-breakpoint
ALTER TABLE `blob` ADD `temp_key` text;--> statement-breakpoint
ALTER TABLE `blob` ADD `takedown_ref` text;--> statement-breakpoint
UPDATE `blob`
SET
  `created_at` = CASE
    WHEN `uploaded_at` > 0 THEN `uploaded_at`
    ELSE CAST(strftime('%s', 'now') AS integer) * 1000
  END,
  `state` = CASE
    WHEN EXISTS (
      SELECT 1 FROM `blob_usage`
      WHERE `blob_usage`.`did` = `blob`.`did`
        AND `blob_usage`.`key` = `blob`.`key`
    ) THEN 'permanent'
    ELSE 'temp'
  END;--> statement-breakpoint
ALTER TABLE `blob_usage` ADD `record_cid` text;--> statement-breakpoint
ALTER TABLE `blob_usage` ADD `commit_cid` text;--> statement-breakpoint
ALTER TABLE `blob_usage` ADD `commit_rev` text;--> statement-breakpoint
ALTER TABLE `blob_usage` ADD `created_at` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
UPDATE `blob_usage`
SET
  `record_cid` = (
    SELECT `record`.`cid`
    FROM `record`
    WHERE `record`.`did` = `blob_usage`.`did`
      AND `record`.`uri` = `blob_usage`.`record_uri`
    LIMIT 1
  ),
  `commit_cid` = (
    SELECT `repo_root`.`commit_cid`
    FROM `repo_root`
    WHERE `repo_root`.`did` = `blob_usage`.`did`
    LIMIT 1
  ),
  `commit_rev` = (
    SELECT `repo_root`.`rev`
    FROM `repo_root`
    WHERE `repo_root`.`did` = `blob_usage`.`did`
    LIMIT 1
  ),
  `created_at` = CAST(strftime('%s', 'now') AS integer) * 1000;--> statement-breakpoint
CREATE INDEX `blob_state_idx` ON `blob` (`did`,`state`);--> statement-breakpoint
CREATE INDEX `blob_usage_commit_rev_idx` ON `blob_usage` (`did`,`commit_rev`,`key`);
