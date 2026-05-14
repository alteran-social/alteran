CREATE TABLE `firehose_event` (
	`seq` integer PRIMARY KEY NOT NULL,
	`event_type` text NOT NULL,
	`did` text,
	`event_payload` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `firehose_event_type_idx` ON `firehose_event` (`event_type`);--> statement-breakpoint
CREATE INDEX `firehose_event_created_at_idx` ON `firehose_event` (`created_at`);--> statement-breakpoint
CREATE TABLE `firehose_sequence` (
	`id` text PRIMARY KEY NOT NULL,
	`next_seq` integer NOT NULL
);
--> statement-breakpoint
INSERT INTO `firehose_sequence` (`id`, `next_seq`)
SELECT 'subscribeRepos', COALESCE(MAX(`seq`), 0) + 1 FROM `commit_log`;
