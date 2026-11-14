CREATE TABLE `space_quarantine_job` (
	`id` text PRIMARY KEY NOT NULL,
	`token` text NOT NULL,
	`renewal_nonce` text NOT NULL,
	`space_ref` text NOT NULL,
	`repo_did` text NOT NULL,
	`epoch_id` text NOT NULL,
	`authority_did` text NOT NULL,
	`space_type` text NOT NULL,
	`skey` text NOT NULL,
	`generation` integer NOT NULL,
	`mutation_id` text NOT NULL,
	`rev` text NOT NULL,
	`expected_hash` blob NOT NULL,
	`accumulated_hash` blob NOT NULL,
	`cursor` text NOT NULL,
	`sequence` integer NOT NULL,
	`record_count` integer NOT NULL,
	`lease_until` integer NOT NULL,
	`status` text NOT NULL,
	`activation_nonce` text,
	`created_at` integer NOT NULL,
	CONSTRAINT "space_quarantine_job_hashes" CHECK(length("space_quarantine_job"."expected_hash") = 2048 AND length("space_quarantine_job"."accumulated_hash") = 2048),
	CONSTRAINT "space_quarantine_job_counts" CHECK("space_quarantine_job"."generation" >= 1 AND "space_quarantine_job"."sequence" >= 0 AND "space_quarantine_job"."record_count" >= 0),
	CONSTRAINT "space_quarantine_job_status" CHECK("space_quarantine_job"."status" IN ('running', 'complete', 'activating', 'active', 'failed'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `space_quarantine_job_owner_epoch` ON `space_quarantine_job` (`space_ref`,`repo_did`,`epoch_id`);--> statement-breakpoint
ALTER TABLE `space_epoch` ADD `verified_job_id` text;--> statement-breakpoint
ALTER TABLE `space_epoch` ADD `activation_nonce` text;--> statement-breakpoint
CREATE INDEX `space_record_path_idx` ON `space_record` (`space_ref`,`repo_did`,("collection" || '/' || "rkey") COLLATE BINARY);