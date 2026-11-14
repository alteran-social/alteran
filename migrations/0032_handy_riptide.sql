CREATE TABLE `space_personal_creation_attempt` (
	`nonce` text PRIMARY KEY NOT NULL,
	`space_ref` text NOT NULL,
	`authority_did` text NOT NULL,
	`space_type` text NOT NULL,
	`skey` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `space_personal_creation_attempt_space` ON `space_personal_creation_attempt` (`space_ref`);--> statement-breakpoint
CREATE TABLE `space_personal_deletion_attempt` (
	`nonce` text PRIMARY KEY NOT NULL,
	`job_nonce` text NOT NULL,
	`space_ref` text NOT NULL,
	`authority_did` text NOT NULL,
	`epoch_id` text,
	`phase` text NOT NULL,
	`sequence` integer NOT NULL,
	`status` text NOT NULL,
	`maximum_count` integer NOT NULL,
	`expected_count` integer NOT NULL,
	`expected_bytes` integer NOT NULL,
	CONSTRAINT "space_personal_deletion_attempt_status" CHECK("space_personal_deletion_attempt"."status" IN ('building', 'sealed')),
	CONSTRAINT "space_personal_deletion_attempt_counts" CHECK("space_personal_deletion_attempt"."sequence" >= 0 AND "space_personal_deletion_attempt"."maximum_count" BETWEEN 1 AND 32 AND "space_personal_deletion_attempt"."expected_count" BETWEEN 0 AND "space_personal_deletion_attempt"."maximum_count" AND "space_personal_deletion_attempt"."expected_bytes" BETWEEN 0 AND 4194304)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `space_personal_deletion_attempt_job` ON `space_personal_deletion_attempt` (`job_nonce`);--> statement-breakpoint
CREATE TABLE `space_personal_deletion_candidate` (
	`attempt_nonce` text NOT NULL,
	`row_id` integer NOT NULL,
	`byte_size` integer NOT NULL,
	PRIMARY KEY(`attempt_nonce`, `row_id`),
	CONSTRAINT "space_personal_deletion_candidate_bytes" CHECK("space_personal_deletion_candidate"."byte_size" BETWEEN 0 AND 1048576)
);
--> statement-breakpoint
CREATE TABLE `space_personal_deletion_job` (
	`nonce` text PRIMARY KEY NOT NULL,
	`space_ref` text NOT NULL,
	`authority_did` text NOT NULL,
	`epoch_id` text,
	`status` text NOT NULL,
	`phase` text NOT NULL,
	`sequence` integer NOT NULL,
	`last_step_nonce` text,
	`last_step_phase` text,
	`last_step_count` integer NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT "space_personal_deletion_job_status" CHECK("space_personal_deletion_job"."status" IN ('deleting', 'complete')),
	CONSTRAINT "space_personal_deletion_job_phase" CHECK("space_personal_deletion_job"."phase" IN ('records', 'versions', 'ops', 'done')),
	CONSTRAINT "space_personal_deletion_job_counts" CHECK("space_personal_deletion_job"."sequence" >= 0 AND "space_personal_deletion_job"."last_step_count" BETWEEN 0 AND 32)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `space_personal_deletion_job_space` ON `space_personal_deletion_job` (`space_ref`);--> statement-breakpoint
CREATE TABLE `space_personal_policy` (
	`space_ref` text PRIMARY KEY NOT NULL,
	`authority_did` text NOT NULL,
	`policy_type` text NOT NULL,
	`creation_nonce` text NOT NULL,
	`notification_state` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT "space_personal_policy_type" CHECK("space_personal_policy"."policy_type" = 'com.atproto.personalspace.policy'),
	CONSTRAINT "space_personal_policy_notifications" CHECK("space_personal_policy"."notification_state" = 'none')
);
--> statement-breakpoint
CREATE UNIQUE INDEX `space_personal_policy_creation_nonce` ON `space_personal_policy` (`creation_nonce`);--> statement-breakpoint
CREATE INDEX `space_epoch_space_owner` ON `space_epoch` (`space_ref`,`repo_did`,`id`);--> statement-breakpoint
CREATE INDEX `space_record_version_space_owner_epoch` ON `space_record_version` (`space_ref`,`repo_did`,`epoch_id`);