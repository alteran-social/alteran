CREATE TABLE `private_blob_staging` (
	`id` text PRIMARY KEY NOT NULL,
	`token` text NOT NULL,
	`repo_did` text NOT NULL,
	`account_incarnation` text NOT NULL,
	`object_key` text NOT NULL,
	`state` text NOT NULL,
	`reserved_bytes` integer NOT NULL,
	`claim_nonce` text,
	`cid` text,
	`digest` text,
	`size` integer,
	`mime_type` text,
	`r2_version` text,
	`etag` text,
	CONSTRAINT "private_blob_staging_state" CHECK("private_blob_staging"."state" IN ('reserved', 'putting', 'ready', 'uncertain')),
	CONSTRAINT "private_blob_staging_charge" CHECK(typeof("private_blob_staging"."reserved_bytes") = 'integer' AND "private_blob_staging"."reserved_bytes" = 5242880)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `private_blob_staging_object_key` ON `private_blob_staging` (`object_key`);--> statement-breakpoint
CREATE INDEX `private_blob_staging_owner` ON `private_blob_staging` (`repo_did`);