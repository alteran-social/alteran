CREATE TABLE `space` (
	`space_ref` text PRIMARY KEY NOT NULL,
	`authority_did` text NOT NULL,
	`space_type` text NOT NULL,
	`skey` text NOT NULL,
	`created_at` integer NOT NULL,
	`deleted_at` integer
);
--> statement-breakpoint
CREATE INDEX `space_authority_type_idx` ON `space` (`authority_did`,`space_type`,`space_ref`);--> statement-breakpoint
CREATE TABLE `space_blob_usage` (
	`space_ref` text NOT NULL,
	`repo_did` text NOT NULL,
	`collection` text NOT NULL,
	`rkey` text NOT NULL,
	`cid` text NOT NULL,
	`key` text NOT NULL,
	PRIMARY KEY(`space_ref`, `repo_did`, `collection`, `rkey`, `cid`)
);
--> statement-breakpoint
CREATE INDEX `space_blob_usage_retention_idx` ON `space_blob_usage` (`repo_did`,`key`);--> statement-breakpoint
CREATE INDEX `space_blob_usage_space_cid_idx` ON `space_blob_usage` (`space_ref`,`repo_did`,`cid`);--> statement-breakpoint
CREATE TABLE `space_op` (
	`space_ref` text NOT NULL,
	`repo_did` text NOT NULL,
	`rev` text NOT NULL,
	`ordinal` integer NOT NULL,
	`collection` text NOT NULL,
	`rkey` text NOT NULL,
	`cid` text,
	`prev` text,
	PRIMARY KEY(`space_ref`, `repo_did`, `rev`, `ordinal`)
);
--> statement-breakpoint
CREATE TABLE `space_record` (
	`space_ref` text NOT NULL,
	`repo_did` text NOT NULL,
	`collection` text NOT NULL,
	`rkey` text NOT NULL,
	`cid` text NOT NULL,
	`value_cbor` blob NOT NULL,
	`repo_rev` text NOT NULL,
	PRIMARY KEY(`space_ref`, `repo_did`, `collection`, `rkey`)
);
--> statement-breakpoint
CREATE INDEX `space_record_cid_idx` ON `space_record` (`space_ref`,`repo_did`,`cid`);--> statement-breakpoint
CREATE TABLE `space_repo` (
	`space_ref` text NOT NULL,
	`repo_did` text NOT NULL,
	`rev` text,
	`set_hash` blob NOT NULL,
	`generation` integer NOT NULL,
	`mutation_id` text NOT NULL,
	PRIMARY KEY(`space_ref`, `repo_did`),
	CONSTRAINT "space_repo_hash_size" CHECK(length("space_repo"."set_hash") = 2048)
);
