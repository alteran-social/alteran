CREATE TABLE `space_epoch` (
	`id` text PRIMARY KEY NOT NULL,
	`space_ref` text NOT NULL,
	`repo_did` text NOT NULL,
	`state` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT "space_epoch_state" CHECK("space_epoch"."state" in ('active', 'quarantined', 'retired', 'deleting'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `space_epoch_active_owner` ON `space_epoch` (`space_ref`,`repo_did`) WHERE "space_epoch"."state" = 'active';--> statement-breakpoint
CREATE TABLE `space_record_version` (
	`epoch_id` text NOT NULL,
	`space_ref` text NOT NULL,
	`repo_did` text NOT NULL,
	`path` text NOT NULL,
	`collection` text NOT NULL,
	`rkey` text NOT NULL,
	`from_generation` integer NOT NULL,
	`until_generation` integer,
	`cid` text NOT NULL,
	`value_cbor` blob NOT NULL,
	`value_size` integer NOT NULL,
	`repo_rev` text NOT NULL,
	PRIMARY KEY(`epoch_id`, `path`, `from_generation`),
	CONSTRAINT "space_record_version_interval" CHECK("space_record_version"."from_generation" >= 1 AND ("space_record_version"."until_generation" IS NULL OR "space_record_version"."until_generation" > "space_record_version"."from_generation")),
	CONSTRAINT "space_record_version_path" CHECK("space_record_version"."path" = "space_record_version"."collection" || '/' || "space_record_version"."rkey"),
	CONSTRAINT "space_record_version_size" CHECK("space_record_version"."value_size" = length("space_record_version"."value_cbor") AND "space_record_version"."value_size" > 0 AND "space_record_version"."value_size" <= 1048576)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `space_record_version_current_path` ON `space_record_version` (`epoch_id`,`path`) WHERE "space_record_version"."until_generation" IS NULL;--> statement-breakpoint
CREATE TABLE `space_snapshot_lease` (
	`id` text PRIMARY KEY NOT NULL,
	`token` text NOT NULL,
	`renewal_nonce` text NOT NULL,
	`space_ref` text NOT NULL,
	`repo_did` text NOT NULL,
	`epoch_id` text NOT NULL,
	`generation` integer NOT NULL,
	`rev` text NOT NULL,
	`set_hash` blob NOT NULL,
	`expires_at` integer NOT NULL,
	`maximum_expires_at` integer NOT NULL,
	CONSTRAINT "space_snapshot_lease_hash_size" CHECK(length("space_snapshot_lease"."set_hash") = 2048)
);
--> statement-breakpoint
CREATE INDEX `space_snapshot_lease_epoch_expiry` ON `space_snapshot_lease` (`epoch_id`,`expires_at`,`generation`);--> statement-breakpoint
ALTER TABLE `space_repo` ADD `active_epoch_id` text;