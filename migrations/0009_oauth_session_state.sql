CREATE TABLE `oauth_session` (
	`id` text PRIMARY KEY NOT NULL,
	`did` text NOT NULL,
	`client_id` text NOT NULL,
	`client_auth_method` text NOT NULL,
	`client_auth_key_id` text,
	`dpop_jkt` text NOT NULL,
	`scope` text NOT NULL,
	`current_refresh_token_id` text NOT NULL,
	`access_jti` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`revoked_at` integer
);
--> statement-breakpoint
CREATE INDEX `oauth_session_client_idx` ON `oauth_session` (`client_id`);--> statement-breakpoint
CREATE INDEX `oauth_session_current_refresh_idx` ON `oauth_session` (`current_refresh_token_id`);--> statement-breakpoint
CREATE INDEX `oauth_session_access_jti_idx` ON `oauth_session` (`access_jti`);--> statement-breakpoint
ALTER TABLE `refresh_token` ADD `token_kind` text DEFAULT 'legacy' NOT NULL;--> statement-breakpoint
ALTER TABLE `refresh_token` ADD `oauth_session_id` text;--> statement-breakpoint
ALTER TABLE `refresh_token` ADD `client_id` text;--> statement-breakpoint
ALTER TABLE `refresh_token` ADD `client_auth_method` text;--> statement-breakpoint
ALTER TABLE `refresh_token` ADD `client_auth_key_id` text;--> statement-breakpoint
ALTER TABLE `refresh_token` ADD `dpop_jkt` text;--> statement-breakpoint
ALTER TABLE `refresh_token` ADD `oauth_scope` text;--> statement-breakpoint
ALTER TABLE `refresh_token` ADD `access_jti` text;--> statement-breakpoint
ALTER TABLE `refresh_token` ADD `revoked_at` integer;--> statement-breakpoint
UPDATE `refresh_token` SET `revoked_at` = CAST(strftime('%s','now') AS INTEGER) WHERE `revoked_at` IS NULL;--> statement-breakpoint
CREATE INDEX `refresh_token_oauth_session_idx` ON `refresh_token` (`oauth_session_id`);--> statement-breakpoint
CREATE INDEX `refresh_token_access_jti_idx` ON `refresh_token` (`access_jti`);
