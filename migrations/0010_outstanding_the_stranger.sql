CREATE TABLE IF NOT EXISTS `actor_preferences` (
	`did` text PRIMARY KEY NOT NULL,
	`json` text NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `chat_convo` (
	`id` text PRIMARY KEY NOT NULL,
	`rev` text NOT NULL,
	`status` text DEFAULT 'accepted' NOT NULL,
	`muted` integer DEFAULT 0 NOT NULL,
	`unread_count` integer DEFAULT 0 NOT NULL,
	`last_message_json` text,
	`last_reaction_json` text,
	`updated_at` integer NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `chat_convo_member` (
	`convo_id` text NOT NULL,
	`did` text NOT NULL,
	`handle` text NOT NULL,
	`display_name` text,
	`avatar` text,
	`position` integer DEFAULT 0 NOT NULL,
	PRIMARY KEY(`convo_id`, `did`)
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `chat_convo_member_did_idx` ON `chat_convo_member` (`did`);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `rate_limit` (
	`ip` text NOT NULL,
	`bucket` text NOT NULL,
	`window` integer NOT NULL,
	`count` integer NOT NULL,
	PRIMARY KEY(`ip`, `bucket`, `window`)
);
