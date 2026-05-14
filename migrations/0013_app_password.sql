CREATE TABLE `app_password` (
	`did` text NOT NULL,
	`name` text NOT NULL,
	`password_scrypt` text NOT NULL,
	`privileged` integer DEFAULT false NOT NULL,
	`created_at` integer NOT NULL,
	PRIMARY KEY(`did`, `name`)
);
--> statement-breakpoint
CREATE INDEX `app_password_did_idx` ON `app_password` (`did`);