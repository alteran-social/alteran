CREATE TABLE `account_space_incarnation_init` (
	`id` integer PRIMARY KEY NOT NULL,
	`did` text NOT NULL,
	`incarnation` text NOT NULL,
	CONSTRAINT "account_space_incarnation_init_singleton" CHECK("account_space_incarnation_init"."id" = 1)
);
--> statement-breakpoint
ALTER TABLE `account` ADD `space_incarnation` text;--> statement-breakpoint
CREATE UNIQUE INDEX `account_space_incarnation_unique` ON `account` (`space_incarnation`);