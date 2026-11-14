CREATE TABLE `space_commit_assertion` (
	`mutation_id` text PRIMARY KEY NOT NULL,
	`valid` integer NOT NULL,
	CONSTRAINT "space_commit_assertion_valid" CHECK("space_commit_assertion"."valid" = 1)
);
