CREATE TABLE `space_gc_attempt` (
	`id` text PRIMARY KEY NOT NULL,
	`space_ref` text NOT NULL,
	`repo_did` text NOT NULL,
	`epoch_id` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `space_mutation_attempt` (
	`mutation_id` text PRIMARY KEY NOT NULL,
	`space_ref` text NOT NULL,
	`repo_did` text NOT NULL,
	`epoch_id` text NOT NULL,
	`generation` integer NOT NULL,
	`rev` text NOT NULL,
	`set_hash` blob NOT NULL,
	CONSTRAINT "space_mutation_attempt_generation" CHECK("space_mutation_attempt"."generation" >= 1),
	CONSTRAINT "space_mutation_attempt_hash_size" CHECK(length("space_mutation_attempt"."set_hash") = 2048)
);
