ALTER TABLE `space_epoch` ADD `owner_incarnation` text;--> statement-breakpoint
CREATE INDEX `space_epoch_bound_incarnation` ON `space_epoch` (`owner_incarnation`) WHERE "space_epoch"."owner_incarnation" IS NOT NULL;--> statement-breakpoint
ALTER TABLE `space_mutation_attempt` ADD `owner_incarnation` text;--> statement-breakpoint
CREATE INDEX `space_mutation_attempt_bound_incarnation` ON `space_mutation_attempt` (`owner_incarnation`) WHERE "space_mutation_attempt"."owner_incarnation" IS NOT NULL;--> statement-breakpoint
ALTER TABLE `space_personal_creation_attempt` ADD `authority_incarnation` text;--> statement-breakpoint
CREATE INDEX `space_personal_creation_bound_incarnation` ON `space_personal_creation_attempt` (`authority_incarnation`) WHERE "space_personal_creation_attempt"."authority_incarnation" IS NOT NULL;--> statement-breakpoint
ALTER TABLE `space_personal_policy` ADD `authority_incarnation` text;--> statement-breakpoint
CREATE INDEX `space_personal_policy_bound_incarnation` ON `space_personal_policy` (`authority_incarnation`) WHERE "space_personal_policy"."authority_incarnation" IS NOT NULL;--> statement-breakpoint
CREATE INDEX `space_gc_attempt_owner` ON `space_gc_attempt` (`space_ref`,`repo_did`);--> statement-breakpoint
CREATE INDEX `space_personal_deletion_attempt_owner` ON `space_personal_deletion_attempt` (`space_ref`,`authority_did`);