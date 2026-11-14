CREATE INDEX `space_record_version_gc_candidates` ON `space_record_version` (`epoch_id`,`space_ref`,`repo_did`,`until_generation`,`path`,`from_generation`) WHERE "space_record_version"."until_generation" IS NOT NULL;--> statement-breakpoint
CREATE INDEX `space_snapshot_lease_epoch_generation` ON `space_snapshot_lease` (`epoch_id`,`space_ref`,`repo_did`,`generation`);--> statement-breakpoint
CREATE INDEX `space_snapshot_lease_owner_expiry` ON `space_snapshot_lease` (`space_ref`,`repo_did`,`expires_at`,`id`);--> statement-breakpoint
CREATE INDEX `space_snapshot_lease_owner_maximum_expiry` ON `space_snapshot_lease` (`space_ref`,`repo_did`,`maximum_expires_at`,`id`);--> statement-breakpoint
CREATE INDEX `space_snapshot_lease_expiry` ON `space_snapshot_lease` (`expires_at`,`id`);--> statement-breakpoint
CREATE INDEX `space_snapshot_lease_maximum_expiry` ON `space_snapshot_lease` (`maximum_expires_at`,`id`);