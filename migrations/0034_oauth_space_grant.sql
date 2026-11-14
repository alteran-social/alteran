CREATE TABLE `oauth_space_grant` (
	`session_id` text PRIMARY KEY NOT NULL,
	`snapshot` text NOT NULL,
	`digest` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`session_id`) REFERENCES `oauth_session`(`id`) ON UPDATE no action ON DELETE no action,
	CONSTRAINT "oauth_space_grant_session_size" CHECK(length(CAST("oauth_space_grant"."session_id" AS BLOB)) BETWEEN 1 AND 128),
	CONSTRAINT "oauth_space_grant_snapshot" CHECK(length(CAST("oauth_space_grant"."snapshot" AS BLOB)) BETWEEN 1 AND 65536 AND json_valid("oauth_space_grant"."snapshot")),
	CONSTRAINT "oauth_space_grant_digest" CHECK(length("oauth_space_grant"."digest") = 64 AND "oauth_space_grant"."digest" NOT GLOB '*[^0-9a-f]*'),
	CONSTRAINT "oauth_space_grant_created" CHECK(typeof("oauth_space_grant"."created_at") = 'integer' AND "oauth_space_grant"."created_at" BETWEEN 0 AND 9007199254740991)
);
