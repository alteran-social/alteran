CREATE TABLE `oauth_replay_clock` (
	`id` integer PRIMARY KEY NOT NULL,
	`seconds` integer NOT NULL,
	`nonce` text NOT NULL,
	CONSTRAINT "oauth_replay_clock_singleton" CHECK("oauth_replay_clock"."id" = 1),
	CONSTRAINT "oauth_replay_clock_seconds" CHECK(typeof("oauth_replay_clock"."seconds") = 'integer' AND "oauth_replay_clock"."seconds" BETWEEN 0 AND 9007199254740991),
	CONSTRAINT "oauth_replay_clock_nonce" CHECK(length("oauth_replay_clock"."nonce") = 32)
);
--> statement-breakpoint
INSERT INTO oauth_replay_clock (id, seconds, nonce)
VALUES (1, unixepoch(), '00000000000000000000000000000000');
--> statement-breakpoint
CREATE TRIGGER oauth_replay_clock_no_insert BEFORE INSERT ON oauth_replay_clock
BEGIN SELECT RAISE(ABORT, 'OAuth replay clock already initialized'); END;
--> statement-breakpoint
CREATE TRIGGER oauth_replay_clock_no_delete BEFORE DELETE ON oauth_replay_clock
BEGIN SELECT RAISE(ABORT, 'OAuth replay clock cannot be deleted'); END;
--> statement-breakpoint
CREATE TRIGGER oauth_replay_clock_monotonic BEFORE UPDATE ON oauth_replay_clock
WHEN NEW.id <> OLD.id OR NEW.seconds < OLD.seconds OR NEW.seconds < unixepoch()
BEGIN SELECT RAISE(ABORT, 'OAuth replay clock cannot move backwards'); END;
