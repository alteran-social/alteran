import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import { makeEnv } from "./helpers/env";
import {
  cleanupExpiredOAuthReplaySecrets,
  consumeOAuthReplay,
  consumeOAuthResourceReplay,
  OAUTH_REPLAY_ADMISSION_CLEANUP_SQL,
  OAUTH_REPLAY_AMORTIZED_SWEEP_SQL,
  OAUTH_REPLAY_CLEANUP_LIMIT,
  OAUTH_REPLAY_SWEEP_SQL,
} from "../src/db/oauth-replay";
import { getSecret, setSecret } from "../src/db/account";
import { advanceReplayClock } from "./helpers/oauth-clock";

describe("OAuth replay cleanup", () => {
  it("uses indexed paths for an admission and the bounded sweep", async () => {
    const env = await makeEnv();
    const nonce = "0".repeat(32);
    const admission = await env.ALTERAN_DB.prepare(
      `EXPLAIN QUERY PLAN ${OAUTH_REPLAY_ADMISSION_CLEANUP_SQL}`,
    )
      .bind(nonce, "oauth:dpop:jti:authz:example", 300).all<
      { detail: string }
    >();
    const sweep = await env.ALTERAN_DB.prepare(
      `EXPLAIN QUERY PLAN ${OAUTH_REPLAY_SWEEP_SQL}`,
    )
      .bind(nonce, Math.floor(Date.now() / 1000), OAUTH_REPLAY_CLEANUP_LIMIT)
      .all<{ detail: string }>();
    const now = Math.floor(Date.now() / 1000);
    const amortized = await env.ALTERAN_DB.prepare(
      `EXPLAIN QUERY PLAN ${OAUTH_REPLAY_AMORTIZED_SWEEP_SQL}`,
    )
      .bind(
        "oauth:dpop:jti:authz:example",
        "{}",
        now,
        300,
        now,
        30,
        null,
        null,
        null,
        300,
        0,
        "",
        "",
        "",
        "",
        "",
        "",
        0,
        0,
        0,
        0,
        now - 30,
        nonce,
      ).all<{ detail: string }>();
    expect(
      admission.results.some(({ detail }) =>
        detail.includes("SEARCH secret USING INDEX")
      ),
    ).toBe(true);
    expect(
      sweep.results.some(({ detail }) =>
        detail.includes("oauth_replay_expiry") && detail.includes("SEARCH")
      ),
    ).toBe(true);
    expect(
      amortized.results.some(({ detail }) =>
        detail.includes("oauth_replay_expiry") && detail.includes("SEARCH")
      ),
    ).toBe(true);
  });

  it("drains at most one bounded page while keeping unknown and live entries", async () => {
    const env = await makeEnv();
    const clock = await env.ALTERAN_DB.prepare(
      "SELECT seconds FROM oauth_replay_clock WHERE id = 1",
    )
      .first<{ seconds: number }>();
    if (!clock) throw new Error("Missing replay clock");
    const now = clock.seconds;
    const stale = JSON.stringify({ iat: now - 700, exp: now - 200 });
    const live = JSON.stringify({ iat: now - 30, exp: now + 270 });
    const malformed = "{";
    const unknown = JSON.stringify({ iat: "old", exp: "old" });
    const database = env.ALTERAN_DB;
    for (let start = 0; start < 640; start += 80) {
      await database.batch(
        Array.from({ length: 80 }, (_, index) =>
          database.prepare(
            "INSERT INTO secret (key, value, updated_at) VALUES (?, ?, ?)",
          ).bind(
            `oauth:dpop:jti:authz:stale-${
              String(start + index).padStart(4, "0")
            }`,
            stale,
            0,
          )),
      );
    }
    await setSecret(env, "oauth:dpop:jti:authz:live", live);
    await setSecret(env, "oauth:dpop:jti:authz:malformed", malformed);
    await setSecret(env, "oauth:dpop:jti:authz:unknown", unknown);
    await setSecret(env, "unrelated:keep", stale);
    expect(await cleanupExpiredOAuthReplaySecrets(env)).toBe(
      OAUTH_REPLAY_CLEANUP_LIMIT,
    );
    const count = await database.prepare(
      "SELECT COUNT(*) AS n FROM secret WHERE key GLOB 'oauth:dpop:jti:authz:stale-*'",
    )
      .first<{ n: number }>();
    expect(count?.n).toBe(640 - OAUTH_REPLAY_CLEANUP_LIMIT);
    expect(await cleanupExpiredOAuthReplaySecrets(env)).toBe(
      640 - OAUTH_REPLAY_CLEANUP_LIMIT,
    );
    expect(await getSecret(env, "oauth:dpop:jti:authz:live")).toBe(live);
    expect(await getSecret(env, "oauth:dpop:jti:authz:malformed")).toBe(
      malformed,
    );
    expect(await getSecret(env, "oauth:dpop:jti:authz:unknown")).toBe(unknown);
    expect(await getSecret(env, "unrelated:keep")).toBe(stale);
  });

  it("retains a legacy proof through its final valid second", async () => {
    const env = await makeEnv();
    const clock = await env.ALTERAN_DB.prepare(
      "SELECT seconds FROM oauth_replay_clock WHERE id = 1",
    )
      .first<{ seconds: number }>();
    if (!clock) throw new Error("Missing replay clock");
    const key = "oauth:dpop:jti:authz:legacy-boundary";
    const boundary = clock.seconds + 60;
    await advanceReplayClock(env, boundary);
    await setSecret(
      env,
      key,
      JSON.stringify({ iat: boundary - 300, exp: boundary - 1 }),
    );
    expect(await cleanupExpiredOAuthReplaySecrets(env)).toBe(0);
    expect(await getSecret(env, key)).not.toBeNull();
    await advanceReplayClock(env, boundary + 1);
    expect(await cleanupExpiredOAuthReplaySecrets(env)).toBe(1);
    expect(await getSecret(env, key)).toBeNull();
  });

  it("replaces an expired matching key and removes one older marker", async () => {
    const env = await makeEnv();
    const clock = await env.ALTERAN_DB.prepare(
      "SELECT seconds FROM oauth_replay_clock WHERE id = 1",
    )
      .first<{ seconds: number }>();
    if (!clock) throw new Error("Missing replay clock");
    const key = "oauth:dpop:jti:authz:matching";
    const other = "oauth:dpop:jti:authz:other";
    const stale = JSON.stringify({
      iat: clock.seconds - 700,
      exp: clock.seconds - 200,
    });
    await setSecret(env, key, stale);
    await setSecret(env, other, stale);
    expect(
      (await consumeOAuthReplay(env, key, {
        tag: "dpop",
        issuedAt: clock.seconds,
      })).tag,
    ).toBe("accepted");
    expect(await getSecret(env, other)).toBeNull();
    expect(await getSecret(env, key)).not.toBe(stale);
  });

  it("removes at most one stale marker per concurrent successful admission", async () => {
    const env = await makeEnv();
    const now = Math.floor(Date.now() / 1000);
    const stale = JSON.stringify({ iat: now - 1000, exp: now - 600 });
    for (let index = 0; index < 25; index++) {
      await setSecret(env, `oauth:dpop:jti:authz:backlog-${index}`, stale);
    }
    for (let round = 0; round < 2; round++) {
      const attempts = await Promise.all(
        Array.from(
          { length: 8 },
          (_, index) =>
            consumeOAuthReplay(
              env,
              `oauth:dpop:jti:authz:new-${round}-${index}`,
              {
                tag: "dpop",
                issuedAt: now,
              },
            ),
        ),
      );
      expect(attempts.every((result) => result.tag === "accepted")).toBe(true);
    }
    const count = await env.ALTERAN_DB.prepare(
      "SELECT COUNT(*) AS n FROM secret WHERE key GLOB 'oauth:dpop:jti:authz:backlog-*'",
    )
      .first<{ n: number }>();
    expect(count?.n).toBe(9);
  });

  it("does not sweep on invalid, replayed or revoked-session admissions", async () => {
    const env = await makeEnv();
    const now = Math.floor(Date.now() / 1000);
    const key = "oauth:dpop:jti:authz:reused-proof";
    expect(
      (await consumeOAuthReplay(env, key, { tag: "dpop", issuedAt: now })).tag,
    ).toBe("accepted");
    const staleKey = "oauth:dpop:jti:authz:must-remain";
    const stale = JSON.stringify({ iat: now - 1000, exp: now - 600 });
    await setSecret(env, staleKey, stale);
    expect(
      (await consumeOAuthReplay(env, key, { tag: "dpop", issuedAt: now })).tag,
    ).toBe("replayed");
    expect(
      (await consumeOAuthReplay(env, "oauth:dpop:jti:authz:future-proof", {
        tag: "dpop",
        issuedAt: now + 10_000_000,
      })).tag,
    ).toBe("expired");
    expect(
      (await consumeOAuthResourceReplay(env, "missing-session-proof", now, {
        sessionId: "missing",
        accessJti: "access",
        did: "did:example:test",
        clientId: "client",
        jkt: "key",
        scope: "atproto",
        expiresAt: now + 60,
      })).tag,
    ).toBe("invalidSession");
    expect(await getSecret(env, staleKey)).toBe(stale);
  });

  it("does not sweep when an ignored insertion has a trigger-created marker", async () => {
    const env = await makeEnv();
    const now = Math.floor(Date.now() / 1000);
    const staleKey = "oauth:dpop:jti:authz:must-remain";
    const stale = JSON.stringify({ iat: now - 1000, exp: now - 600 });
    await setSecret(env, staleKey, stale);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER ignored_insert_with_side_effect BEFORE INSERT ON secret
      WHEN NEW.key GLOB 'oauth:dpop:jti:authz:new-*' BEGIN
        INSERT OR IGNORE INTO secret (key, value, updated_at) VALUES (NEW.key, NEW.value, NEW.updated_at);
        SELECT RAISE(IGNORE);
      END`,
    ).run();
    expect(
      (await consumeOAuthReplay(env, "oauth:dpop:jti:authz:new-proof", {
        tag: "dpop",
        issuedAt: now,
      })).tag,
    ).not.toBe("accepted");
    expect(await getSecret(env, staleKey)).toBe(stale);
  });

  it("does not sweep beyond the conservative proof-derived bound", async () => {
    const env = await makeEnv();
    const now = Math.floor(Date.now() / 1000);
    const staleKey = "oauth:dpop:jti:authz:recently-expired";
    const stale = JSON.stringify({ iat: now - 620, exp: now - 320 });
    await setSecret(env, staleKey, stale);
    expect(
      (await consumeOAuthReplay(env, "oauth:dpop:jti:authz:boundary-proof", {
        tag: "dpop",
        issuedAt: now - 300,
      })).tag,
    ).toBe("accepted");
    expect(await getSecret(env, staleKey)).toBe(stale);
  });

  it("does not sweep when an assertion expires during marker insertion", async () => {
    const env = await makeEnv();
    const now = Math.floor(Date.now() / 1000);
    const staleKey = "oauth:dpop:jti:authz:must-remain";
    const stale = JSON.stringify({ iat: 1, exp: 1 });
    await setSecret(env, staleKey, stale);
    await env.ALTERAN_DB.prepare(
      `CREATE TRIGGER expire_assertion_during_admission AFTER INSERT ON secret
      WHEN NEW.key GLOB 'oauth:client-assertion:jti:*' BEGIN
        UPDATE oauth_replay_clock SET seconds = seconds + 60 WHERE id = 1;
      END`,
    ).run();
    expect(
      (await consumeOAuthReplay(
        env,
        "oauth:client-assertion:jti:client:proof",
        {
          tag: "assertion",
          issuedAt: now,
          expiresAt: now + 30,
        },
      )).tag,
    ).toBe("expired");
    expect(await getSecret(env, staleKey)).toBe(stale);
  });
});
