import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import { makeEnv } from "./helpers/env";
import { advanceReplayClock } from "./helpers/oauth-clock";
import { getSecret, setSecret } from "../src/db/account";
import { cleanupExpiredOAuthReplaySecrets } from "../src/db/oauth-replay";
import { issueAuthorizationCode } from "../src/lib/oauth/issue-code";
import { consumeConsent, loadParSnapshot, saveConsent, savePar, type ParRecord } from "../src/lib/oauth/store";

const ID = "consentclock";
type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

async function captured(env: TestEnv, expiry?: number) {
  const now = Math.floor(Date.now() / 1000);
  const par: ParRecord = {
    client_id: "http://localhost", redirect_uri: "http://127.0.0.1/callback", code_challenge: "challenge",
    code_challenge_method: "S256", scope: "atproto", state: "state", dpopJkt: "key",
    clientAuthMethod: "none", createdAt: now, expiresAt: expiry ?? now + 300,
  };
  await savePar(env, ID, par);
  const snapshot = await loadParSnapshot(env, ID);
  if (!snapshot) throw new Error("Missing PAR");
  await saveConsent(env, ID, "csrf", expiry ?? now + 300, snapshot.value);
  const consent = await consumeConsent(env, ID, "csrf");
  if (!consent) throw new Error("Missing consent");
  return { snapshot, consent };
}

describe("consent issuance clock", () => {
  it("rejects equality at the durable D1 deadline and never revives it", async () => {
    const env = await makeEnv();
    const input = await captured(env);
    await advanceReplayClock(env, input.consent.expiresAt);
    expect(await issueAuthorizationCode(env, ID, input.snapshot, input.consent, "did:example:test")).toBeNull();
    const clock = await env.ALTERAN_DB.prepare("SELECT seconds FROM oauth_replay_clock WHERE id = 1")
      .first<{ seconds: number }>();
    expect(clock?.seconds).toBeGreaterThanOrEqual(input.consent.expiresAt);
    expect(await issueAuthorizationCode(env, ID, input.snapshot, input.consent, "did:example:test")).toBeNull();
    expect(await getSecret(env, `oauth:par:${ID}`)).toBe(input.snapshot.value);
  });

  it("withholds a committed code if Worker time expires before recovery", async () => {
    const env = await makeEnv();
    const input = await captured(env);
    const realNow = Date.now;
    const database = env.ALTERAN_DB;
    const delayed = new Proxy(database, { get(target, property) {
      if (property === "batch") return async (statements: Parameters<typeof database.batch>[0]) => {
        await database.batch(statements);
        Date.now = () => input.consent.expiresAt * 1000;
        throw new Error("Lost committed response");
      };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    } });
    try {
      expect(await issueAuthorizationCode({ ...env, ALTERAN_DB: delayed }, ID, input.snapshot, input.consent, "did:example:test"))
        .toBeNull();
      const clock = await env.ALTERAN_DB.prepare("SELECT seconds FROM oauth_replay_clock WHERE id = 1")
        .first<{ seconds: number }>();
      expect(clock?.seconds).toBeGreaterThanOrEqual(input.consent.expiresAt);
    } finally {
      Date.now = realNow;
    }
  });

  it("persists a late Worker observation even when the batch response arrives", async () => {
    const env = await makeEnv();
    const input = await captured(env);
    const realNow = Date.now;
    const database = env.ALTERAN_DB;
    const delayed = new Proxy(database, { get(target, property) {
      if (property === "batch") return async (statements: Parameters<typeof database.batch>[0]) => {
        const result = await database.batch(statements);
        Date.now = () => input.consent.expiresAt * 1000;
        return result;
      };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    } });
    try {
      expect(await issueAuthorizationCode({ ...env, ALTERAN_DB: delayed }, ID, input.snapshot, input.consent, "did:example:test"))
        .toBeNull();
      const clock = await env.ALTERAN_DB.prepare("SELECT seconds FROM oauth_replay_clock WHERE id = 1")
        .first<{ seconds: number }>();
      expect(clock?.seconds).toBeGreaterThanOrEqual(input.consent.expiresAt);
    } finally {
      Date.now = realNow;
    }
  });

  it("withholds a code when D1 crosses the deadline during a delayed batch", async () => {
    for (const loseResponse of [false, true]) {
      const env = await makeEnv();
      const database = env.ALTERAN_DB;
      const time = await database.prepare("SELECT unixepoch() AS now").first<{ now: number }>();
      if (!time) throw new Error("Missing D1 time");
      const deadline = time.now + 3;
      const input = await captured(env, deadline);
      const delayed = new Proxy(database, { get(target, property) {
        if (property === "batch") return async (statements: Parameters<typeof database.batch>[0]) => {
          for (;;) {
            const current = await database.prepare("SELECT unixepoch() AS now").first<{ now: number }>();
            if (current && current.now >= deadline) break;
            await new Promise((resolve) => setTimeout(resolve, 100));
          }
          const result = await database.batch(statements);
          if (loseResponse) throw new Error("Lost committed response");
          return result;
        };
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      } });
      const realNow = Date.now;
      try {
        Date.now = () => time.now * 1000;
        expect(await issueAuthorizationCode({ ...env, ALTERAN_DB: delayed }, ID, input.snapshot, input.consent, "did:example:test"))
          .toBeNull();
        const clock = await database.prepare("SELECT seconds FROM oauth_replay_clock WHERE id = 1")
          .first<{ seconds: number }>();
        expect(clock?.seconds).toBeGreaterThanOrEqual(deadline);
      } finally {
        Date.now = realNow;
      }
    }
  });

  it("withholds a committed code when the separate final clock update is skipped", async () => {
    const env = await makeEnv();
    const input = await captured(env);
    const database = env.ALTERAN_DB;
    const guarded = new Proxy(database, { get(target, property) {
      if (property === "batch") return async (statements: Parameters<typeof database.batch>[0]) => {
        await database.exec("CREATE TRIGGER skip_consent_final_clock BEFORE UPDATE ON oauth_replay_clock BEGIN SELECT RAISE(IGNORE); END");
        return database.batch(statements);
      };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    } });
    await expect(issueAuthorizationCode({ ...env, ALTERAN_DB: guarded }, ID, input.snapshot, input.consent, "did:example:test"))
      .rejects.toThrow();
    await database.exec("DROP TRIGGER skip_consent_final_clock");
    expect(await getSecret(env, `oauth:par:${ID}`)).not.toBe(input.snapshot.value);
    expect((await database.prepare("SELECT COUNT(*) AS n FROM secret WHERE key GLOB 'oauth:code:*'")
      .first<{ n: number }>())?.n).toBe(1);
  });

  it("withholds the code if a final clock trigger removes it", async () => {
    const env = await makeEnv();
    const input = await captured(env);
    const database = env.ALTERAN_DB;
    const guarded = new Proxy(database, { get(target, property) {
      if (property === "batch") return async (statements: Parameters<typeof database.batch>[0]) => {
        await database.exec(`CREATE TRIGGER remove_code_after_final_clock AFTER UPDATE ON oauth_replay_clock
          BEGIN DELETE FROM secret WHERE key GLOB 'oauth:code:*'; END`.replace(/\n/g, " "));
        return database.batch(statements);
      };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    } });
    expect(await issueAuthorizationCode({ ...env, ALTERAN_DB: guarded }, ID, input.snapshot, input.consent, "did:example:test"))
      .toBeNull();
    await database.exec("DROP TRIGGER remove_code_after_final_clock");
    expect(await getSecret(env, `oauth:par:${ID}`)).not.toBe(input.snapshot.value);
    expect((await database.prepare("SELECT COUNT(*) AS n FROM secret WHERE key GLOB 'oauth:code:*'")
      .first<{ n: number }>())?.n).toBe(0);
  });

  it("leaves a competing PAR untouched and rolls back a skipped receipt", async () => {
    const env = await makeEnv();
    const input = await captured(env);
    await setSecret(env, `oauth:par:${ID}`, JSON.stringify({ other: "winner" }));
    expect(await issueAuthorizationCode(env, ID, input.snapshot, input.consent, "did:example:test")).toBeNull();
    expect(await getSecret(env, `oauth:par:${ID}`)).toBe(JSON.stringify({ other: "winner" }));
    await setSecret(env, `oauth:par:${ID}`, input.snapshot.value);
    await env.ALTERAN_DB.exec(`CREATE TRIGGER skip_consent_receipt BEFORE INSERT ON secret
      WHEN NEW.key GLOB 'oauth:dpop:jti:consent:*' BEGIN SELECT RAISE(IGNORE); END`.replace(/\n/g, " "));
    await expect(issueAuthorizationCode(env, ID, input.snapshot, input.consent, "did:example:test")).rejects.toThrow();
    expect(await getSecret(env, `oauth:par:${ID}`)).toBe(input.snapshot.value);
  });

  it("cleans an issuance receipt through the indexed replay sweep after its lifetime", async () => {
    const env = await makeEnv();
    const input = await captured(env);
    expect(await issueAuthorizationCode(env, ID, input.snapshot, input.consent, "did:example:test")).toBeTruthy();
    const count = () => env.ALTERAN_DB.prepare("SELECT COUNT(*) AS n FROM secret WHERE key GLOB 'oauth:dpop:jti:consent:*'")
      .first<{ n: number }>();
    expect((await count())?.n).toBe(1);
    await advanceReplayClock(env, input.consent.createdAt + 305);
    expect(await cleanupExpiredOAuthReplaySecrets(env)).toBeGreaterThanOrEqual(1);
    expect((await count())?.n).toBe(0);
  });

  it("rolls back a code if the logical clock advances during its transaction", async () => {
    const env = await makeEnv();
    const input = await captured(env);
    await env.ALTERAN_DB.exec(`CREATE TRIGGER advance_consent_clock AFTER INSERT ON secret
      WHEN NEW.key GLOB 'oauth:dpop:jti:consent:*' BEGIN
        UPDATE oauth_replay_clock SET seconds = seconds + 301 WHERE id = 1;
      END`.replace(/\n/g, " "));
    await expect(issueAuthorizationCode(env, ID, input.snapshot, input.consent, "did:example:test")).rejects.toThrow();
    expect(await getSecret(env, `oauth:par:${ID}`)).toBe(input.snapshot.value);
    const codes = await env.ALTERAN_DB.prepare("SELECT COUNT(*) AS n FROM secret WHERE key GLOB 'oauth:code:*'")
      .first<{ n: number }>();
    expect(codes?.n).toBe(0);
  });
});
