import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import { makeEnv } from "./helpers/env";
import { createOAuthSession } from "./helpers/oauth-store";
import { Miniflare } from "miniflare";
import { readFileSync } from "node:fs";

describe("Space grant database guards", () => {
  it("requires a bounded lowercase digest and a matching session", async () => {
    const env = await makeEnv();
    await createOAuthSession(env, {
      id: "session", did: "did:example:test", clientId: "https://client.example/metadata.json",
      clientAuthMethod: "none", dpopJkt: "a".repeat(43), scope: "atproto",
      currentRefreshTokenId: "refresh", accessJti: "access", expiresAt: Math.floor(Date.now() / 1000) + 600,
    });
    const insert = (id: string, digest: string) => env.ALTERAN_DB.prepare(
      "INSERT INTO oauth_space_grant (session_id, snapshot, digest, created_at) VALUES (?, '{}', ?, 1)",
    ).bind(id, digest).run();
    await expect(insert("missing", "a".repeat(64))).rejects.toThrow();
    await expect(insert("session", "a".repeat(64) + "\0" + "x".repeat(400_000))).rejects.toThrow();
    await expect(insert("session", "a".repeat(32) + "\0" + "x".repeat(31))).rejects.toThrow();
    await expect(insert("session", "A".repeat(64))).rejects.toThrow();
    await expect(env.ALTERAN_DB.prepare("INSERT INTO oauth_space_grant VALUES (?, ?, ?, 1)")
      .bind("session", new TextEncoder().encode("{}"), "a".repeat(64)).run()).rejects.toThrow();
    await expect(env.ALTERAN_DB.prepare("INSERT INTO oauth_space_grant VALUES (?, '{}', ?, 1)")
      .bind("session", new TextEncoder().encode("a".repeat(64))).run()).rejects.toThrow();
    await insert("session", "a".repeat(64));
    const row = await env.ALTERAN_DB.prepare("SELECT snapshot, digest FROM oauth_space_grant WHERE session_id = ?")
      .bind("session").first<{ snapshot: string; digest: string }>();
    expect(row).toEqual({ snapshot: "{}", digest: "a".repeat(64) });
  });

  it("rejects an upgrade when a grant was inserted before the guards", async () => {
    const service = new Miniflare({
      d1Databases: { DB: ":memory:" }, compatibilityDate: "2025-10-02",
      script: "export default { fetch: () => new Response('ok') }", modules: true,
    });
    try {
      await service.ready;
      const db = await service.getD1Database("DB");
      await db.exec("CREATE TABLE oauth_session (id TEXT PRIMARY KEY NOT NULL)");
      await db.exec(readFileSync(new URL("../migrations/0034_oauth_space_grant.sql", import.meta.url), "utf8").replace(/\n/g, " "));
      await db.prepare("INSERT INTO oauth_session (id) VALUES (?)").bind("session").run();
      await db.prepare("INSERT INTO oauth_space_grant VALUES (?, '{}', ?, 1)")
        .bind("session", "a".repeat(64)).run();
      const assertion = readFileSync(new URL("../migrations/0035_oauth_space_grant_guards.sql", import.meta.url), "utf8")
        .split("--> statement-breakpoint")[0].replace(/\n/g, " ");
      await expect(db.exec(assertion)).rejects.toThrow();
    } finally {
      await service.dispose();
    }
  });

  it("cannot change, replace or delete an issued snapshot", async () => {
    const env = await makeEnv();
    await createOAuthSession(env, {
      id: "session", did: "did:example:test", clientId: "https://client.example/metadata.json",
      clientAuthMethod: "none", dpopJkt: "a".repeat(43), scope: "atproto",
      currentRefreshTokenId: "refresh", accessJti: "access", expiresAt: Math.floor(Date.now() / 1000) + 600,
    });
    await env.ALTERAN_DB.prepare("INSERT INTO oauth_space_grant VALUES (?, '{}', ?, 1)")
      .bind("session", "a".repeat(64)).run();
    await expect(env.ALTERAN_DB.prepare("UPDATE oauth_space_grant SET digest = ? WHERE session_id = ?")
      .bind("b".repeat(64), "session").run()).rejects.toThrow();
    await expect(env.ALTERAN_DB.prepare("DELETE FROM oauth_space_grant WHERE session_id = ?")
      .bind("session").run()).rejects.toThrow();
    await expect(env.ALTERAN_DB.prepare("INSERT OR REPLACE INTO oauth_space_grant VALUES (?, '{}', ?, 1)")
      .bind("session", "b".repeat(64)).run()).rejects.toThrow();
    const row = await env.ALTERAN_DB.prepare("SELECT snapshot, digest FROM oauth_space_grant WHERE session_id = ?")
      .bind("session").first<{ snapshot: string; digest: string }>();
    expect(row).toEqual({ snapshot: "{}", digest: "a".repeat(64) });
  });
});
