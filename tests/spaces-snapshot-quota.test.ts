import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeSpaceEnv as makeEnv } from "./helpers/space-env";
import { applySpaceWrites, createLocalSpace } from "./helpers/space-adapters";
import { acquireSpaceSnapshot } from "./helpers/space-adapters";
import {
  GLOBAL_LEASE_EXPIRY_SQL,
  GLOBAL_LEASE_MAXIMUM_EXPIRY_SQL,
  OWNER_LEASE_EXPIRY_SQL,
  OWNER_LEASE_MAXIMUM_EXPIRY_SQL,
  pruneExpiredSpaceSnapshotLeases,
} from "../src/db/space-lease-expiry";

const DID = "did:example:test";
const SPACE = `at://${DID}/space/com.example.notes/quota`;
type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

async function fixture() {
  const env = await makeEnv();
  await createLocalSpace(env, SPACE);
  await applySpaceWrites(env, SPACE, DID, [{
    action: "create",
    collection: "com.example.note",
    rkey: "a",
    record: { $type: "com.example.note", text: "a" },
  }]);
  return env;
}

async function seedLeases(
  env: TestEnv,
  count: number,
  expiresAt: number,
  maximumExpiresAt: number,
) {
  const state = new Uint8Array(2048).buffer;
  const sql = `INSERT INTO space_snapshot_lease
    (id, token, renewal_nonce, space_ref, repo_did, epoch_id, generation, rev, set_hash, expires_at, maximum_expires_at)
    VALUES (?, ?, ?, ?, ?, ?, 1, '2222222222222', ?, ?, ?)`;
  await withLegacyLeaseInsert(env, () => env.ALTERAN_DB.batch(
    Array.from(
      { length: count },
      (_, index) =>
        env.ALTERAN_DB.prepare(sql).bind(
          `fake-${index}`,
          `token-${index}`,
          `nonce-${index}`,
          `at://${DID}/space/com.example.notes/fake${Math.floor(index / 16)}`,
          DID,
          `epoch-${index}`,
          state,
          expiresAt,
          maximumExpiresAt,
        ),
    ),
  ));
}

async function withLegacyLeaseInsert(env: TestEnv, action: () => Promise<unknown>) {
  const trigger = await env.ALTERAN_DB.prepare(
    "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'space_snapshot_owner_insert'",
  ).first<{ sql: string }>();
  if (!trigger?.sql) throw new Error('Missing snapshot owner trigger');
  await env.ALTERAN_DB.exec('DROP TRIGGER space_snapshot_owner_insert');
  try { await action(); } finally { await env.ALTERAN_DB.exec(trigger.sql.replace(/\n/g, ' ')); }
}

async function leaseCount(env: TestEnv): Promise<number> {
  const row = await env.ALTERAN_DB.prepare(
    "SELECT COUNT(*) AS count FROM space_snapshot_lease",
  ).first<{ count: number }>();
  return row?.count ?? -1;
}

describe("Space snapshot quotas and bounded expiry", () => {
  it("serializes concurrent acquisitions at the per-repo cap", async () => {
    const env = await fixture();
    for (let index = 0; index < 12; index++) {
      await acquireSpaceSnapshot(env, SPACE, DID);
    }
    const attempts = await Promise.allSettled(
      Array.from({ length: 8 }, () => acquireSpaceSnapshot(env, SPACE, DID)),
    );
    expect(attempts.filter((attempt) => attempt.status === "fulfilled"))
      .toHaveLength(4);
    expect(attempts.filter((attempt) => attempt.status === "rejected"))
      .toHaveLength(4);
    expect(await leaseCount(env)).toBe(16);
  });

  it("rejects acquisitions at the global cap across Spaces", async () => {
    const env = await fixture();
    const now = Math.floor(Date.now() / 1000);
    await seedLeases(env, 128, now + 600, now + 900);
    await expect(acquireSpaceSnapshot(env, SPACE, DID)).rejects.toThrow();
    expect(await leaseCount(env)).toBe(128);
  });

  it("commits bounded cleanup even when an upgrade starts above the global cap", async () => {
    const env = await fixture();
    const trigger = await env.ALTERAN_DB.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
    )
      .bind("space_snapshot_lease_quota").first<{ sql: string }>();
    if (!trigger?.sql) throw new Error("Missing quota trigger");
    await env.ALTERAN_DB.exec("DROP TRIGGER space_snapshot_lease_quota");
    const now = Math.floor(Date.now() / 1000);
    await seedLeases(env, 145, now - 1, now + 900);
    await env.ALTERAN_DB.exec(trigger.sql.replace(/\n/g, " "));
    await expect(acquireSpaceSnapshot(env, SPACE, DID)).rejects.toThrow();
    expect(await leaseCount(env)).toBe(137);
    await expect(acquireSpaceSnapshot(env, SPACE, DID)).rejects.toThrow();
    expect(await leaseCount(env)).toBe(129);
    await acquireSpaceSnapshot(env, SPACE, DID);
    expect(await leaseCount(env)).toBe(122);
  });

  it("makes bounded progress on both expiry deadlines", async () => {
    const env = await fixture();
    const now = Math.floor(Date.now() / 1000);
    const sql = `INSERT INTO space_snapshot_lease
      (id, token, renewal_nonce, space_ref, repo_did, epoch_id, generation, rev, set_hash, expires_at, maximum_expires_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, '2222222222222', ?, ?, ?)`;
    const state = new Uint8Array(2048).buffer;
    await withLegacyLeaseInsert(env, () => env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(sql).bind(
        "expiry",
        "a",
        "a",
        SPACE,
        DID,
        "a",
        state,
        now - 1,
        now + 100,
      ),
      env.ALTERAN_DB.prepare(sql).bind(
        "maximum",
        "b",
        "b",
        SPACE,
        DID,
        "b",
        state,
        now + 100,
        now - 1,
      ),
    ]));
    await pruneExpiredSpaceSnapshotLeases(env, SPACE, DID, 1);
    expect(await leaseCount(env)).toBe(0);
  });

  it("uses indexed candidate ranges and direct rowid deletes", async () => {
    const env = await fixture();
    const queries = [
      [GLOBAL_LEASE_EXPIRY_SQL, [1], "space_snapshot_lease_expiry"],
      [
        GLOBAL_LEASE_MAXIMUM_EXPIRY_SQL,
        [1],
        "space_snapshot_lease_maximum_expiry",
      ],
      [
        OWNER_LEASE_EXPIRY_SQL,
        [SPACE, DID, 1, SPACE, DID],
        "space_snapshot_lease_owner_expiry",
      ],
      [
        OWNER_LEASE_MAXIMUM_EXPIRY_SQL,
        [SPACE, DID, 1, SPACE, DID],
        "space_snapshot_lease_owner_maximum_expiry",
      ],
    ] as const;
    for (const [sql, parameters, index] of queries) {
      const plan = await env.ALTERAN_DB.prepare(`EXPLAIN QUERY PLAN ${sql}`)
        .bind(...parameters).all<{ detail: string }>();
      const detail = plan.results.map((row) => row.detail).join("\n");
      expect(detail).toContain("INTEGER PRIMARY KEY");
      expect(detail).toContain(index);
      expect(detail).not.toContain("USE TEMP B-TREE");
    }
  });
});
