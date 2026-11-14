import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import * as dagCbor from "@ipld/dag-cbor";
import { makeSpaceEnv as makeEnv } from "./helpers/space-env";
import { applySpaceWrites, createLocalSpace } from "./helpers/space-adapters";
import {
  acquireSpaceSnapshot,
  readSpaceSnapshotPage,
  releaseSpaceSnapshot,
} from "./helpers/space-adapters";
import { pruneExpiredSpaceSnapshotLeases } from "../src/db/space-lease-expiry";
import { pruneSpaceRecordVersionsPage } from "./helpers/space-adapters";
import { nextSpaceRevision } from "../src/db/space-tid";
import { SpaceStorageError } from "../src/db/space-types";
import { spaceSetHashDigest } from "../src/lib/spaces/lthash";

const DID = "did:example:test";
const COLLECTION = "com.example.note";
const SPACE = `at://${DID}/space/com.example.notes/snapshot`;
type TestEnv = Awaited<ReturnType<typeof makeEnv>>;
const pruneSpaceRecordVersions = async (
  ...args: Parameters<typeof pruneSpaceRecordVersionsPage>
) => (await pruneSpaceRecordVersionsPage(...args)).pruned;

async function fixture() {
  const env = await makeEnv();
  await createLocalSpace(env, SPACE);
  await applySpaceWrites(env, SPACE, DID, [{
    action: "create",
    collection: COLLECTION,
    rkey: "a",
    record: { $type: COLLECTION, text: "old" },
  }]);
  return { env, lease: await acquireSpaceSnapshot(env, SPACE, DID) };
}

async function update(env: TestEnv) {
  await applySpaceWrites(env, SPACE, DID, [{
    action: "update",
    collection: COLLECTION,
    rkey: "a",
    record: { $type: COLLECTION, text: "new" },
  }]);
}

async function rejectsCode(action: () => Promise<unknown>, code: string) {
  try {
    await action();
    throw new Error("Expected a storage error");
  } catch (error) {
    expect(error).toBeInstanceOf(SpaceStorageError);
    expect((error as SpaceStorageError).code).toBe(code);
  }
}

function clockEnv(env: TestEnv, seconds: number): TestEnv {
  const database = env.ALTERAN_DB;
  return {
    ...env,
    ALTERAN_DB: new Proxy(database, {
      get(target, property) {
        if (property === "prepare") {
          return (sql: string) =>
            target.prepare(sql.replaceAll("unixepoch()", String(seconds)));
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }),
  };
}

function captureTransfers(env: TestEnv) {
  const database = env.ALTERAN_DB;
  let largest = 0;
  const wrapped = new Proxy(database, {
    get(target, property) {
      if (property === "batch") {
        return async (statements: Parameters<typeof database.batch>[0]) => {
          const results = await database.batch(statements);
          largest = Math.max(largest, JSON.stringify(results).length);
          return results;
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { env: { ...env, ALTERAN_DB: wrapped }, largest: () => largest };
}

function losePurgeResponse(env: TestEnv): TestEnv {
  const database = env.ALTERAN_DB;
  return {
    ...env,
    ALTERAN_DB: new Proxy(database, {
      get(target, property) {
        if (property === "batch") {
          return async (statements: Parameters<typeof database.batch>[0]) => {
            await database.batch(statements);
            throw new Error("Lost purge response");
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }),
  };
}

describe("Space snapshot integrity and expiry", () => {
  it("rejects a changed commit revision, hash state or digest", async () => {
    const { env, lease } = await fixture();
    await rejectsCode(
      () =>
        readSpaceSnapshotPage(env, {
          ...lease,
          rev: nextSpaceRevision(lease.rev),
        }, null),
      "SpaceSnapshotUnavailable",
    );
    const state = Uint8Array.from(lease.setHash);
    state[0] ^= 1;
    await rejectsCode(
      () =>
        readSpaceSnapshotPage(env, {
          ...lease,
          setHash: state,
          data: spaceSetHashDigest(state),
        }, null),
      "SpaceSnapshotUnavailable",
    );
    const data = Uint8Array.from(lease.data);
    data[0] ^= 1;
    await rejectsCode(
      () => readSpaceSnapshotPage(env, { ...lease, data }, null),
      "SpaceSnapshotUnavailable",
    );
  });

  it("rejects oversized and non-string snapshot cursors", async () => {
    const { env, lease } = await fixture();
    await rejectsCode(
      () => readSpaceSnapshotPage(env, lease, "x".repeat(1_000_000)),
      "InvalidRequest",
    );
    await rejectsCode(
      () => readSpaceSnapshotPage(env, lease, 42 as any),
      "InvalidRequest",
    );
  });

  it("captures hash state and digest before asynchronous account resolution", async () => {
    const { env, lease } = await fixture();
    let resolveDid: (value: string) => void = () => {};
    const did = new Promise<string>((resolve) => resolveDid = resolve);
    const mutable = {
      ...lease,
      setHash: Uint8Array.from(lease.setHash),
      data: Uint8Array.from(lease.data),
    };
    const pending = readSpaceSnapshotPage(
      {
        ...env,
        PDS_DID: { get: () => did },
      },
      mutable,
      null,
    );
    mutable.setHash[0] ^= 1;
    mutable.data[0] ^= 1;
    resolveDid(DID);
    expect(dagCbor.decode((await pending).records[0].value)).toMatchObject({
      text: "old",
    });
  });

  it("rejects oversized and shared lease buffers before copying them", async () => {
    const { env, lease } = await fixture();
    await rejectsCode(
      () =>
        readSpaceSnapshotPage(env, {
          ...lease,
          setHash: new Uint8Array(2_000_000),
        }, null),
      "SpaceSnapshotUnavailable",
    );
    await rejectsCode(
      () =>
        readSpaceSnapshotPage(env, {
          ...lease,
          data: new Uint8Array(2_000_000),
        }, null),
      "SpaceSnapshotUnavailable",
    );
    if (typeof SharedArrayBuffer !== "undefined") {
      const shared = new Uint8Array(new SharedArrayBuffer(2048));
      shared.set(lease.setHash);
      await rejectsCode(
        () => readSpaceSnapshotPage(env, { ...lease, setHash: shared }, null),
        "SpaceSnapshotUnavailable",
      );
    }
  });

  it("rejects a stored lease whose revision or hash was changed", async () => {
    const { env, lease } = await fixture();
    await env.ALTERAN_DB.exec(
      "DROP TRIGGER space_snapshot_lease_identity_immutable",
    );
    await env.ALTERAN_DB.prepare(
      "UPDATE space_snapshot_lease SET rev = ? WHERE id = ?",
    )
      .bind(nextSpaceRevision(lease.rev), lease.id).run();
    await rejectsCode(
      () => readSpaceSnapshotPage(env, lease, null),
      "SpaceSnapshotUnavailable",
    );
    const state = Uint8Array.from(lease.setHash);
    state[0] ^= 1;
    await env.ALTERAN_DB.prepare(
      "UPDATE space_snapshot_lease SET rev = ?, set_hash = ? WHERE id = ?",
    )
      .bind(lease.rev, state.buffer, lease.id).run();
    await rejectsCode(
      () => readSpaceSnapshotPage(env, lease, null),
      "SpaceSnapshotUnavailable",
    );
  });

  it("prevents reassignment or replacement of a live lease", async () => {
    const { env, lease } = await fixture();
    await expect(
      env.ALTERAN_DB.prepare(
        "UPDATE space_snapshot_lease SET space_ref = ? WHERE id = ?",
      )
        .bind(`${SPACE}-other`, lease.id).run(),
    ).rejects.toThrow();
    await expect(
      env.ALTERAN_DB.prepare(`INSERT OR REPLACE INTO space_snapshot_lease
      (id, token, renewal_nonce, space_ref, repo_did, epoch_id, generation, rev, set_hash, expires_at, maximum_expires_at)
      SELECT id, token, renewal_nonce, space_ref, repo_did, epoch_id, generation, rev, set_hash, expires_at, maximum_expires_at
      FROM space_snapshot_lease WHERE id = ?`).bind(lease.id).run(),
    ).rejects.toThrow();
    expect((await readSpaceSnapshotPage(env, lease, null)).records)
      .toHaveLength(1);
  });
  it("does not transfer oversized TEXT disguised by a NUL as a snapshot value", async () => {
    const { env, lease } = await fixture();
    await env.ALTERAN_DB.exec("DROP TRIGGER space_version_fence_update");
    await env.ALTERAN_DB.exec("DROP TRIGGER space_record_version_update_guard");
    await env.ALTERAN_DB.prepare(
      "UPDATE space_record_version SET value_cbor = ?, value_size = 1 WHERE epoch_id = ?",
    )
      .bind(`x\0${"x".repeat(1_500_000)}`, lease.epochId).run();
    const capture = captureTransfers(env);
    await rejectsCode(
      () => readSpaceSnapshotPage(capture.env, lease, null),
      "InvalidRepoState",
    );
    expect(capture.largest()).toBeLessThan(30_000);
  });

  it("does not transfer an oversized non-BLOB head when acquiring a lease", async () => {
    const { env } = await fixture();
    await env.ALTERAN_DB.exec("DROP TRIGGER space_repo_fence_update");
    await env.ALTERAN_DB.prepare(
      "UPDATE space_repo SET set_hash = ? WHERE space_ref = ? AND repo_did = ?",
    )
      .bind(`${"x".repeat(2048)}\0${"x".repeat(1_500_000)}`, SPACE, DID).run();
    const capture = captureTransfers(env);
    await rejectsCode(
      () => acquireSpaceSnapshot(capture.env, SPACE, DID),
      "SpaceSnapshotUnavailable",
    );
    expect(capture.largest()).toBeLessThan(30_000);
  });

  it("uses the selected nonce, not trigger-affected change counts, for leases", async () => {
    const { env, lease } = await fixture();
    await env.ALTERAN_DB.exec(
      `CREATE TRIGGER audit_snapshot_renew AFTER UPDATE ON space_snapshot_lease
      BEGIN INSERT INTO secret (key, value, updated_at) VALUES ('test:snapshot-audit', '1', 0)
        ON CONFLICT(key) DO UPDATE SET value = '1'; END`.replace(/\n/g, " "),
    );
    expect((await readSpaceSnapshotPage(env, lease, null)).records)
      .toHaveLength(1);
  });

  it("rolls back an acquisition whose trigger changes the leased head", async () => {
    const { env } = await fixture();
    await env.ALTERAN_DB.exec(
      `CREATE TRIGGER change_snapshot_head AFTER INSERT ON space_snapshot_lease
      BEGIN UPDATE space_snapshot_lease SET set_hash = zeroblob(2048) WHERE id = NEW.id; END`
        .replace(/\n/g, " "),
    );
    await expect(acquireSpaceSnapshot(env, SPACE, DID)).rejects.toThrow();
    const row = await env.ALTERAN_DB.prepare(
      "SELECT COUNT(*) AS count FROM space_snapshot_lease",
    ).first<{ count: number }>();
    expect(row?.count).toBe(1);
  });

  it("eventually clears an orphan lease after a lost acquisition response", async () => {
    const { env, lease } = await fixture();
    await releaseSpaceSnapshot(env, lease);
    const database = env.ALTERAN_DB;
    const unreliable = new Proxy(database, {
      get(target, property) {
        if (property === "batch") {
          return async (statements: Parameters<typeof database.batch>[0]) => {
            await database.batch(statements);
            throw new Error("Lost acquisition response");
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    await expect(
      acquireSpaceSnapshot({ ...env, ALTERAN_DB: unreliable }, SPACE, DID),
    ).rejects.toThrow();
    const count = await env.ALTERAN_DB.prepare(
      "SELECT COUNT(*) AS count FROM space_snapshot_lease",
    ).first<{ count: number }>();
    expect(count?.count).toBe(1);
    await pruneExpiredSpaceSnapshotLeases(
      clockEnv(env, Math.floor(Date.now() / 1000) + 120), SPACE, DID,
    );
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_snapshot_lease').first())?.n).toBe(0);
  });

  it("never revives a lease after the database clock moves forward and backward", async () => {
    const { env, lease } = await fixture();
    await update(env);
    const now = Math.floor(Date.now() / 1000);
    const future = clockEnv(env, now + 120);
    const past = clockEnv(env, now);
    expect(
      dagCbor.decode(
        (await readSpaceSnapshotPage(past, lease, null)).records[0].value,
      ),
    ).toMatchObject({ text: "old" });
    expect(await pruneSpaceRecordVersions(future, SPACE, DID)).toBe(1);
    await rejectsCode(
      () => readSpaceSnapshotPage(past, lease, null),
      "SpaceSnapshotUnavailable",
    );
    await pruneExpiredSpaceSnapshotLeases(future, SPACE, DID);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_snapshot_lease').first())?.n).toBe(0);
  });

  it("keeps a purged lease invalid after its database response is lost", async () => {
    const { env, lease } = await fixture();
    await update(env);
    const now = Math.floor(Date.now() / 1000);
    const future = clockEnv(env, now + 120);
    await expect(
      pruneExpiredSpaceSnapshotLeases(losePurgeResponse(future), SPACE, DID),
    ).rejects.toThrow();
    await rejectsCode(
      () => readSpaceSnapshotPage(clockEnv(env, now), lease, null),
      "SpaceSnapshotUnavailable",
    );
    await pruneExpiredSpaceSnapshotLeases(future, SPACE, DID);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_snapshot_lease').first())?.n).toBe(0);
    expect(await pruneSpaceRecordVersions(future, SPACE, DID)).toBe(1);
  });

  it("prevents old GC SQL from deleting a version while an expired lease row remains", async () => {
    const { env, lease } = await fixture();
    await update(env);
    await env.ALTERAN_DB.prepare(
      "UPDATE space_snapshot_lease SET expires_at = unixepoch() - 1 WHERE id = ?",
    ).bind(lease.id).run();
    await env.ALTERAN_DB.prepare(
      "INSERT INTO space_gc_attempt (id, space_ref, repo_did, epoch_id) VALUES (?, ?, ?, ?)",
    )
      .bind("old-gc", SPACE, DID, lease.epochId).run();
    await expect(
      env.ALTERAN_DB.prepare(
        "DELETE FROM space_record_version WHERE space_ref = ? AND until_generation IS NOT NULL",
      )
        .bind(SPACE).run(),
    ).rejects.toThrow();
    await pruneExpiredSpaceSnapshotLeases(env, SPACE, DID);
    expect((await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_snapshot_lease').first())?.n).toBe(0);
    await env.ALTERAN_DB.prepare(
      "DELETE FROM space_record_version WHERE space_ref = ? AND until_generation IS NOT NULL",
    )
      .bind(SPACE).run();
  });
});
