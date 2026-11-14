import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from "./helpers/env";
import {
  applySpaceWrites,
  createLocalSpace,
  getSpaceRecord,
} from "../src/db/space-store";
import {
  acquireSpaceSnapshot,
  releaseSpaceSnapshot,
} from "../src/db/space-snapshot";
import {
  pruneSpaceRecordVersionsPage,
  SPACE_VERSION_GC_DELETE_SQL,
  SPACE_VERSION_GC_FIRST_SQL,
  SPACE_VERSION_GC_NEXT_SQL,
  type SpaceVersionGcCursor,
} from "../src/db/space-version-gc";
import { SpaceStorageError } from "../src/db/space-types";

const DID = "did:example:test";
const COLLECTION = "com.example.note";
const SPACE = `at://${DID}/space/com.example.notes/versiongc`;
type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

async function fixture(keys = ["a", "b", "c"]) {
  const env = await makeEnv();
  await createLocalSpace(env, SPACE);
  await applySpaceWrites(
    env,
    SPACE,
    DID,
    keys.map((rkey) => ({
      action: "create" as const,
      collection: COLLECTION,
      rkey,
      record: { $type: COLLECTION, text: "old" },
    })),
  );
  return env;
}

async function update(env: TestEnv, keys: string[]) {
  await applySpaceWrites(
    env,
    SPACE,
    DID,
    keys.map((rkey) => ({
      action: "update" as const,
      collection: COLLECTION,
      rkey,
      record: { $type: COLLECTION, text: "new" },
    })),
  );
}

async function oldCount(env: TestEnv) {
  const result = await env.ALTERAN_DB.prepare(
    "SELECT COUNT(*) AS count FROM space_record_version WHERE until_generation IS NOT NULL",
  ).first<{ count: number }>();
  return result?.count;
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

function onBatch(
  env: TestEnv,
  callback: (size: number) => Promise<void>,
): TestEnv {
  const database = env.ALTERAN_DB;
  return {
    ...env,
    ALTERAN_DB: new Proxy(database, {
      get(target, property) {
        if (property === "batch") {
          return async (statements: Parameters<typeof database.batch>[0]) => {
            const result = await database.batch(statements);
            await callback(statements.length);
            return result;
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }),
  };
}

describe("bounded Space version cleanup", () => {
  it("advances over pinned pages, reaches later versions, and revisits released versions on a new cycle", async () => {
    const env = await fixture();
    const lease = await acquireSpaceSnapshot(env, SPACE, DID);
    await update(env, ["a", "b"]);
    await update(env, ["a"]);
    const first = await pruneSpaceRecordVersionsPage(env, SPACE, DID, null, 1);
    expect(first.pruned).toBe(0);
    expect(first.cursor?.path).toBe(`${COLLECTION}/a`);
    const second = await pruneSpaceRecordVersionsPage(
      env,
      SPACE,
      DID,
      first.cursor,
      1,
    );
    expect(second.pruned).toBe(0);
    expect(second.cursor?.path).toBe(`${COLLECTION}/b`);
    const third = await pruneSpaceRecordVersionsPage(
      env,
      SPACE,
      DID,
      second.cursor,
      1,
    );
    expect(third).toEqual({ pruned: 1, cursor: null });
    expect(await oldCount(env)).toBe(2);
    await releaseSpaceSnapshot(env, lease);
    const fourth = await pruneSpaceRecordVersionsPage(env, SPACE, DID, null, 1);
    const fifth = await pruneSpaceRecordVersionsPage(
      env,
      SPACE,
      DID,
      fourth.cursor,
      1,
    );
    expect(fourth.pruned + fifth.pruned).toBe(2);
    expect(fifth.cursor).toBe(null);
    expect(await oldCount(env)).toBe(0);
    expect(await getSpaceRecord(env, SPACE, DID, COLLECTION, "a")).not.toBe(
      null,
    );
  });

  it("uses an immutable owner and epoch bound cursor and copies it before awaiting", async () => {
    const env = await fixture();
    const lease = await acquireSpaceSnapshot(env, SPACE, DID);
    await update(env, ["a", "b", "c"]);
    const first = await pruneSpaceRecordVersionsPage(env, SPACE, DID, null, 1);
    const cursor = first.cursor!;
    expect(Object.isFrozen(cursor)).toBe(true);
    for (
      const bad of [
        { ...cursor, epochId: "other" },
        { ...cursor, spaceRef: `${SPACE}x` },
        { ...cursor, repoDid: "did:example:other" },
        { ...cursor, path: "x".repeat(1000) },
        { ...cursor, fromGeneration: cursor.untilGeneration },
      ]
    ) {
      await rejectsCode(
        () => pruneSpaceRecordVersionsPage(env, SPACE, DID, bad, 1),
        "InvalidCursor",
      );
    }
    const mutable = { ...cursor };
    let resolveDid!: (value: string) => void;
    const did = new Promise<string>((resolve) => resolveDid = resolve);
    const pending = pruneSpaceRecordVersionsPage(
      {
        ...env,
        PDS_DID: { get: () => did },
      },
      SPACE,
      DID,
      mutable,
      1,
    );
    mutable.path = `${COLLECTION}/c`;
    resolveDid(DID);
    expect((await pending).cursor?.path).toBe(`${COLLECTION}/b`);
    await releaseSpaceSnapshot(env, lease);
  });

  it("handles duplicate concurrent pages and retries a lost committed response", async () => {
    const env = await fixture();
    await update(env, ["a", "b", "c"]);
    const [a, b] = await Promise.all([
      pruneSpaceRecordVersionsPage(env, SPACE, DID, null, 2),
      pruneSpaceRecordVersionsPage(env, SPACE, DID, null, 2),
    ]);
    expect(a.pruned + b.pruned).toBeGreaterThanOrEqual(2);
    expect(a.pruned + b.pruned).toBeLessThanOrEqual(3);
    let lost = false;
    const interrupted = onBatch(env, async (size) => {
      if (size === 8 && !lost) {
        lost = true;
        throw new Error("Lost GC response");
      }
    });
    const cursor = a.cursor ?? b.cursor;
    if (cursor) {
      await expect(
        pruneSpaceRecordVersionsPage(interrupted, SPACE, DID, cursor, 2),
      ).rejects.toThrow("Lost GC response");
      const retried = await pruneSpaceRecordVersionsPage(
        env,
        SPACE,
        DID,
        cursor,
        2,
      );
      expect(retried.pruned).toBe(0);
    }
    await pruneSpaceRecordVersionsPage(env, SPACE, DID, null, 100);
    expect(await oldCount(env)).toBe(0);
  });

  it("rechecks extant leases between the scan and deletion batches", async () => {
    const env = await fixture(["a"]);
    const lease = await acquireSpaceSnapshot(env, SPACE, DID);
    await update(env, ["a"]);
    let released = false;
    const wrapped = onBatch(env, async (size) => {
      if (size === 6 && !released) {
        released = true;
        await releaseSpaceSnapshot(env, lease);
      }
    });
    expect((await pruneSpaceRecordVersionsPage(wrapped, SPACE, DID)).pruned)
      .toBe(1);
    expect(released).toBe(true);
    expect(await oldCount(env)).toBe(0);
  });

  it("preserves a historical lease inserted after candidate selection", async () => {
    const env = await fixture(["a"]);
    const lease = await acquireSpaceSnapshot(env, SPACE, DID);
    await update(env, ["a"]);
    await releaseSpaceSnapshot(env, lease);
    let inserted = false;
    const wrapped = onBatch(env, async (size) => {
      if (size !== 6 || inserted) return;
      inserted = true;
      await env.ALTERAN_DB.prepare(`INSERT INTO space_snapshot_lease
        (id, token, renewal_nonce, space_ref, repo_did, epoch_id, generation, rev, set_hash, expires_at, maximum_expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch() + 60, unixepoch() + 900)`)
        .bind(
          lease.id,
          lease.token,
          crypto.randomUUID(),
          lease.spaceRef,
          lease.repoDid,
          lease.epochId,
          lease.generation,
          lease.rev,
          lease.setHash.buffer,
        ).run();
    });
    expect((await pruneSpaceRecordVersionsPage(wrapped, SPACE, DID)).pruned)
      .toBe(0);
    expect(inserted).toBe(true);
    expect(await oldCount(env)).toBe(1);
    await releaseSpaceSnapshot(env, lease);
    expect((await pruneSpaceRecordVersionsPage(env, SPACE, DID)).pruned).toBe(
      1,
    );
  });

  it("rejects an epoch change between selection and deletion", async () => {
    const env = await fixture(["a"]);
    await update(env, ["a"]);
    let changed = false;
    const wrapped = onBatch(env, async (size) => {
      if (size !== 6 || changed) return;
      changed = true;
      await env.ALTERAN_DB.prepare(
        "UPDATE space_epoch SET state = 'quarantined' WHERE space_ref = ? AND repo_did = ?",
      )
        .bind(SPACE, DID).run();
    });
    await expect(pruneSpaceRecordVersionsPage(wrapped, SPACE, DID)).rejects
      .toThrow();
    expect(changed).toBe(true);
    expect(await oldCount(env)).toBe(1);
    expect(
      (await env.ALTERAN_DB.prepare(
        "SELECT COUNT(*) AS count FROM space_gc_attempt",
      )
        .first<{ count: number }>())?.count,
    ).toBe(0);
  });

  it("rolls back the deletion if a trigger prevents the transaction postcondition", async () => {
    const env = await fixture(["a"]);
    await update(env, ["a"]);
    await env.ALTERAN_DB.prepare(
      "CREATE TRIGGER test_ignore_version_delete BEFORE DELETE ON space_record_version BEGIN SELECT RAISE(IGNORE); END",
    ).run();
    await expect(pruneSpaceRecordVersionsPage(env, SPACE, DID)).rejects
      .toThrow();
    expect(await oldCount(env)).toBe(1);
    expect(
      (await env.ALTERAN_DB.prepare(
        "SELECT COUNT(*) AS count FROM space_gc_attempt",
      ).first<{ count: number }>())?.count,
    ).toBe(0);
    await env.ALTERAN_DB.exec("DROP TRIGGER test_ignore_version_delete");
    expect((await pruneSpaceRecordVersionsPage(env, SPACE, DID)).pruned).toBe(
      1,
    );
  });

  it("rejects corrupt oversized paths before transferring them from D1", async () => {
    const env = await fixture(["a"]);
    await update(env, ["a"]);
    await env.ALTERAN_DB.exec("DROP TRIGGER space_record_version_update_guard");
    await env.ALTERAN_DB.exec("DROP TRIGGER space_version_fence_update");
    const rkey = "\0" + "x".repeat(400_000);
    await env.ALTERAN_DB.prepare(
      "UPDATE space_record_version SET rkey = ?, path = ? WHERE until_generation IS NOT NULL",
    )
      .bind(rkey, `${COLLECTION}/${rkey}`).run();
    let largest = 0;
    const database = env.ALTERAN_DB;
    const guarded = {
      ...env,
      ALTERAN_DB: new Proxy(database, {
        get(target, property) {
          if (property === "batch") {
            return async (statements: Parameters<typeof database.batch>[0]) => {
              const result = await database.batch(statements);
              largest = Math.max(largest, JSON.stringify(result).length);
              return result;
            };
          }
          const value = Reflect.get(target, property, target);
          return typeof value === "function" ? value.bind(target) : value;
        },
      }),
    };
    await rejectsCode(
      () => pruneSpaceRecordVersionsPage(guarded, SPACE, DID),
      "InvalidRepoState",
    );
    expect(largest).toBeLessThan(30_000);
    expect(await oldCount(env)).toBe(1);
  });

  it("seeks near the end of a large equal-generation prefix without scanning earlier paths", async () => {
    const env = await fixture(["a"]);
    await update(env, ["a"]);
    await env.ALTERAN_DB.exec("DROP TRIGGER space_record_version_insert_guard");
    await env.ALTERAN_DB.exec("DROP TRIGGER space_version_fence_insert");
    await env.ALTERAN_DB.prepare(
      `WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i + 1 FROM n WHERE i < 600)
      INSERT INTO space_record_version
      (epoch_id, space_ref, repo_did, path, collection, rkey, from_generation, until_generation, cid, value_cbor, value_size, repo_rev)
      SELECT v.epoch_id, v.space_ref, v.repo_did, v.collection || '/' || printf('k%04d', n.i), v.collection,
        printf('k%04d', n.i), v.from_generation, v.until_generation, v.cid, v.value_cbor, v.value_size, v.repo_rev
      FROM space_record_version v CROSS JOIN n WHERE v.rkey = 'a' AND v.until_generation IS NOT NULL`,
    ).run();
    const identity = await env.ALTERAN_DB.prepare(
      "SELECT active_epoch_id AS epoch FROM space_repo WHERE space_ref = ? AND repo_did = ?",
    )
      .bind(SPACE, DID).first<{ epoch: string }>();
    const prefix = [identity!.epoch, SPACE, DID] as const;
    const result = await env.ALTERAN_DB.prepare(SPACE_VERSION_GC_NEXT_SQL).bind(
      ...prefix,
      2,
      `${COLLECTION}/k0590`,
      1,
      2,
      ...prefix,
      2,
      `${COLLECTION}/k0590`,
      2,
      ...prefix,
      2,
      2,
      2,
    ).all<{ path: string }>();
    expect(result.results.map((row) => row.path)).toEqual([
      `${COLLECTION}/k0591`,
      `${COLLECTION}/k0592`,
    ]);
    expect(result.meta.rows_read).toBeLessThan(30);
  });

  it("seeks bounded ranges before sorting and deletes by indexed candidate keys", async () => {
    const env = await fixture();
    const plan = async (sql: string, args: (string | number)[]) => {
      const result = await env.ALTERAN_DB.prepare(`EXPLAIN QUERY PLAN ${sql}`)
        .bind(...args).all<{ detail: string }>();
      return result.results.map((row) => row.detail);
    };
    const prefix = ["epoch", SPACE, DID] as const;
    const first = await plan(SPACE_VERSION_GC_FIRST_SQL, [...prefix, 3]);
    const next = await plan(SPACE_VERSION_GC_NEXT_SQL, [
      ...prefix,
      2,
      `${COLLECTION}/a`,
      1,
      3,
      ...prefix,
      2,
      `${COLLECTION}/a`,
      3,
      ...prefix,
      2,
      3,
      3,
    ]);
    const deletion = await plan(SPACE_VERSION_GC_DELETE_SQL, [
      "[]",
      ...prefix,
      "attempt",
    ]);
    expect(first.join(" ")).toContain("space_record_version_gc_candidates");
    expect(
      next.filter((line) =>
        line.includes(
          "SEARCH v USING COVERING INDEX space_record_version_gc_candidates",
        )
      ).length,
    ).toBe(3);
    expect(next.join(" ")).toContain("from_generation>?");
    expect(next.join(" ")).toContain("path>?");
    expect(deletion.join(" ")).toContain("INTEGER PRIMARY KEY (rowid=?)");
    expect(deletion.join(" ")).toContain(
      "space_snapshot_lease_epoch_generation",
    );
  });
});
