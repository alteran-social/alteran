import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import * as dagCbor from "@ipld/dag-cbor";
import { makeSpaceEnv as makeEnv } from "./helpers/space-env";
import { readSpaceRepoOps } from "./helpers/space-storage";
import { commitSpaceWrites, loadSpaceSnapshot } from "./helpers/space-storage";
import { parseSpaceRef } from "../src/db/space-ref";
import { applySpaceWrites, createLocalSpace } from "./helpers/space-storage";
import { nextSpaceRevision } from "../src/db/space-tid";
import { SpaceStorageError } from "../src/db/space-types";
import {
  applySpaceSetHashChanges,
  spaceRecordHashElement,
  spaceSetHashDigest,
} from "../src/lib/spaces/lthash";
import { encodeRecordBlock } from "../src/services/repo/blockstore-ops";

const DID = "did:example:test";
const TYPE = "com.example.note";
const SPACE = `at://${DID}/space/com.example.notes/ops`;
const OTHER = `at://${DID}/space/com.example.notes/other`;
type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

function create(rkey: string, text: string) {
  return {
    action: "create" as const,
    collection: TYPE,
    rkey,
    record: { $type: TYPE, text },
  };
}
function update(rkey: string, text: string) {
  return {
    action: "update" as const,
    collection: TYPE,
    rkey,
    record: { $type: TYPE, text },
  };
}
function remove(rkey: string) {
  return { action: "delete" as const, collection: TYPE, rkey };
}
async function setup(env: TestEnv) {
  await createLocalSpace(env, SPACE);
  const initial = await applySpaceWrites(env, SPACE, DID, [
    create("baseline", "initial"),
  ]);
  if (!initial) throw new Error("Missing initial commit");
  return initial;
}
async function page(
  env: TestEnv,
  since: string,
  cursor?: string,
  limit = 100,
  excludeValues = false,
) {
  const result = await readSpaceRepoOps(env, SPACE, DID, {
    since,
    cursor,
    limit,
    excludeValues,
  });
  if (result.tag !== "page") throw new Error("Expected incremental page");
  return result;
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

describe("incremental Space repo reads", () => {
  it("pages through a shared revision and retains superseded and deleted operations", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    const second = await applySpaceWrites(env, SPACE, DID, [
      create("a", "one"),
      create("b", "two"),
    ]);
    const last = await applySpaceWrites(env, SPACE, DID, [
      update("a", "new"),
      remove("b"),
    ]);
    if (!second || !last) throw new Error("Missing commit");

    const pages = [];
    let cursor: string | undefined;
    do {
      const result = await page(env, first.rev, cursor, 1);
      pages.push(result);
      cursor = result.cursor ?? undefined;
    } while (cursor);
    expect(pages).toHaveLength(4);
    expect(pages[0].cursor).toBe(`${second.rev}/0`);
    const operations = pages.flatMap((result) => result.operations);
    expect(operations.map(({ rev, rkey }) => [rev, rkey])).toEqual([
      [second.rev, "a"],
      [second.rev, "b"],
      [last.rev, "a"],
      [last.rev, "b"],
    ]);
    expect(operations[0].value).toBeUndefined();
    expect(operations[1].value).toBeUndefined();
    expect(dagCbor.decode(operations[2].value!)).toMatchObject({
      $type: TYPE,
      text: "new",
    });
    expect(operations[3].cid).toBeNull();
    expect(operations[3].value).toBeUndefined();
    expect(pages.at(-1)?.commit.rev).toBe(last.rev);
    expect([...pages.at(-1)!.commit.data]).toEqual([...last.data]);
  });

  it("converges to the final page commit when a write happens between pages", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    await applySpaceWrites(env, SPACE, DID, [
      create("a", "one"),
      create("b", "two"),
    ]);
    const one = await page(env, first.rev, undefined, 1);
    expect(one.cursor).toBeTruthy();
    const later = await applySpaceWrites(env, SPACE, DID, [
      update("a", "later"),
    ]);
    if (!later) throw new Error("Missing later commit");
    let cursor = one.cursor;
    const pages = [one];
    while (cursor) {
      const next = await page(env, first.rev, cursor, 1);
      pages.push(next);
      cursor = next.cursor;
    }
    let state = first.setHash;
    for (const result of pages) {
      for (const operation of result.operations) {
        const changes = [];
        if (operation.prev) {
          changes.push({
            action: "remove" as const,
            element: spaceRecordHashElement(
              operation.collection,
              operation.rkey,
              operation.prev,
            ),
          });
        }
        if (operation.cid) {
          changes.push({
            action: "add" as const,
            element: spaceRecordHashElement(
              operation.collection,
              operation.rkey,
              operation.cid,
            ),
          });
        }
        state = applySpaceSetHashChanges(state, changes);
      }
    }
    const final = pages.at(-1)!;
    expect(final.commit.rev).toBe(later.rev);
    expect([...spaceSetHashDigest(state)]).toEqual([...final.commit.data]);
  });

  it("reads the head and operations from one D1 snapshot during a competing write", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    const ref = parseSpaceRef(SPACE);
    const [cid, value] = await encodeRecordBlock({
      $type: TYPE,
      text: "concurrent",
    });
    const writes = [{
      action: "create" as const,
      collection: TYPE,
      rkey: "race",
      cid: cid.toString(),
      value,
      blobs: [],
    }];
    const snapshot = await loadSpaceSnapshot(env, ref, DID, writes);
    const database = env.ALTERAN_DB;
    let readDispatched: () => void = () => {};
    let writeDispatched: () => void = () => {};
    const readerStarted = new Promise<void>((resolve) =>
      readDispatched = resolve
    );
    const writerStarted = new Promise<void>((resolve) =>
      writeDispatched = resolve
    );
    const readerDatabase = new Proxy(database, {
      get(target, property) {
        if (property === "prepare") {
          return (sql: string) =>
            target.prepare(
              sql.includes("AS known_since")
                ? sql.replace(
                  "SELECT CASE WHEN typeof(h.rev)",
                  "WITH RECURSIVE spin(n) AS (VALUES(0) UNION ALL SELECT n + 1 FROM spin WHERE n < 500000) SELECT (SELECT sum(n) FROM spin) AS test_pause, CASE WHEN typeof(h.rev)",
                )
                : sql,
            );
        }
        if (property === "batch") {
          return (statements: Parameters<typeof database.batch>[0]) => {
            const result = database.batch(statements);
            readDispatched();
            return result;
          };
        }
        const result = Reflect.get(target, property, target);
        return typeof result === "function" ? result.bind(target) : result;
      },
    });
    const writerDatabase = new Proxy(database, {
      get(target, property) {
        if (property === "batch") {
          return (statements: Parameters<typeof database.batch>[0]) => {
            const result = database.batch(statements);
            writeDispatched();
            return result;
          };
        }
        const result = Reflect.get(target, property, target);
        return typeof result === "function" ? result.bind(target) : result;
      },
    });
    const reading = readSpaceRepoOps(
      { ...env, ALTERAN_DB: readerDatabase },
      SPACE,
      DID,
      { since: first.rev },
    );
    await readerStarted;
    const writing = commitSpaceWrites(
      { ...env, ALTERAN_DB: writerDatabase },
      ref,
      DID,
      writes,
      snapshot,
    );
    const readFinishedFirst = await Promise.race([
      writerStarted.then(() => false),
      reading.then(() => true),
    ]);
    expect(readFinishedFirst).toBe(false);
    const [result, written] = await Promise.all([reading, writing]);
    expect(result.tag).toBe("page");
    expect(written.tag).toBe("committed");
    if (result.tag !== "page" || written.tag !== "committed") {
      throw new Error("Missing result");
    }
    if (result.operations.length === 0) {
      expect(result.commit.rev).toBe(first.rev);
      expect([...result.commit.data]).toEqual([...first.data]);
    } else {
      expect(result.operations).toHaveLength(1);
      expect(result.commit.rev).toBe(written.commit.rev);
      expect([...result.commit.data]).toEqual([...written.commit.data]);
    }
  });

  it("returns only operation metadata when values are excluded", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    await applySpaceWrites(env, SPACE, DID, [create("a", "private")]);
    const result = await page(env, first.rev, undefined, 100, true);
    expect(result.operations).toHaveLength(1);
    expect(result.operations[0].value).toBeUndefined();
    expect(result.cursor).toBeNull();
  });

  it("returns records with nested types accepted by the writer", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    await applySpaceWrites(env, SPACE, DID, [{
      action: "create",
      collection: TYPE,
      rkey: "nested",
      record: { $type: TYPE, nested: { $type: "not an nsid" } },
    }]);
    const result = await page(env, first.rev);
    expect(dagCbor.decode(result.operations[0].value!)).toMatchObject({
      nested: { $type: "not an nsid" },
    });
  });

  it("returns large canonical arrays accepted by the writer", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    await applySpaceWrites(env, SPACE, DID, [{
      action: "create",
      collection: TYPE,
      rkey: "many",
      record: { $type: TYPE, items: Array(100_001).fill(null) },
    }]);
    const result = await page(env, first.rev);
    const decoded = dagCbor.decode(result.operations[0].value!) as {
      items: unknown[];
    };
    expect(decoded.items).toHaveLength(100_001);
  });

  it("rejects invalid and over-budget records without adding operations", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    for (const [rkey, record] of [
      ["bad-type", { $type: TYPE, nested: { $type: "" } }],
      ["too-many", { $type: TYPE, items: Array(131_072).fill(null) }],
    ] as const) {
      await rejectsCode(
        () => applySpaceWrites(env, SPACE, DID, [{ action: "create", collection: TYPE, rkey, record }]),
        "InvalidRequest",
      );
    }
    const result = await page(env, first.rev);
    expect(result.operations).toHaveLength(0);
    expect(result.commit.rev).toBe(first.rev);
  });

  it("requires full sync for an unknown or absent starting revision", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    const missing = nextSpaceRevision(first.rev);
    expect((await readSpaceRepoOps(env, SPACE, DID, { since: missing })).tag)
      .toBe("fullSync");
    await rejectsCode(
      () => readSpaceRepoOps(env, SPACE, DID, {} as any),
      "InvalidRequest",
    );
    const current = await page(env, first.rev);
    expect(current.operations).toHaveLength(0);
  });

  it("rejects invalid cursors and never reads another Space or repo", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    await createLocalSpace(env, OTHER);
    await applySpaceWrites(env, OTHER, DID, [create("hidden", "other")]);
    for (
      const cursor of [
        "",
        `${first.rev}/-1`,
        `${first.rev}/01`,
        `${first.rev}/0/extra`,
        "bad/0",
      ]
    ) {
      await rejectsCode(() => page(env, first.rev, cursor), "InvalidCursor");
    }
    await rejectsCode(
      () =>
        readSpaceRepoOps(env, SPACE, "did:example:other", { since: first.rev }),
      "RepoNotFound",
    );
    expect((await page(env, first.rev)).operations).toHaveLength(0);
  });

  it("limits value bytes before transfer and returns a continuation", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    await applySpaceWrites(env, SPACE, DID, [create("a", "a".repeat(600_000))]);
    await applySpaceWrites(env, SPACE, DID, [create("b", "b".repeat(600_000))]);
    const one = await page(env, first.rev);
    expect(one.operations).toHaveLength(1);
    expect(one.operations[0].value?.length).toBeGreaterThan(600_000);
    expect(one.cursor).toBeTruthy();
    const two = await page(env, first.rev, one.cursor!);
    expect(two.operations).toHaveLength(1);
    expect(two.cursor).toBeNull();
  });

  it("fails closed on an oversized first current value", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    await applySpaceWrites(env, SPACE, DID, [create("a", "normal")]);
    await env.ALTERAN_DB.exec("DROP TRIGGER space_record_fence_update");
    await env.ALTERAN_DB.prepare(
      "UPDATE space_record SET value_cbor = ? WHERE space_ref = ? AND rkey = ?",
    )
      .bind(new Uint8Array(1024 * 1024 + 1).buffer, SPACE, "a").run();
    await rejectsCode(() => page(env, first.rev), "InvalidRepoState");
  });

  it("fails closed if a current record differs from its active version", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    await applySpaceWrites(env, SPACE, DID, [create("a", "normal")]);
    await env.ALTERAN_DB.exec("DROP TRIGGER space_record_fence_update");
    await env.ALTERAN_DB.prepare(
      "UPDATE space_record SET value_cbor = ? WHERE space_ref = ? AND rkey = ?",
    )
      .bind(new Uint8Array([1, 2]).buffer, SPACE, "a").run();
    await rejectsCode(() => page(env, first.rev), "InvalidRepoState");
  });

  it("does not transfer oversized text disguised by a leading NUL", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    await applySpaceWrites(env, SPACE, DID, [create("a", "normal")]);
    await env.ALTERAN_DB.exec("DROP TRIGGER space_record_fence_update");
    await env.ALTERAN_DB.prepare(
      "UPDATE space_record SET value_cbor = ? WHERE space_ref = ? AND rkey = ?",
    )
      .bind(`\0${"x".repeat(1_500_000)}`, SPACE, "a").run();
    const capture = captureTransfers(env);
    await rejectsCode(() => page(capture.env, first.rev), "InvalidRepoState");
    expect(capture.largest()).toBeLessThan(30_000);
  });

  it("does not transfer oversized operation metadata", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    await applySpaceWrites(env, SPACE, DID, [create("a", "normal")]);
    await env.ALTERAN_DB.exec("DROP TRIGGER space_op_fence_update");
    await env.ALTERAN_DB.prepare(
      "UPDATE space_op SET collection = ? WHERE space_ref = ? AND rkey = ?",
    )
      .bind(`\0${"x".repeat(1_500_000)}`, SPACE, "a").run();
    const capture = captureTransfers(env);
    await rejectsCode(() => page(capture.env, first.rev), "InvalidRepoState");
    expect(capture.largest()).toBeLessThan(30_000);
  });

  it("does not transfer an oversized non-BLOB head hash", async () => {
    const env = await makeEnv();
    const first = await setup(env);
    await env.ALTERAN_DB.exec("DROP TRIGGER space_repo_fence_update");
    await env.ALTERAN_DB.prepare(
      "UPDATE space_repo SET set_hash = ? WHERE space_ref = ? AND repo_did = ?",
    )
      .bind(`${"x".repeat(2048)}\0${"x".repeat(1_500_000)}`, SPACE, DID).run();
    const capture = captureTransfers(env);
    await rejectsCode(() => page(capture.env, first.rev), "InvalidRepoState");
    expect(capture.largest()).toBeLessThan(30_000);
  });
});
