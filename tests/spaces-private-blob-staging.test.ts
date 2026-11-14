import { expect } from "@std/expect";
import type { D1Database, R2Bucket } from "@cloudflare/workers-types";
import { Miniflare } from "miniflare";
import { sha256 } from "@noble/hashes/sha2.js";
import { CID } from "multiformats/cid";
import { create as createDigest } from "multiformats/hashes/digest";
import { afterEach, describe, it } from "./helpers/bdd";
import {
  PRIVATE_BLOB_MAX_BYTES,
  PRIVATE_BLOB_MAX_RESERVATIONS,
  type PrivateBlobReservation,
  reservePrivateBlob,
  stagePrivateBlob,
} from "../src/lib/spaces/private-blob-staging";

const DID = "did:example:test";
const OTHER = "did:example:other";
const workers: Miniflare[] = [];

// This schema is intentionally isolated from the application migrations.
async function setup() {
  const worker = new Miniflare({
    d1Databases: { DB: ":memory:" },
    r2Buckets: ["PRIVATE"],
    compatibilityDate: "2025-10-02",
    script: "export default { fetch: () => new Response('ok') }",
    modules: true,
  });
  workers.push(worker);
  await worker.ready;
  const env = {
    ALTERAN_DB: await worker.getD1Database("DB") as unknown as D1Database,
    ALTERAN_BLOBS: await worker.getR2Bucket("PRIVATE") as unknown as R2Bucket,
  };
  await env.ALTERAN_DB.exec(`CREATE TABLE private_blob_staging (
    id TEXT PRIMARY KEY NOT NULL,
    token TEXT NOT NULL,
    repo_did TEXT NOT NULL,
    object_key TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'putting', 'ready', 'uncertain')),
    reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes = 5242880),
    claim_nonce TEXT, cid TEXT, digest TEXT, size INTEGER, mime_type TEXT,
    r2_version TEXT, etag TEXT
  )`.replace(/\n/g, " "));
  await env.ALTERAN_DB.exec(
    "CREATE INDEX private_blob_staging_repo ON private_blob_staging(repo_did)",
  );
  for (
    const table of ["blob", "blob_usage", "space_blob_usage", "space_record"]
  ) {
    await env.ALTERAN_DB.exec(`CREATE TABLE ${table} (id INTEGER)`);
  }
  return env;
}

async function reservation(env: Awaited<ReturnType<typeof setup>>, did = DID) {
  const result = await reservePrivateBlob(env.ALTERAN_DB, did);
  if (result.tag !== "reserved") {
    throw new Error(`Reservation failed: ${result.tag}`);
  }
  return result.reservation;
}

async function row(
  env: Awaited<ReturnType<typeof setup>>,
  value: PrivateBlobReservation,
) {
  return await env.ALTERAN_DB.prepare(
    "SELECT * FROM private_blob_staging WHERE id = ? AND repo_did = ?",
  ).bind(value.id, value.repoDid).first<{
    object_key: string;
    state: string;
    reserved_bytes: number;
    cid: string | null;
    digest: string | null;
    r2_version: string | null;
    etag: string | null;
  }>();
}

describe("private blob staging foundation", () => {
  afterEach(async () => {
    await Promise.all(workers.splice(0).map((worker) => worker.dispose()));
  });

  it("stages a checksum-validated immutable object without public or Space references", async () => {
    const env = await setup();
    const handle = await reservation(env);
    const bytes = new TextEncoder().encode("private content");
    const expected = CID.createV1(0x55, createDigest(0x12, sha256(bytes)))
      .toString();
    const pending = stagePrivateBlob(
      env.ALTERAN_DB,
      env.ALTERAN_BLOBS,
      handle,
      bytes,
      "text/plain",
    );
    bytes.fill(0);
    const result = await pending;
    expect(result).toEqual({
      tag: "staged",
      cid: expected,
      size: 15,
      mimeType: "text/plain",
    });
    const stored = await row(env, handle);
    expect(stored?.state).toBe("ready");
    expect(stored?.cid).toBe(expected);
    expect(stored?.r2_version).toBeTruthy();
    expect(stored?.etag).toBeTruthy();
    expect(stored?.reserved_bytes).toBe(PRIVATE_BLOB_MAX_BYTES);
    const object = await env.ALTERAN_BLOBS.get(stored!.object_key);
    expect(await object?.text()).toBe("private content");
    for (
      const table of ["blob", "blob_usage", "space_blob_usage", "space_record"]
    ) {
      const count = await env.ALTERAN_DB.prepare(
        `SELECT COUNT(*) AS count FROM ${table}`,
      ).first<{ count: number }>();
      expect(count?.count).toBe(0);
    }
  });

  it("allows one claimant for a reservation and never reuses it", async () => {
    const env = await setup();
    const handle = await reservation(env);
    const [first, second] = await Promise.all([
      stagePrivateBlob(
        env.ALTERAN_DB,
        env.ALTERAN_BLOBS,
        handle,
        new Uint8Array([1]),
        "application/octet-stream",
      ),
      stagePrivateBlob(
        env.ALTERAN_DB,
        env.ALTERAN_BLOBS,
        handle,
        new Uint8Array([2]),
        "application/octet-stream",
      ),
    ]);
    expect([first.tag, second.tag].sort()).toEqual(["invalid", "staged"]);
    expect((await row(env, handle))?.state).toBe("ready");
    expect(
      (await stagePrivateBlob(
        env.ALTERAN_DB,
        env.ALTERAN_BLOBS,
        handle,
        new Uint8Array(),
        "text/plain",
      )).tag,
    )
      .toBe("invalid");
  });

  it("retains a full charge when a PUT succeeds but its response is lost", async () => {
    const env = await setup();
    const handle = await reservation(env);
    const bucket = {
      async put(
        key: string,
        body: Uint8Array,
        options: Parameters<R2Bucket["put"]>[2],
      ) {
        await env.ALTERAN_BLOBS.put(key, body, options);
        throw new Error("response lost");
      },
    } as unknown as R2Bucket;
    expect(
      (await stagePrivateBlob(
        env.ALTERAN_DB,
        bucket,
        handle,
        new Uint8Array([1, 2, 3]),
        "text/plain",
      )).tag,
    )
      .toBe("uncertain");
    const stored = await row(env, handle);
    expect(stored?.state).toBe("uncertain");
    expect(stored?.reserved_bytes).toBe(PRIVATE_BLOB_MAX_BYTES);
    expect(await env.ALTERAN_BLOBS.get(stored!.object_key)).toBeTruthy();
    expect(
      (await stagePrivateBlob(
        env.ALTERAN_DB,
        env.ALTERAN_BLOBS,
        handle,
        new Uint8Array([1, 2, 3]),
        "text/plain",
      )).tag,
    )
      .toBe("invalid");
  });

  it("captures verified upload metadata once before saving it", async () => {
    const env = await setup();
    const handle = await reservation(env);
    let versionReads = 0;
    let etagReads = 0;
    let expectedVersion = "";
    let expectedEtag = "";
    const bucket = {
      async put(
        key: string,
        body: Uint8Array,
        options: Parameters<R2Bucket["put"]>[2],
      ) {
        const uploaded = await env.ALTERAN_BLOBS.put(key, body, options);
        if (!uploaded) throw new Error("Expected a successful upload");
        expectedVersion = uploaded.version;
        expectedEtag = uploaded.etag;
        return {
          key: uploaded.key,
          size: uploaded.size,
          checksums: uploaded.checksums,
          get version() {
            return ++versionReads === 1 ? expectedVersion : "changed-version";
          },
          get etag() {
            return ++etagReads === 1 ? expectedEtag : "changed-etag";
          },
        };
      },
    } as unknown as R2Bucket;
    expect(
      (await stagePrivateBlob(
        env.ALTERAN_DB,
        bucket,
        handle,
        new Uint8Array([9]),
        "text/plain",
      )).tag,
    )
      .toBe("staged");
    const stored = await row(env, handle);
    expect(versionReads).toBe(1);
    expect(etagReads).toBe(1);
    expect(stored?.r2_version).toBe(expectedVersion);
    expect(stored?.etag).toBe(expectedEtag);
  });

  it("does not trust a PUT adapter that mutates both body and supplied checksum", async () => {
    const env = await setup();
    const handle = await reservation(env);
    const bucket = {
      async put(
        key: string,
        body: Uint8Array,
        options: Parameters<R2Bucket["put"]>[2],
      ) {
        body.fill(0);
        const supplied = (options as { sha256?: unknown } | undefined)?.sha256;
        if (!(supplied instanceof Uint8Array)) {
          throw new Error("Missing checksum");
        }
        supplied.set(sha256(body));
        return await env.ALTERAN_BLOBS.put(key, body, options);
      },
    } as unknown as R2Bucket;
    expect(
      (await stagePrivateBlob(
        env.ALTERAN_DB,
        bucket,
        handle,
        new Uint8Array([1, 2]),
        "text/plain",
      )).tag,
    )
      .toBe("uncertain");
    const stored = await row(env, handle);
    expect(stored?.state).toBe("uncertain");
    expect(stored?.reserved_bytes).toBe(PRIVATE_BLOB_MAX_BYTES);
    expect(await env.ALTERAN_BLOBS.get(stored!.object_key)).toBeTruthy();
  });

  it("never overwrites an object that already occupies its random key", async () => {
    const env = await setup();
    const handle = await reservation(env);
    const stored = await row(env, handle);
    await env.ALTERAN_BLOBS.put(stored!.object_key, "existing");
    expect(
      (await stagePrivateBlob(
        env.ALTERAN_DB,
        env.ALTERAN_BLOBS,
        handle,
        new TextEncoder().encode("replacement"),
        "text/plain",
      )).tag,
    )
      .toBe("uncertain");
    expect(await (await env.ALTERAN_BLOBS.get(stored!.object_key))?.text())
      .toBe("existing");
    expect((await row(env, handle))?.state).toBe("uncertain");
  });

  it("retains the reservation if the database skips the ready transition", async () => {
    const env = await setup();
    const handle = await reservation(env);
    await env.ALTERAN_DB.exec(
      `CREATE TRIGGER skip_private_blob_ready BEFORE UPDATE ON private_blob_staging
      WHEN NEW.state = 'ready' BEGIN SELECT RAISE(IGNORE); END`.replace(
        /\n/g,
        " ",
      ),
    );
    expect(
      (await stagePrivateBlob(
        env.ALTERAN_DB,
        env.ALTERAN_BLOBS,
        handle,
        new Uint8Array([8]),
        "text/plain",
      )).tag,
    )
      .toBe("uncertain");
    const stored = await row(env, handle);
    expect(stored?.state).toBe("putting");
    expect(stored?.reserved_bytes).toBe(PRIVATE_BLOB_MAX_BYTES);
    expect(await env.ALTERAN_BLOBS.get(stored!.object_key)).toBeTruthy();
  });

  it("rolls back a ready transition altered by an after-update trigger", async () => {
    for (const change of ["state = 'uncertain'", "etag = 'forged'"]) {
      const env = await setup();
      const handle = await reservation(env);
      await env.ALTERAN_DB.exec(
        `CREATE TRIGGER change_private_blob_ready AFTER UPDATE ON private_blob_staging
         WHEN NEW.state = 'ready' BEGIN
           UPDATE private_blob_staging SET ${change} WHERE id = NEW.id;
         END`.replace(/\n/g, " "),
      );
      expect(
        (await stagePrivateBlob(
          env.ALTERAN_DB,
          env.ALTERAN_BLOBS,
          handle,
          new Uint8Array([7]),
          "text/plain",
        )).tag,
      )
        .toBe("uncertain");
      const stored = await row(env, handle);
      expect(stored?.state).toBe("putting");
      expect(stored?.etag).toBeNull();
      expect(stored?.reserved_bytes).toBe(PRIVATE_BLOB_MAX_BYTES);
      expect(await env.ALTERAN_BLOBS.get(stored!.object_key)).toBeTruthy();
    }
  });

  it("caps concurrent and zero-byte attempts by repo and permanently charges slots", async () => {
    const env = await setup();
    const outcomes = await Promise.all(Array.from(
      { length: PRIVATE_BLOB_MAX_RESERVATIONS + 1 },
      () => reservePrivateBlob(env.ALTERAN_DB, DID),
    ));
    expect(outcomes.filter((item) => item.tag === "reserved").length).toBe(
      PRIVATE_BLOB_MAX_RESERVATIONS,
    );
    expect(outcomes.filter((item) => item.tag === "quota-exceeded").length)
      .toBe(1);
    const empty = outcomes.find((item) => item.tag === "reserved");
    if (!empty || empty.tag !== "reserved") {
      throw new Error("Missing reservation");
    }
    expect(
      (await stagePrivateBlob(
        env.ALTERAN_DB,
        env.ALTERAN_BLOBS,
        empty.reservation,
        new Uint8Array(),
        "text/plain",
      )).tag,
    )
      .toBe("staged");
    expect((await reservePrivateBlob(env.ALTERAN_DB, DID)).tag).toBe(
      "quota-exceeded",
    );
    expect((await reservePrivateBlob(env.ALTERAN_DB, OTHER)).tag).toBe(
      "reserved",
    );
    const total = await env.ALTERAN_DB.prepare(
      "SELECT COUNT(*) AS count, SUM(reserved_bytes) AS bytes FROM private_blob_staging WHERE repo_did = ?",
    ).bind(DID).first<{ count: number; bytes: number }>();
    expect(total).toEqual({
      count: PRIVATE_BLOB_MAX_RESERVATIONS,
      bytes: PRIVATE_BLOB_MAX_RESERVATIONS * PRIVATE_BLOB_MAX_BYTES,
    });
  });

  it("rejects malformed input and foreign handles without touching an object", async () => {
    const env = await setup();
    const handle = await reservation(env);
    const altered = { ...handle, repoDid: OTHER };
    for (
      const [value, bytes, mime] of [
        [altered, new Uint8Array([1]), "text/plain"],
        [handle, new Uint8Array(PRIVATE_BLOB_MAX_BYTES + 1), "text/plain"],
        [handle, new Uint8Array(), "text/*"],
      ] as const
    ) {
      expect(
        (await stagePrivateBlob(
          env.ALTERAN_DB,
          env.ALTERAN_BLOBS,
          value,
          bytes,
          mime,
        )).tag,
      ).toBe("invalid");
    }
    const detached = new Uint8Array([1]);
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    expect(
      (await stagePrivateBlob(
        env.ALTERAN_DB,
        env.ALTERAN_BLOBS,
        handle,
        detached,
        "text/plain",
      )).tag,
    )
      .toBe("invalid");
    expect((await reservePrivateBlob(env.ALTERAN_DB, "did:example:%ZZ")).tag)
      .toBe("invalid");
    const stored = await row(env, handle);
    expect(stored?.state).toBe("reserved");
    expect(await env.ALTERAN_BLOBS.get(stored!.object_key)).toBeNull();
  });
});
