import type { D1Database, R2Bucket, R2Object } from "@cloudflare/workers-types";
import { isSpaceDid } from "./space-did";
import { sha256 } from "@noble/hashes/sha2.js";
import { CID } from "multiformats/cid";
import { create as createDigest } from "multiformats/hashes/digest";
import { copyPlainRecord } from "./plain-values";

export const PRIVATE_BLOB_MAX_BYTES = 5 * 1024 * 1024;
export const PRIVATE_BLOB_MAX_RESERVATIONS = 64;

export type PrivateBlobReservation = {
  readonly id: string;
  readonly token: string;
  readonly repoDid: string;
};

export type PrivateBlobReservationResult =
  | { readonly tag: "reserved"; readonly reservation: PrivateBlobReservation }
  | { readonly tag: "invalid" | "quota-exceeded" | "unavailable" };

export type PrivateBlobStageResult =
  | {
    readonly tag: "staged";
    readonly cid: string;
    readonly size: number;
    readonly mimeType: string;
  }
  | { readonly tag: "invalid" | "unavailable" | "uncertain" };

type ClaimedJob = { object_key: string };

/**
 * Internal staging foundation. Callers authenticate and bind repoDid before
 * reserving; these helpers do not authorize a Space or expose an HTTP route.
 * The isolated test schema is not a production quota or migration. Every job
 * permanently reserves one full-size slot, including failed or uncertain PUTs.
 */
export async function reservePrivateBlob(
  database: D1Database,
  repoDid: string,
): Promise<PrivateBlobReservationResult> {
  if (!isSpaceDid(repoDid)) return { tag: "invalid" };
  const id = crypto.randomUUID();
  const token = crypto.randomUUID();
  const key = `space-staging/${crypto.randomUUID()}`;
  try {
    await database.prepare(
      `INSERT INTO private_blob_staging (id, token, repo_did, object_key, state, reserved_bytes)
       SELECT ?, ?, ?, ?, 'reserved', ? WHERE
         (SELECT COUNT(*) FROM private_blob_staging WHERE repo_did = ?) < ?`,
    ).bind(
      id,
      token,
      repoDid,
      key,
      PRIVATE_BLOB_MAX_BYTES,
      repoDid,
      PRIVATE_BLOB_MAX_RESERVATIONS,
    ).run();
    const row = await database.prepare(
      `SELECT id FROM private_blob_staging
       WHERE id = ? AND token = ? AND repo_did = ? AND object_key = ? AND state = 'reserved'`,
    ).bind(id, token, repoDid, key).first<{ id: string }>();
    if (!row) return { tag: "quota-exceeded" };
    return {
      tag: "reserved",
      reservation: Object.freeze({ id, token, repoDid }),
    };
  } catch {
    return { tag: "unavailable" };
  }
}

/**
 * Consume a reservation once. The caller must reserve before reading a request
 * body; this bounded helper accepts an already-buffered copy, not a stream.
 * A PUT with an unknown outcome is never retried, deleted, or uncharged here.
 */
export async function stagePrivateBlob(
  database: D1Database,
  bucket: R2Bucket,
  input: PrivateBlobReservation,
  body: Uint8Array,
  mimeType: string,
): Promise<PrivateBlobStageResult> {
  const reservation = copyPlainRecord(input, ["id", "token", "repoDid"]);
  if (
    !reservation || !validUuid(reservation.id) ||
    !validUuid(reservation.token) ||
    !isSpaceDid(reservation.repoDid) || !validMime(mimeType)
  ) return { tag: "invalid" };
  let bytes: Uint8Array;
  try {
    if (
      !ArrayBuffer.isView(body) || !(body instanceof Uint8Array) ||
      Object.getPrototypeOf(body) !== Uint8Array.prototype ||
      Object.hasOwn(body, "byteLength") ||
      body.byteLength > PRIVATE_BLOB_MAX_BYTES
    ) return { tag: "invalid" };
    bytes = new Uint8Array(body);
  } catch {
    return { tag: "invalid" };
  }
  const digest = sha256(bytes);
  const cid = CID.createV1(0x55, createDigest(0x12, digest)).toString();
  const digestHex = hex(digest);
  const claim = crypto.randomUUID();
  const { id, token, repoDid } = reservation;
  let job: ClaimedJob | undefined;
  try {
    const [, selected] = await database.batch([
      database.prepare(
        `UPDATE private_blob_staging SET state = 'putting', claim_nonce = ?, cid = ?,
          digest = ?, size = ?, mime_type = ?
         WHERE id = ? AND token = ? AND repo_did = ? AND state = 'reserved'`,
      ).bind(
        claim,
        cid,
        digestHex,
        bytes.byteLength,
        mimeType,
        id,
        token,
        repoDid,
      ),
      database.prepare(
        `SELECT object_key FROM private_blob_staging
         WHERE id = ? AND token = ? AND repo_did = ? AND state = 'putting' AND claim_nonce = ?
           AND cid = ? AND digest = ? AND size = ? AND mime_type = ?`,
      ).bind(
        id,
        token,
        repoDid,
        claim,
        cid,
        digestHex,
        bytes.byteLength,
        mimeType,
      ),
    ]);
    job = selected.results?.[0] as ClaimedJob | undefined;
  } catch {
    return { tag: "unavailable" };
  }
  if (!job || typeof job.object_key !== "string") return { tag: "invalid" };

  let metadata: { readonly version: string; readonly etag: string };
  try {
    const object = await bucket.put(job.object_key, bytes, {
      sha256: new Uint8Array(digest),
      onlyIf: { etagDoesNotMatch: "*" },
    });
    const checked = checkedPut(
      object,
      job.object_key,
      bytes.byteLength,
      digest,
    );
    if (!checked) {
      await markUncertain(database, id, token, repoDid, claim);
      return { tag: "uncertain" };
    }
    metadata = checked;
  } catch {
    await markUncertain(database, id, token, repoDid, claim);
    return { tag: "uncertain" };
  }
  try {
    const identity = [
      id,
      token,
      repoDid,
      claim,
      job.object_key,
      cid,
      digestHex,
      bytes.byteLength,
      mimeType,
    ] as const;
    const [, checked] = await database.batch([
      database.prepare(
        `UPDATE private_blob_staging SET state = 'ready', r2_version = ?, etag = ?
         WHERE id = ? AND token = ? AND repo_did = ? AND state = 'putting' AND claim_nonce = ?
           AND object_key = ? AND cid = ? AND digest = ? AND size = ? AND mime_type = ?`,
      ).bind(metadata.version, metadata.etag, ...identity),
      database.prepare(
        `SELECT CASE WHEN EXISTS (
           SELECT 1 FROM private_blob_staging WHERE id = ? AND token = ? AND repo_did = ?
             AND state = 'ready' AND claim_nonce = ? AND object_key = ? AND cid = ?
             AND digest = ? AND size = ? AND mime_type = ? AND r2_version = ? AND etag = ?
         ) THEN 1 ELSE json('{') END AS valid`,
      ).bind(...identity, metadata.version, metadata.etag),
    ]);
    if (checked.results?.[0]?.valid !== 1) return { tag: "uncertain" };
    return { tag: "staged", cid, size: bytes.byteLength, mimeType };
  } catch {
    return { tag: "uncertain" };
  }
}

async function markUncertain(
  database: D1Database,
  id: unknown,
  token: unknown,
  repoDid: unknown,
  claim: string,
): Promise<void> {
  try {
    await database.prepare(
      `UPDATE private_blob_staging SET state = 'uncertain'
       WHERE id = ? AND token = ? AND repo_did = ? AND state = 'putting' AND claim_nonce = ?`,
    ).bind(id, token, repoDid, claim).run();
  } catch {
    // A remaining putting row retains the full quota charge.
  }
}

function checkedPut(
  object: R2Object | null,
  key: string,
  size: number,
  digest: Uint8Array,
): { readonly version: string; readonly etag: string } | null {
  if (!object) return null;
  const actualKey = object.key;
  const actualSize = object.size;
  const version = object.version;
  const etag = object.etag;
  const checksum = object.checksums?.sha256;
  if (
    actualKey !== key || actualSize !== size ||
    typeof version !== "string" || !version ||
    typeof etag !== "string" || !etag ||
    !(checksum instanceof ArrayBuffer)
  ) return null;
  const actual = new Uint8Array(checksum);
  if (
    actual.length !== digest.length ||
    !actual.every((value, index) => value === digest[index])
  ) return null;
  return { version, etag };
}

function validUuid(value: unknown): value is string {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
      .test(value);
}

function validMime(value: unknown): value is string {
  return typeof value === "string" && value.length <= 255 &&
    /^[A-Za-z0-9!#$%&'+.^_`|~-]+\/[A-Za-z0-9!#$%&'+.^_`|~-]+$/.test(value);
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}
