import type { D1Database, R2Bucket, R2Object } from '@cloudflare/workers-types';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import {
  ACTIVE_PRIVATE_BLOB_OWNER, capturePrivateBlobReservation, getPrivateBlobStatus,
  isPrivateBlobMime, PRIVATE_BLOB_MAX_BYTES, privateBlobKey, randomHex,
  type PrivateBlobReservation,
} from './private-blob-reservation';

export {
  getPrivateBlobStatus, preparePrivateBlobReservation, reservePrivateBlob,
  PRIVATE_BLOB_MAX_BYTES, PRIVATE_BLOB_MAX_GLOBAL_RESERVATIONS, PRIVATE_BLOB_MAX_RESERVATIONS,
  type PrivateBlobReservation, type PrivateBlobReservationResult, type PrivateBlobStatus,
} from './private-blob-reservation';

export type PrivateBlobStageResult =
  | { readonly tag: 'staged'; readonly cid: string; readonly size: number; readonly mimeType: string }
  | { readonly tag: 'invalid' | 'unavailable' | 'uncertain' };

type PutReceipt = { readonly version: string; readonly etag: string };

/**
 * The caller authenticates the owner and supplies a trusted dedicated private
 * bucket. This internal helper has no upload route, cleanup, or quota release.
 * A PUT with an ambiguous outcome is never retried or treated as absent.
 */
export async function stagePrivateBlob(
  database: D1Database,
  bucket: R2Bucket,
  input: PrivateBlobReservation,
  body: Uint8Array,
  mimeType: string,
): Promise<PrivateBlobStageResult> {
  const handle = capturePrivateBlobReservation(input);
  if (!handle || !isPrivateBlobMime(mimeType)) return { tag: 'invalid' };
  const bytes = copyUploadBytes(body);
  if (!bytes) return { tag: 'invalid' };
  const digest = sha256(bytes);
  const cid = CID.createV1(0x55, createDigest(0x12, digest)).toString();
  const digestHex = hex(digest);
  const claim = randomHex();
  const key = privateBlobKey(handle);
  const identity = [handle.id, handle.token, handle.repoDid, handle.accountIncarnation] as const;
  const payload = [claim, cid, digestHex, bytes.byteLength, mimeType] as const;
  try {
    const result = await database.batch([
      database.prepare(`UPDATE private_blob_staging SET state = 'putting', claim_nonce = ?, cid = ?,
          digest = ?, size = ?, mime_type = ?
        WHERE id = ? AND token = ? AND repo_did = ? AND account_incarnation = ? AND object_key = ?
          AND state = 'reserved' AND ${ACTIVE_PRIVATE_BLOB_OWNER}`)
        .bind(...payload, ...identity, key, handle.repoDid, handle.accountIncarnation),
      database.prepare(`SELECT CASE WHEN EXISTS (SELECT 1 FROM private_blob_staging
        WHERE id = ? AND token = ? AND repo_did = ? AND account_incarnation = ? AND object_key = ?
          AND state = 'putting' AND claim_nonce = ? AND cid = ? AND digest = ? AND size = ? AND mime_type = ?
          AND ${ACTIVE_PRIVATE_BLOB_OWNER}) THEN 1 ELSE json('{') END AS valid`)
        .bind(...identity, key, ...payload, handle.repoDid, handle.accountIncarnation),
    ]);
    if (!validBatch(result, 2) || result[1].results?.[0]?.valid !== 1) return { tag: 'unavailable' };
  } catch {
    return await stageAfterFailure(database, handle, cid, bytes.byteLength, mimeType);
  }

  let receipt: PutReceipt;
  try {
    const object = await bucket.put(key, bytes, { sha256: new Uint8Array(digest), onlyIf: { etagDoesNotMatch: '*' } });
    const checked = checkedPut(object, key, bytes.byteLength, digest);
    if (!checked) {
      await markUncertain(database, handle, claim);
      return { tag: 'uncertain' };
    }
    receipt = checked;
  } catch {
    await markUncertain(database, handle, claim);
    return { tag: 'uncertain' };
  }

  try {
    const result = await database.batch([
      database.prepare(`UPDATE private_blob_staging SET state = 'ready', r2_version = ?, etag = ?
        WHERE id = ? AND token = ? AND repo_did = ? AND account_incarnation = ? AND object_key = ?
          AND state = 'putting' AND claim_nonce = ? AND cid = ? AND digest = ? AND size = ? AND mime_type = ?`)
        .bind(receipt.version, receipt.etag, ...identity, key, ...payload),
      database.prepare(`SELECT CASE WHEN EXISTS (SELECT 1 FROM private_blob_staging
        WHERE id = ? AND token = ? AND repo_did = ? AND account_incarnation = ? AND object_key = ?
          AND state = 'ready' AND claim_nonce = ? AND cid = ? AND digest = ? AND size = ? AND mime_type = ?
          AND r2_version = ? AND etag = ?) THEN 1 ELSE json('{') END AS valid`)
        .bind(...identity, key, ...payload, receipt.version, receipt.etag),
      database.prepare(`SELECT ${ACTIVE_PRIVATE_BLOB_OWNER} AS active`).bind(handle.repoDid, handle.accountIncarnation),
    ]);
    if (!validBatch(result, 3) || result[1].results?.[0]?.valid !== 1) return { tag: 'uncertain' };
    const rows = result[2].results;
    if (!rows || rows.length !== 1 || (rows[0].active !== 0 && rows[0].active !== 1)) return { tag: 'uncertain' };
    if (rows[0].active !== 1) return { tag: 'invalid' };
    return { tag: 'staged', cid, size: bytes.byteLength, mimeType };
  } catch {
    return await stageAfterFailure(database, handle, cid, bytes.byteLength, mimeType);
  }
}

async function stageAfterFailure(
  database: D1Database, handle: PrivateBlobReservation, cid: string, size: number, mimeType: string,
): Promise<PrivateBlobStageResult> {
  const status = await getPrivateBlobStatus(database, handle);
  if (status.tag === 'staged' && status.cid === cid && status.size === size && status.mimeType === mimeType) return status;
  if (status.tag === 'putting' || status.tag === 'uncertain') return { tag: 'uncertain' };
  if (status.tag === 'invalid') return { tag: 'invalid' };
  return { tag: 'unavailable' };
}

async function markUncertain(database: D1Database, handle: PrivateBlobReservation, claim: string): Promise<void> {
  try {
    const identity = [handle.id, handle.token, handle.repoDid, handle.accountIncarnation, claim] as const;
    await database.batch([
      database.prepare(`UPDATE private_blob_staging SET state = 'uncertain' WHERE id = ? AND token = ?
        AND repo_did = ? AND account_incarnation = ? AND claim_nonce = ? AND state = 'putting'`).bind(...identity),
      database.prepare(`SELECT CASE WHEN EXISTS (SELECT 1 FROM private_blob_staging WHERE id = ? AND token = ?
        AND repo_did = ? AND account_incarnation = ? AND claim_nonce = ? AND state = 'uncertain')
        THEN 1 ELSE json('{') END AS valid`).bind(...identity),
    ]);
  } catch {
    // An unchanged putting row retains its full charge.
  }
}

function copyUploadBytes(input: unknown): Uint8Array | null {
  if (!ArrayBuffer.isView(input) || !(input instanceof Uint8Array)) return null;
  try {
    const prototype = Object.getPrototypeOf(Uint8Array.prototype);
    const length = Object.getOwnPropertyDescriptor(prototype, 'byteLength')?.get?.call(input);
    const offset = Object.getOwnPropertyDescriptor(prototype, 'byteOffset')?.get?.call(input);
    const buffer = Object.getOwnPropertyDescriptor(prototype, 'buffer')?.get?.call(input);
    if (!Number.isSafeInteger(length) || length < 0 || length > PRIVATE_BLOB_MAX_BYTES ||
      !Number.isSafeInteger(offset) || offset < 0 || !(buffer instanceof ArrayBuffer)) return null;
    return new Uint8Array(buffer, offset, length).slice();
  } catch {
    return null;
  }
}

function checkedPut(object: R2Object | null, key: string, size: number, digest: Uint8Array): PutReceipt | null {
  if (!object) return null;
  const actualKey = object.key, actualSize = object.size, version = object.version, etag = object.etag;
  const checksum = object.checksums?.sha256;
  if (actualKey !== key || actualSize !== size || !validMetadata(version) || !validMetadata(etag) ||
    !(checksum instanceof ArrayBuffer)) return null;
  const actual = new Uint8Array(checksum);
  if (actual.length !== digest.length || !actual.every((value, index) => value === digest[index])) return null;
  return { version, etag };
}

function validMetadata(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 512 && !value.includes('\0') &&
    new TextEncoder().encode(value).byteLength <= 512;
}

function validBatch(results: { success?: boolean }[], count: number): boolean {
  return Array.isArray(results) && results.length === count && results.every((entry) => entry?.success === true);
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
