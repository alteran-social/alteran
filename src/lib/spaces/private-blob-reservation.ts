import type { D1Database } from '@cloudflare/workers-types';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { copyPlainRecord } from './plain-values';
import { isSpaceDid } from './space-did';

export const PRIVATE_BLOB_MAX_BYTES = 5 * 1024 * 1024;
export const PRIVATE_BLOB_MAX_RESERVATIONS = 64;
export const PRIVATE_BLOB_MAX_GLOBAL_RESERVATIONS = 256;

/** Internal callers must use preparePrivateBlobReservation; shape validation does not prove provenance. */
export type PrivateBlobReservation = {
  readonly id: string;
  readonly token: string;
  readonly repoDid: string;
  readonly accountIncarnation: string;
};

export type PrivateBlobStatus =
  | { readonly tag: 'reserved' | 'putting' | 'uncertain' }
  | { readonly tag: 'staged'; readonly cid: string; readonly size: number; readonly mimeType: string }
  | { readonly tag: 'invalid' | 'unavailable' };

export type PrivateBlobReservationResult =
  | { readonly tag: 'reserved' | 'invalid' | 'quota-exceeded' | 'unavailable' };

export const ACTIVE_PRIVATE_BLOB_OWNER = `EXISTS (
  SELECT 1 FROM account a JOIN account_state s ON s.did = a.did
  WHERE a.did = ? AND a.space_incarnation = ? AND typeof(s.active) = 'integer' AND s.active = 1
    AND s.status IS NULL AND s.suspended_until IS NULL
)`;

/** The handle must be retained across a lost reservation response. */
export function preparePrivateBlobReservation(repoDid: string, accountIncarnation: string): PrivateBlobReservation | null {
  if (!isBlobRepoDid(repoDid) || !isHex(accountIncarnation, 32)) return null;
  return Object.freeze({ id: randomHex(), token: randomHex(), repoDid, accountIncarnation });
}

export function capturePrivateBlobReservation(input: unknown): PrivateBlobReservation | null {
  const value = copyPlainRecord(input, ['id', 'token', 'repoDid', 'accountIncarnation']);
  if (!value || !isHex(value.id, 32) || !isHex(value.token, 32) || !isBlobRepoDid(value.repoDid) ||
    !isHex(value.accountIncarnation, 32)) return null;
  return Object.freeze({ id: value.id, token: value.token, repoDid: value.repoDid, accountIncarnation: value.accountIncarnation });
}

export function privateBlobKey(handle: PrivateBlobReservation): string {
  return `space-staging/${handle.id}`;
}

export function randomHex(): string {
  return crypto.randomUUID().replaceAll('-', '');
}

export function isHex(value: unknown, length: number): value is string {
  return typeof value === 'string' && value.length === length && !/[^0-9a-f]/.test(value);
}

export function isPrivateBlobMime(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 255 &&
    !/[^\x21-\x7e]/.test(value) &&
    /^[A-Za-z0-9!#$%&'+.^_`|~-]+\/[A-Za-z0-9!#$%&'+.^_`|~-]+$/.test(value);
}

function isBlobRepoDid(value: unknown): value is string {
  return isSpaceDid(value) && !/[^A-Za-z0-9._:%-]/.test(value);
}

/** Reserve before consuming an upload body. Every reservation remains charged. */
export async function reservePrivateBlob(database: D1Database, input: PrivateBlobReservation): Promise<PrivateBlobReservationResult> {
  const handle = capturePrivateBlobReservation(input);
  if (!handle) return { tag: 'invalid' };
  const { id, token, repoDid, accountIncarnation } = handle;
  const key = privateBlobKey(handle);
  try {
    const result = await database.batch([
      database.prepare(`INSERT INTO private_blob_staging
        (id, token, repo_did, account_incarnation, object_key, state, reserved_bytes)
        SELECT ?, ?, ?, ?, ?, 'reserved', ?
        WHERE NOT EXISTS (SELECT 1 FROM private_blob_staging WHERE id = ? OR object_key = ?)
          AND ${ACTIVE_PRIVATE_BLOB_OWNER}
          AND NOT EXISTS (SELECT 1 FROM private_blob_staging INDEXED BY private_blob_staging_owner
            WHERE repo_did = ? LIMIT 1 OFFSET 63)
          AND NOT EXISTS (SELECT 1 FROM private_blob_staging LIMIT 1 OFFSET 255)`)
        .bind(id, token, repoDid, accountIncarnation, key, PRIVATE_BLOB_MAX_BYTES, id, key,
          repoDid, accountIncarnation, repoDid),
      database.prepare(`SELECT ${ACTIVE_PRIVATE_BLOB_OWNER} AS active,
        EXISTS (SELECT 1 FROM private_blob_staging WHERE id = ? AND token = ? AND repo_did = ?
          AND account_incarnation = ? AND object_key = ? AND state = 'reserved'
          AND reserved_bytes = 5242880 AND claim_nonce IS NULL AND cid IS NULL AND digest IS NULL
          AND size IS NULL AND mime_type IS NULL AND r2_version IS NULL AND etag IS NULL) AS reserved,
        EXISTS (SELECT 1 FROM private_blob_staging WHERE id = ?) AS taken,
        EXISTS (SELECT 1 FROM private_blob_staging INDEXED BY private_blob_staging_owner
          WHERE repo_did = ? LIMIT 1 OFFSET 63) AS owner_full,
        EXISTS (SELECT 1 FROM private_blob_staging LIMIT 1 OFFSET 255) AS global_full`)
        .bind(repoDid, accountIncarnation, id, token, repoDid, accountIncarnation, key, id, repoDid),
    ]);
    if (result.length !== 2 || result.some((entry: { success?: boolean }) => entry.success !== true)) return { tag: 'unavailable' };
    const rows = result[1].results as Array<Record<string, unknown>> | undefined;
    if (!rows || rows.length !== 1) return { tag: 'unavailable' };
    const row = rows[0];
    if (row.active !== 1) return { tag: 'invalid' };
    if (row.reserved === 1) return { tag: 'reserved' };
    if (row.taken === 1) return { tag: 'invalid' };
    if (row.owner_full === 1 || row.global_full === 1) return { tag: 'quota-exceeded' };
    return { tag: 'unavailable' };
  } catch {
    const status = await getPrivateBlobStatus(database, handle);
    return status.tag === 'reserved' ? { tag: 'reserved' } : { tag: 'unavailable' };
  }
}

/**
 * Status access is limited to the live account incarnation that reserved the
 * slot. A staged result is a historical PUT receipt, not an R2 health check.
 */
export async function getPrivateBlobStatus(database: D1Database, input: PrivateBlobReservation): Promise<PrivateBlobStatus> {
  const handle = capturePrivateBlobReservation(input);
  if (!handle) return { tag: 'invalid' };
  try {
    const row = await database.prepare(`SELECT
      CASE WHEN typeof(state) = 'text' AND length(CAST(state AS BLOB)) <= 16 THEN state END AS state,
      CASE WHEN typeof(cid) = 'text' AND length(CAST(cid AS BLOB)) = 59 THEN cid END AS cid,
      CASE WHEN typeof(digest) = 'text' AND length(CAST(digest AS BLOB)) = 64 THEN digest END AS digest,
      CASE WHEN typeof(size) = 'integer' AND size BETWEEN 0 AND 5242880 THEN size END AS size,
      CASE WHEN typeof(mime_type) = 'text' AND length(CAST(mime_type AS BLOB)) BETWEEN 3 AND 255
        THEN mime_type END AS mime_type,
      CASE WHEN claim_nonce IS NULL AND cid IS NULL AND digest IS NULL AND size IS NULL AND mime_type IS NULL
        AND r2_version IS NULL AND etag IS NULL THEN 1 ELSE 0 END AS empty_payload,
      CASE WHEN typeof(claim_nonce) = 'text' AND length(claim_nonce) = 32
        AND length(CAST(claim_nonce AS BLOB)) = 32 AND claim_nonce NOT GLOB '*[^0-9a-f]*'
        THEN 1 ELSE 0 END AS claim_valid,
      CASE WHEN r2_version IS NULL AND etag IS NULL THEN 1 ELSE 0 END AS empty_receipt,
      CASE WHEN typeof(r2_version) = 'text' AND length(CAST(r2_version AS BLOB)) BETWEEN 1 AND 512
        AND instr(r2_version, char(0)) = 0 THEN 1 ELSE 0 END AS version_valid,
      CASE WHEN typeof(etag) = 'text' AND length(CAST(etag AS BLOB)) BETWEEN 1 AND 512
        AND instr(etag, char(0)) = 0 THEN 1 ELSE 0 END AS etag_valid
      FROM private_blob_staging WHERE id = ? AND token = ? AND repo_did = ? AND account_incarnation = ?
        AND object_key = ? AND reserved_bytes = 5242880 AND ${ACTIVE_PRIVATE_BLOB_OWNER}`)
      .bind(handle.id, handle.token, handle.repoDid, handle.accountIncarnation, privateBlobKey(handle),
        handle.repoDid, handle.accountIncarnation).first<Record<string, unknown>>();
    if (!row) return { tag: 'invalid' };
    if (row.state === 'reserved') return { tag: row.empty_payload === 1 ? 'reserved' : 'unavailable' };
    if (row.claim_valid !== 1 || !validReceipt(row.cid, row.digest, row.size, row.mime_type)) return { tag: 'unavailable' };
    if (row.state === 'putting' || row.state === 'uncertain') {
      return { tag: row.empty_receipt === 1 ? row.state : 'unavailable' };
    }
    if (row.state !== 'ready' || row.version_valid !== 1 || row.etag_valid !== 1) return { tag: 'unavailable' };
    return { tag: 'staged', cid: row.cid as string, size: row.size as number, mimeType: row.mime_type as string };
  } catch {
    return { tag: 'unavailable' };
  }
}

function validReceipt(cidValue: unknown, digestValue: unknown, size: unknown, mime: unknown): boolean {
  if (typeof cidValue !== 'string' || !isHex(digestValue, 64) || typeof size !== 'number' ||
    !Number.isSafeInteger(size) || size < 0 || size > PRIVATE_BLOB_MAX_BYTES || !isPrivateBlobMime(mime)) return false;
  try {
    const digest = Uint8Array.from(digestValue.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
    return CID.createV1(0x55, createDigest(0x12, digest)).toString() === cidValue;
  } catch {
    return false;
  }
}
