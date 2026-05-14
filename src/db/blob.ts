import { eq, sql } from 'drizzle-orm';
import { getDb } from './client';
import { blob_ref, blob_quota } from './schema';
import type { Env } from '../env';

export type BlobKeyRef = {
  did: string;
  key: string;
};

export type BlobRefMetadata = {
  did: string;
  cid: string;
  key: string;
  mime: string;
  size: number;
  uploadedAt: number;
};

export type BlobRegistrationResult =
  | { tag: 'registered'; blob: BlobRefMetadata }
  | { tag: 'alreadyExists'; blob: BlobRefMetadata }
  | { tag: 'quotaExceeded' };

export async function putBlobRef(env: Env, did: string, cid: string, key: string, mime: string, size: number) {
  const db = getDb(env);
  const uploadedAt = Date.now();
  await db
    .insert(blob_ref)
    .values({ did, cid, key, mime, size, uploadedAt })
    .onConflictDoUpdate({
      target: [blob_ref.did, blob_ref.cid],
      set: {
        key: sql.raw(`excluded.${blob_ref.key.name}`),
        mime: sql.raw(`excluded.${blob_ref.mime.name}`),
        size: sql.raw(`excluded.${blob_ref.size.name}`),
        uploadedAt: sql.raw(`excluded.${blob_ref.uploadedAt.name}`),
      },
    });
}

export async function registerBlobRefWithQuota(
  env: Env,
  did: string,
  cid: string,
  key: string,
  mime: string,
  size: number,
): Promise<BlobRegistrationResult> {
  const existing = await getBlobRef(env, did, cid);
  if (existing) {
    const uploadedAt = Date.now();
    await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(
        `UPDATE blob
         SET uploaded_at = ?
         WHERE did = ? AND cid = ?`,
      ).bind(uploadedAt, did, cid),
      env.ALTERAN_DB.prepare(
        `UPDATE blob_quota
         SET updated_at = ?
         WHERE did = ?`,
      ).bind(uploadedAt, did),
    ]);
    return { tag: 'alreadyExists', blob: { ...existing, uploadedAt } };
  }

  const quotaBytes = parseInt(env.PDS_BLOB_QUOTA_BYTES || '10737418240', 10);
  const maxBytes = Number.isFinite(quotaBytes) && quotaBytes > 0 ? quotaBytes : 10737418240;
  const uploadedAt = Date.now();
  const results = await env.ALTERAN_DB.batch([
    env.ALTERAN_DB.prepare(
      `INSERT OR IGNORE INTO blob_quota (did, total_bytes, blob_count, updated_at)
       VALUES (?, 0, 0, ?)`,
    ).bind(did, uploadedAt),
    env.ALTERAN_DB.prepare(
      `UPDATE blob_quota
       SET updated_at = ?
       WHERE did = ?`,
    ).bind(uploadedAt, did),
    env.ALTERAN_DB.prepare(
      `INSERT OR IGNORE INTO blob (did, cid, key, mime, size, uploaded_at)
       SELECT ?, ?, ?, ?, ?, ?
       FROM blob_quota
       WHERE did = ?
         AND total_bytes + ? <= ?`,
    ).bind(did, cid, key, mime, size, uploadedAt, did, size, maxBytes),
    env.ALTERAN_DB.prepare(
      `UPDATE blob_quota
       SET total_bytes = (
             SELECT COALESCE(SUM(size), 0) FROM blob WHERE did = ?
           ),
           blob_count = (
             SELECT COUNT(*) FROM blob WHERE did = ?
           ),
           updated_at = ?
       WHERE did = ?`,
    ).bind(did, did, Date.now(), did),
  ]);

  const blob = await getBlobRef(env, did, cid);
  if (blob && changedRows(results[2]) === 1) return { tag: 'registered', blob };
  if (blob) return { tag: 'alreadyExists', blob };
  return { tag: 'quotaExceeded' };
}

export async function getRecordBlobKeys(env: Env, did: string, uri: string): Promise<string[]> {
  const result = await env.ALTERAN_DB.prepare(
    'SELECT key FROM blob_usage WHERE did = ? AND record_uri = ?',
  )
    .bind(did, uri)
    .all<{ key: string }>();

  return result.results?.map((row: { key: string }) => row.key) ?? [];
}

export async function blobKeyHasUsage(env: Env, did: string, key: string): Promise<boolean> {
  const row = await env.ALTERAN_DB.prepare(
    'SELECT 1 FROM blob_usage WHERE did = ? AND key = ? LIMIT 1',
  )
    .bind(did, key)
    .first();

  return row !== null;
}

export async function deleteUnreferencedBlobKeys(
  env: Env,
  refs: readonly BlobKeyRef[],
): Promise<number> {
  let deleted = 0;
  for (const { did, key } of uniqueBlobKeyRefs(refs)) {
    const blob = await env.ALTERAN_DB.prepare(
      'SELECT 1 FROM blob WHERE did = ? AND key = ? LIMIT 1',
    )
      .bind(did, key)
      .first();
    if (!blob) continue;

    const cutoff = blobDeletionCutoff();
    const object = await env.ALTERAN_BLOBS.head(key);
    if (object && !uploadedBeforeCutoff(object, cutoff)) continue;

    const [deletion] = await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(
        `DELETE FROM blob
         WHERE did = ?
           AND key = ?
           AND uploaded_at <= ?
           AND NOT EXISTS (
             SELECT 1 FROM blob_usage WHERE did = ? AND key = ?
           )`,
      ).bind(did, key, cutoff, did, key),
      recomputeQuotaStatement(env, did),
    ]);
    if (changedRows(deletion) !== 1) continue;

    // R2 deletes cannot share D1's commit guard. Metadata is the visibility
    // gate; object cleanup needs a separate lease/tombstone flow.
    deleted++;
  }

  return deleted;
}

export async function sweepEligibleUnreferencedBlobKeys(
  env: Env,
  options: { did?: string; limit?: number } = {},
): Promise<number> {
  return deleteUnreferencedBlobKeys(env, await listOrphanBlobRefs(env, {
    did: options.did,
    limit: options.limit ?? 100,
  }));
}

export async function listOrphanBlobKeys(env: Env): Promise<string[]> {
  return (await listOrphanBlobRefs(env)).map((ref) => ref.key);
}

export async function listOrphanBlobRefs(
  env: Env,
  options: { did?: string; limit?: number } = {},
): Promise<BlobKeyRef[]> {
  const limit = Math.max(1, Math.min(options.limit ?? 100, 1000));
  const cutoff = blobDeletionCutoff();
  const result = options.did
    ? await env.ALTERAN_DB.prepare(
      `SELECT did, key
       FROM blob b
       WHERE b.did = ?
         AND b.uploaded_at <= ?
         AND NOT EXISTS (
           SELECT 1 FROM blob_usage u WHERE u.did = b.did AND u.key = b.key
         )
       ORDER BY b.uploaded_at, b.did, b.key
       LIMIT ?`,
    ).bind(options.did, cutoff, limit).all<BlobKeyRef>()
    : await env.ALTERAN_DB.prepare(
      `SELECT did, key
       FROM blob b
       WHERE b.uploaded_at <= ?
         AND NOT EXISTS (
           SELECT 1 FROM blob_usage u WHERE u.did = b.did AND u.key = b.key
         )
       ORDER BY b.uploaded_at, b.did, b.key
       LIMIT ?`,
    ).bind(cutoff, limit).all<BlobKeyRef>();
  return result.results ?? [];
}

export async function deleteBlobByKey(env: Env, key: string) {
  const db = getDb(env);
  await db.delete(blob_ref).where(eq(blob_ref.key, key)).run();
}

export async function getBlobQuota(env: Env, did: string) {
  const db = getDb(env);
  const quota = await db.select().from(blob_quota).where(eq(blob_quota.did, did)).get();
  return quota ?? { did, total_bytes: 0, blob_count: 0, updated_at: Date.now() };
}

export async function updateBlobQuota(env: Env, did: string, bytesAdded: number, countAdded: number) {
  const db = getDb(env);
  const current = await getBlobQuota(env, did);

  const newTotalBytes = Math.max(0, current.total_bytes + bytesAdded);
  const newBlobCount = Math.max(0, current.blob_count + countAdded);
  const now = Date.now();

  await db
    .insert(blob_quota)
    .values({
      did,
      total_bytes: newTotalBytes,
      blob_count: newBlobCount,
      updated_at: now,
    })
    .onConflictDoUpdate({
      target: blob_quota.did,
      set: {
        total_bytes: sql.raw(`excluded.${blob_quota.total_bytes.name}`),
        blob_count: sql.raw(`excluded.${blob_quota.blob_count.name}`),
        updated_at: sql.raw(`excluded.${blob_quota.updated_at.name}`),
      },
    });
}

export async function checkBlobQuota(env: Env, did: string, additionalBytes: number): Promise<boolean> {
  const quota = await getBlobQuota(env, did);
  const maxBytes = parseInt(env.PDS_BLOB_QUOTA_BYTES || '10737418240', 10);

  return quota.total_bytes + additionalBytes <= maxBytes;
}

export async function deleteUnreferencedBlobRef(env: Env, did: string, cid: string): Promise<void> {
  await env.ALTERAN_DB.batch([
    env.ALTERAN_DB.prepare(
      `DELETE FROM blob
       WHERE did = ?
         AND cid = ?
         AND NOT EXISTS (
           SELECT 1 FROM blob_usage u WHERE u.did = blob.did AND u.key = blob.key
         )`,
    ).bind(did, cid),
    recomputeQuotaStatement(env, did),
  ]);
}

function uniqueBlobKeyRefs(refs: readonly BlobKeyRef[]): BlobKeyRef[] {
  const seen = new Set<string>();
  const unique: BlobKeyRef[] = [];
  for (const ref of refs) {
    const id = `${ref.did}\0${ref.key}`;
    if (seen.has(id)) continue;
    seen.add(id);
    unique.push(ref);
  }
  return unique;
}

function blobDeletionCutoff(): number {
  return Date.now() - 60 * 60 * 1000;
}

function changedRows(result: unknown): number {
  const meta = (result as { meta?: Record<string, unknown> } | undefined)?.meta;
  const changes = meta?.changes ?? meta?.rows_written ?? meta?.rowsWritten;
  return typeof changes === 'number' ? changes : 0;
}

function recomputeQuotaStatement(env: Env, did: string) {
  return env.ALTERAN_DB.prepare(
    `UPDATE blob_quota
     SET total_bytes = (
           SELECT COALESCE(SUM(size), 0) FROM blob WHERE did = ?
         ),
         blob_count = (
           SELECT COUNT(*) FROM blob WHERE did = ?
         ),
         updated_at = ?
     WHERE did = ?`,
  ).bind(did, did, Date.now(), did);
}

async function getBlobRef(env: Env, did: string, cid: string): Promise<BlobRefMetadata | null> {
  const row = await env.ALTERAN_DB.prepare(
    `SELECT did, cid, key, mime, size, uploaded_at as uploadedAt
     FROM blob
     WHERE did = ? AND cid = ?
     LIMIT 1`,
  ).bind(did, cid).first<BlobRefMetadata>();
  return row ?? null;
}

function uploadedBeforeCutoff(object: { uploaded?: Date | string | number }, cutoff: number): boolean {
  const uploaded = object.uploaded;
  if (uploaded instanceof Date) return uploaded.getTime() <= cutoff;
  if (typeof uploaded === 'string' || typeof uploaded === 'number') {
    const timestamp = new Date(uploaded).getTime();
    return Number.isFinite(timestamp) && timestamp <= cutoff;
  }
  return false;
}
