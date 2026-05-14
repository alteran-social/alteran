import type { D1PreparedStatement } from '@cloudflare/workers-types';
import { getDb } from './client';
import { record, type NewRecordRow, blob_ref, blob_usage, blob_quota } from './schema';
import type { Env } from '../env';
import { eq, inArray, and, sql } from 'drizzle-orm';
import { type AccountState, toRow, fromRow } from '../lib/account-state';

export type CommitGuard = {
  did: string;
  commitCid: string;
  rev: string;
};

export type BlobKeyRef = {
  did: string;
  key: string;
};

export async function putRecord(env: Env, row: NewRecordRow) {
  await env.ALTERAN_DB.batch(putRecordStatements(env, row));
}

export async function getRecord(env: Env, uri: string) {
  const db = getDb(env);
  const result = await db.select().from(record).where(eq(record.uri, uri)).get();
  return result ?? null;
}

export async function deleteRecord(env: Env, uri: string) {
  await env.ALTERAN_DB.batch(deleteRecordStatements(env, uri));
}

export async function listRecords(env: Env) {
  const db = getDb(env);
  return db.select().from(record).all();
}

export async function getRecordsByCids(env: Env, cids: string[]) {
  if (!cids.length) return [] as Awaited<ReturnType<typeof listRecords>>;
  const db = getDb(env);
  return db.select().from(record).where(inArray(record.cid, cids)).all();
}

export async function putBlobRef(env: Env, did: string, cid: string, key: string, mime: string, size: number) {
  const uploadedAt = Date.now();
  await env.ALTERAN_DB.prepare(
    `INSERT INTO blob (
       did, cid, key, mime, size, uploaded_at, created_at, state, temp_key, takedown_ref
     )
     VALUES (?, ?, ?, ?, ?, ?, ?, 'temp', ?, NULL)
     ON CONFLICT(did, cid) DO UPDATE SET
       key = CASE WHEN blob.state = 'permanent' THEN blob.key ELSE excluded.key END,
       mime = CASE WHEN blob.state = 'permanent' THEN blob.mime ELSE excluded.mime END,
       size = CASE WHEN blob.state = 'permanent' THEN blob.size ELSE excluded.size END,
       uploaded_at = CASE WHEN blob.state = 'permanent' THEN blob.uploaded_at ELSE excluded.uploaded_at END,
       created_at = CASE WHEN blob.created_at > 0 THEN blob.created_at ELSE excluded.created_at END,
       state = CASE WHEN blob.state = 'permanent' THEN blob.state ELSE excluded.state END,
       temp_key = CASE WHEN blob.state = 'permanent' THEN blob.temp_key ELSE excluded.temp_key END`,
  )
    .bind(did, cid, key, mime, size, uploadedAt, uploadedAt, key)
    .run();
}

export async function setRecordBlobUsage(env: Env, did: string, uri: string, keys: string[]) {
  await env.ALTERAN_DB.batch(setRecordBlobUsageStatements(env, did, uri, keys));
}

export async function getRecordBlobKeys(env: Env, did: string, uri: string): Promise<string[]> {
  const result = await env.ALTERAN_DB.prepare(
    'SELECT key FROM blob_usage WHERE did = ? AND record_uri = ?',
  )
    .bind(did, uri)
    .all<{ key: string }>();

  return result.results?.map((row) => row.key) ?? [];
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
      'SELECT did, size FROM blob WHERE did = ? AND key = ? LIMIT 1',
    )
      .bind(did, key)
      .first<{ did: string; size: number }>();
    if (!blob) continue;

    // Dereferenced blobs become non-public immediately because blob_usage was
    // removed in the repo commit. Physical deletion is delayed so a concurrent
    // upload of the same content-addressed object is not destroyed underneath a
    // valid follow-up record creation.
    if (!(await isBlobEligibleForPhysicalDeletion(env, did, key))) {
      continue;
    }

    const deletion = await env.ALTERAN_DB.prepare(
      `DELETE FROM blob
       WHERE did = ?
         AND key = ?
         AND NOT EXISTS (
           SELECT 1 FROM blob_usage WHERE did = ? AND key = ?
         )`,
    )
      .bind(did, key, did, key)
      .run();
    if (changedRows(deletion) !== 1) {
      continue;
    }

    const stillStored = await env.ALTERAN_DB.prepare(
      'SELECT 1 FROM blob WHERE key = ? LIMIT 1',
    ).bind(key).first();
    if (!stillStored) {
      try {
        await env.ALTERAN_BLOBS.delete(key);
      } catch {
        // Metadata is the visibility gate. Failed object deletes should not
        // resurrect dereferenced blobs.
      }
    }

    await updateBlobQuota(env, blob.did, -Number(blob.size), -1);
    deleted++;
  }

  return deleted;
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

async function isBlobEligibleForPhysicalDeletion(env: Env, did: string, key: string): Promise<boolean> {
  const graceMs = 60 * 60 * 1000;
  const cutoff = Date.now() - graceMs;
  const row = await env.ALTERAN_DB.prepare(
    'SELECT uploaded_at FROM blob WHERE did = ? AND key = ? LIMIT 1',
  )
    .bind(did, key)
    .first<{ uploaded_at: number }>();
  return row !== null && Number(row.uploaded_at) <= cutoff;
}

function changedRows(result: unknown): number {
  const meta = (result as { meta?: Record<string, unknown> } | undefined)?.meta;
  const changes = meta?.changes ?? meta?.rows_written ?? meta?.rowsWritten;
  return typeof changes === 'number' ? changes : 0;
}

export function putRecordStatements(
  env: Env,
  row: NewRecordRow,
  guard?: CommitGuard,
): D1PreparedStatement[] {
  const toInsert: NewRecordRow = {
    ...row,
    createdAt: row.createdAt ?? Date.now(),
  };
  if (guard) {
    return [
      env.ALTERAN_DB.prepare(
        `INSERT OR IGNORE INTO record (uri, did, cid, json, created_at)
         SELECT ?, ?, ?, ?, ?
         WHERE EXISTS (
           SELECT 1 FROM repo_root WHERE did = ? AND commit_cid = ?
         )`,
      ).bind(
        toInsert.uri,
        toInsert.did,
        toInsert.cid,
        toInsert.json,
        toInsert.createdAt ?? 0,
        guard.did,
        guard.commitCid,
      ),
      env.ALTERAN_DB.prepare(
        `UPDATE record
         SET cid = ?, json = ?
         WHERE uri = ?
           AND EXISTS (
             SELECT 1 FROM repo_root WHERE did = ? AND commit_cid = ?
           )`,
      ).bind(toInsert.cid, toInsert.json, toInsert.uri, guard.did, guard.commitCid),
    ];
  }
  return [
    env.ALTERAN_DB.prepare(
      `INSERT INTO record (uri, did, cid, json, created_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(uri) DO UPDATE SET
         cid = excluded.cid,
         json = excluded.json`,
    ).bind(
      toInsert.uri,
      toInsert.did,
      toInsert.cid,
      toInsert.json,
      toInsert.createdAt ?? 0,
    ),
  ];
}

export function deleteRecordStatements(
  env: Env,
  uri: string,
  guard?: CommitGuard,
): D1PreparedStatement[] {
  if (guard) {
    return [
      env.ALTERAN_DB.prepare(
        `DELETE FROM record
         WHERE uri = ?
           AND EXISTS (
             SELECT 1 FROM repo_root WHERE did = ? AND commit_cid = ?
           )`,
      ).bind(uri, guard.did, guard.commitCid),
    ];
  }
  return [
    env.ALTERAN_DB.prepare('DELETE FROM record WHERE uri = ?').bind(uri),
  ];
}

export function setRecordBlobUsageStatements(
  env: Env,
  did: string,
  uri: string,
  keys: string[],
  guard?: CommitGuard,
  recordCid?: string,
): D1PreparedStatement[] {
  const now = Date.now();
  const statements: D1PreparedStatement[] = [
    guard
      ? env.ALTERAN_DB.prepare(
        `DELETE FROM blob_usage
         WHERE did = ?
           AND record_uri = ?
           AND EXISTS (
             SELECT 1 FROM repo_root WHERE did = ? AND commit_cid = ?
           )`,
      ).bind(did, uri, guard.did, guard.commitCid)
      : env.ALTERAN_DB.prepare('DELETE FROM blob_usage WHERE did = ? AND record_uri = ?').bind(did, uri),
  ];
  for (const key of new Set(keys)) {
    if (guard) {
      statements.push(
        env.ALTERAN_DB.prepare(
          `UPDATE blob
           SET state = 'permanent'
           WHERE did = ?
             AND key = ?
             AND takedown_ref IS NULL
             AND EXISTS (
               SELECT 1 FROM repo_root WHERE did = ? AND commit_cid = ?
             )`,
        ).bind(did, key, guard.did, guard.commitCid),
      );
      statements.push(
        env.ALTERAN_DB.prepare(
          `INSERT OR IGNORE INTO blob_usage (
             did, record_uri, key, record_cid, commit_cid, commit_rev, created_at
           )
           SELECT ?, ?, ?, ?, ?, ?, ?
           WHERE EXISTS (
             SELECT 1 FROM repo_root WHERE did = ? AND commit_cid = ?
           )`,
        ).bind(did, uri, key, recordCid ?? null, guard.commitCid, guard.rev, now, guard.did, guard.commitCid),
      );
    } else {
      statements.push(
        env.ALTERAN_DB.prepare(
          `UPDATE blob
           SET state = 'permanent'
           WHERE did = ? AND key = ? AND takedown_ref IS NULL`,
        ).bind(did, key),
      );
      statements.push(
        env.ALTERAN_DB.prepare(
          `INSERT INTO blob_usage (
             did, record_uri, key, record_cid, commit_cid, commit_rev, created_at
           )
           VALUES (?, ?, ?, ?, NULL, NULL, ?)`,
        ).bind(did, uri, key, recordCid ?? null, now),
      );
    }
  }
  return statements;
}

export async function listOrphanBlobKeys(env: Env): Promise<string[]> {
  return (await listOrphanBlobRefs(env)).map((ref) => ref.key);
}

export async function listOrphanBlobRefs(env: Env): Promise<BlobKeyRef[]> {
  const db = getDb(env);
  // select blob rows that are not referenced in blob_usage for the same DID
  const all = await db.select().from(blob_ref).all();
  const used = new Set((await db.select().from(blob_usage).all()).map((u) => `${u.did}\0${u.key}`));
  return all
    .filter((blob) => !used.has(`${blob.did}\0${blob.key}`))
    .map((blob) => ({ did: blob.did, key: blob.key }));
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

  return (quota.total_bytes + additionalBytes) <= maxBytes;
}

// Account state management for migration support. Reads/writes route through
// the AccountState FSM so the persisted row stays consistent with whatever the
// firehose broadcast emits.
export async function getAccountState(env: Env, did: string): Promise<AccountState | null> {
  const db = getDb(env);
  const { account_state } = await import('./schema');
  const row = await db.select().from(account_state).where(eq(account_state.did, did)).get();
  return row ? fromRow(row) : null;
}

export async function setAccountState(env: Env, did: string, state: AccountState): Promise<void> {
  const db = getDb(env);
  const { account_state } = await import('./schema');
  const row = toRow(state);
  await db
    .insert(account_state)
    .values({ did, ...row, created_at: Date.now() })
    .onConflictDoUpdate({
      target: account_state.did,
      set: row,
    })
    .run();
}

export async function createAccountState(env: Env, did: string, active: boolean = false): Promise<void> {
  await setAccountState(env, did, active ? { tag: 'active' } : { tag: 'deactivated' });
}

export async function setAccountActive(env: Env, did: string, active: boolean): Promise<void> {
  await setAccountState(env, did, active ? { tag: 'active' } : { tag: 'deactivated' });
}

export async function isAccountActive(env: Env, did: string): Promise<boolean> {
  const state = await getAccountState(env, did);
  // If no account state row exists, assume active (backward compatibility
  // with rows that predate the migration).
  return state === null ? true : state.tag === 'active';
}
