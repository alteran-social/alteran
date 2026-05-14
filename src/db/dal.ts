import type { D1PreparedStatement } from '@cloudflare/workers-types';
import { getDb } from './client';
import { record, type NewRecordRow } from './schema';
import type { Env } from '../env';
import { eq, inArray } from 'drizzle-orm';
import { type AccountState, toRow, fromRow } from '../lib/account-state';

export {
  blobKeyHasUsage,
  checkBlobQuota,
  deleteBlobByKey,
  deleteUnreferencedBlobKeys,
  deleteUnreferencedBlobRef,
  getBlobQuota,
  getRecordBlobKeys,
  listOrphanBlobKeys,
  listOrphanBlobRefs,
  putBlobRef,
  registerBlobRefWithQuota,
  sweepEligibleUnreferencedBlobKeys,
  updateBlobQuota,
} from './blob';
export type { BlobKeyRef, BlobRefMetadata, BlobRegistrationResult } from './blob';

export type CommitGuard = {
  did: string;
  commitCid: string;
  rev: string;
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

export async function setRecordBlobUsage(env: Env, did: string, uri: string, keys: string[]) {
  await env.ALTERAN_DB.batch(setRecordBlobUsageStatements(env, did, uri, keys));
}

export async function repairRecordBlobUsageForCurrentRecord(
  env: Env,
  did: string,
  uri: string,
  cid: string,
  keys: string[],
  expectedCommitCid: string,
): Promise<RecordBlobUsageRepairResult> {
  const uniqueKeys = Array.from(new Set(keys));
  const blobPrecondition = blobKeyPreconditionSql(uniqueKeys, did);
  const statements: D1PreparedStatement[] = [
    env.ALTERAN_DB.prepare(
      `UPDATE repo_root
       SET commit_cid = commit_cid
       WHERE did = ?
         AND commit_cid = ?
         AND EXISTS (
           SELECT 1 FROM record
           WHERE uri = ? AND did = ? AND cid = ?
         )${blobPrecondition.clause}`,
    ).bind(did, expectedCommitCid, uri, did, cid, ...blobPrecondition.binds),
    env.ALTERAN_DB.prepare(
      `DELETE FROM blob_usage
       WHERE did = ?
         AND record_uri = ?
         AND EXISTS (
           SELECT 1 FROM repo_root WHERE did = ? AND commit_cid = ?
         )
         AND EXISTS (
           SELECT 1 FROM record WHERE uri = ? AND did = ? AND cid = ?
         )${blobPrecondition.clause}`,
    ).bind(did, uri, did, expectedCommitCid, uri, did, cid, ...blobPrecondition.binds),
  ];
  for (const key of uniqueKeys) {
    statements.push(
      env.ALTERAN_DB.prepare(
        `INSERT OR IGNORE INTO blob_usage (did, record_uri, key, cid, repo_rev)
         SELECT ?, ?, ?, b.cid, root.rev
         FROM blob b
         INNER JOIN repo_root root
           ON root.did = ? AND root.commit_cid = ?
         INNER JOIN record current_record
           ON current_record.uri = ? AND current_record.did = ? AND current_record.cid = ?
         WHERE b.did = ? AND b.key = ?${blobPrecondition.clause}`,
      ).bind(did, uri, key, did, expectedCommitCid, uri, did, cid, did, key, ...blobPrecondition.binds),
    );
  }
  const results = await env.ALTERAN_DB.batch(statements);
  if (changedRows(results[0]) === 1) return { tag: 'repaired' };
  if (uniqueKeys.length > 0 && await hasMissingBlobKey(env, did, uniqueKeys)) {
    return { tag: 'blobNotFound' };
  }
  return { tag: 'conflict' };
}

export type RecordBlobUsageRepairResult =
  | { tag: 'repaired' }
  | { tag: 'blobNotFound' }
  | { tag: 'conflict' };

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
): D1PreparedStatement[] {
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
          `INSERT OR IGNORE INTO blob_usage (did, record_uri, key, cid, repo_rev)
           SELECT ?, ?, ?, b.cid, ?
           FROM blob b
           WHERE b.did = ?
             AND b.key = ?
             AND EXISTS (
               SELECT 1 FROM repo_root WHERE did = ? AND commit_cid = ?
             )`,
        ).bind(did, uri, key, guard.rev, did, key, guard.did, guard.commitCid),
      );
    } else {
      statements.push(
        env.ALTERAN_DB.prepare(
          `INSERT INTO blob_usage (did, record_uri, key, cid, repo_rev)
           SELECT ?, ?, ?, b.cid, COALESCE((SELECT rev FROM repo_root WHERE did = ?), '')
           FROM blob b
           WHERE b.did = ? AND b.key = ?`,
        ).bind(did, uri, key, did, did, key),
      );
    }
  }
  return statements;
}

function changedRows(result: unknown): number {
  const meta = (result as { meta?: Record<string, unknown> } | undefined)?.meta;
  const changes = meta?.changes ?? meta?.rows_written ?? meta?.rowsWritten;
  return typeof changes === 'number' ? changes : 0;
}

function blobKeyPreconditionSql(keys: string[], did: string): { sql: string; clause: string; binds: Array<string | number> } {
  if (keys.length === 0) return { sql: '1 = 1', clause: '', binds: [] };
  const placeholders = keys.map(() => '?').join(', ');
  const sql = `(SELECT COUNT(DISTINCT key) FROM blob WHERE did = ? AND key IN (${placeholders})) = ?`;
  return {
    sql,
    clause: ` AND ${sql}`,
    binds: [did, ...keys, keys.length],
  };
}

async function hasMissingBlobKey(env: Env, did: string, keys: string[]): Promise<boolean> {
  const precondition = blobKeyPreconditionSql(keys, did);
  const row = await env.ALTERAN_DB.prepare(
    `SELECT ${precondition.sql} AS ok`,
  )
    .bind(...precondition.binds)
    .first<{ ok: number }>();
  return row?.ok !== 1;
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
