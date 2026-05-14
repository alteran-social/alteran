import type { Env } from '../env';
import type { D1PreparedStatement } from '@cloudflare/workers-types';
import { drizzle } from 'drizzle-orm/d1';
import { eq } from 'drizzle-orm';
import { repo_root, commit_log } from './schema';
import type { CommitGuard } from './dal';
import { RepoManager } from '../services/repo-manager';
import { createCommit, signCommit, commitCid, generateTid, serializeCommit } from '../lib/commit';
import { CID } from 'multiformats/cid';
import { resolveSecret } from '../lib/secrets';
import { encodeBlocksForCommit } from '../services/car';
import { ServerMisconfigured } from '../lib/errors';
import { assertCommitEventLimits } from '../lib/repo-write-limits';

export class RepoCommitConflictError extends Error {
  constructor(message = 'repo head changed') {
    super(message);
    this.name = 'RepoCommitConflictError';
  }
}

export class RepoBlobNotFoundError extends Error {
  constructor(message = 'blob not found') {
    super(message);
    this.name = 'RepoBlobNotFoundError';
  }
}

export async function getRoot(env: Env) {
  const db = drizzle(env.ALTERAN_DB);
  const did = (await resolveSecret(env.PDS_DID)) ?? 'did:example:single-user';
  return db.select().from(repo_root).where(eq(repo_root.did, did)).get();
}

export async function assertRepoHead(
  env: Env,
  did: string,
  expectedCommitCid: string | null | undefined,
): Promise<void> {
  if (expectedCommitCid === undefined) return;
  if (expectedCommitCid === null) {
    const row = await env.ALTERAN_DB.prepare(
      'SELECT 1 FROM repo_root WHERE did = ? LIMIT 1',
    ).bind(did).first();
    if (row) throw new RepoCommitConflictError();
    return;
  }
  const result = await env.ALTERAN_DB.prepare(
    `UPDATE repo_root
     SET commit_cid = commit_cid
     WHERE did = ? AND commit_cid = ?`,
  ).bind(did, expectedCommitCid).run();
  if (changedRows(result) !== 1) throw new RepoCommitConflictError();
}

/**
 * Bump the repository root to a new revision with signed commit
 */
export async function bumpRoot(env: Env, prevMstRoot?: CID, currentMstRoot?: CID, opts?: {
  ops?: import('../lib/firehose/frames').RepoOp[];
  newMstBlocks?: Array<[CID, Uint8Array]>;
  newRecordBlocks?: Array<[CID, Uint8Array]>;
  sideEffectStatements?: (guard: CommitGuard) => D1PreparedStatement[];
  expectedCommitCid?: string | null;
  requiredBlobKeys?: string[];
}): Promise<{
  commitCid: string;
  rev: string;
  ops: import('../lib/firehose/frames').RepoOp[];
  mstRoot: CID;
  commitData: string;
  sig: string;
  blocks: string; // base64-encoded CAR
}> {
  const db = drizzle(env.ALTERAN_DB);
  const did = (await resolveSecret(env.PDS_DID)) ?? 'did:example:single-user';

  // Falls back to an ephemeral key only in non-production so dev runs work
  // without REPO_SIGNING_KEY; prod always requires the configured key.
  const signingKey = await getSigningKey(env);

  const expectedCommitCid = opts && 'expectedCommitCid' in opts ? opts.expectedCommitCid : undefined;
  const row = expectedCommitCid === undefined
    ? await db.select().from(repo_root).where(eq(repo_root.did, did)).get()
    : undefined;
  const prevCommitCid = expectedCommitCid === undefined
    ? (row?.commitCid ? CID.parse(row.commitCid) : null)
    : (expectedCommitCid ? CID.parse(expectedCommitCid) : null);

  // Prefer caller-provided pointer to avoid an extra MST load on the
  // batched-write path that already knows the new root.
  const repoManager = new RepoManager(env);
  const mstRootCid = currentMstRoot
    ? currentMstRoot
    : await (async () => {
        const mst = await repoManager.getOrCreateRoot();
        return mst.getPointer();
      })();

  // Caller-provided ops avoid the more expensive full-tree diff.
  const ops = opts?.ops !== undefined
    ? opts.ops
    : (prevMstRoot ? await repoManager.extractOps(prevMstRoot, mstRootCid) : []);

  const rev = generateTid();
  const commit = createCommit(did, mstRootCid, rev, prevCommitCid);
  const signedCommit = await signCommit(commit, signingKey);
  const cid = await commitCid(signedCommit);
  const cidString = cid.toString();

  // Serialize commit for storage
  const commitBytes = serializeCommit(signedCommit);
  const commitData = JSON.stringify({
    did: signedCommit.did,
    version: signedCommit.version,
    data: signedCommit.data.toString(),
    rev: signedCommit.rev,
    prev: signedCommit.prev?.toString() || null,
  });
  // Encode signature to base64 (workers-safe)
  let s = '';
  for (const b of signedCommit.sig) s += String.fromCharCode(b);
  const sigBase64 = btoa(s);

  // Encode blocks as CAR for firehose
  const blocksBytes = await encodeBlocksForCommit(
    env,
    cid,
    mstRootCid,
    ops,
    opts?.newMstBlocks,
    commitBytes,
    opts?.newRecordBlocks,
  );
  assertCommitEventLimits(ops.length, blocksBytes.byteLength);
  // Encode to base64 (workers-safe)
  let blocksBase64 = '';
  for (const b of blocksBytes) blocksBase64 += String.fromCharCode(b);
  blocksBase64 = btoa(blocksBase64);

  const ts = Date.now();
  const guard = { did, commitCid: cidString };
  const requiredBlobKeys = Array.from(new Set(opts?.requiredBlobKeys ?? []));
  const rootStatement = rootMutationStatement(env, did, cidString, rev, expectedCommitCid, requiredBlobKeys);
  const blockStatements = blockstorePutStatements(env, [
    ...(opts?.newRecordBlocks ?? []),
    ...(opts?.newMstBlocks ?? []),
  ], guard);
  const statements = [
    rootStatement,
    ...blockStatements,
    ...(opts?.sideEffectStatements?.(guard) ?? []),
    env.ALTERAN_DB.prepare(
      `INSERT INTO commit_log (cid, rev, data, sig, ts)
       SELECT ?, ?, ?, ?, ?
       WHERE EXISTS (
         SELECT 1 FROM repo_root WHERE did = ? AND commit_cid = ?
       )`,
    ).bind(cidString, rev, commitData, sigBase64, ts, did, cidString),
  ];

  const results = await env.ALTERAN_DB.batch(statements);
  if ((expectedCommitCid !== undefined || requiredBlobKeys.length > 0) && changedRows(results[0]) !== 1) {
    if (requiredBlobKeys.length > 0 && await hasMissingBlobKey(env, requiredBlobKeys)) {
      throw new RepoBlobNotFoundError();
    }
    throw new RepoCommitConflictError();
  }

  return { commitCid: cidString, rev, ops, mstRoot: mstRootCid, commitData, sig: sigBase64, blocks: blocksBase64 };
}

function blockstorePutStatements(
  env: Env,
  blocks: Array<[CID, Uint8Array]>,
  guard: CommitGuard,
): D1PreparedStatement[] {
  const deduped = new Map<string, Uint8Array>();
  for (const [cid, bytes] of blocks) {
    deduped.set(cid.toString(), bytes);
  }
  return Array.from(deduped, ([cid, bytes]) =>
    env.ALTERAN_DB.prepare(
      `INSERT OR REPLACE INTO blockstore (cid, bytes)
       SELECT ?, ?
       WHERE EXISTS (
         SELECT 1 FROM repo_root WHERE did = ? AND commit_cid = ?
       )`,
    ).bind(cid, bytesToBase64(bytes), guard.did, guard.commitCid),
  );
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function rootMutationStatement(
  env: Env,
  did: string,
  commitCid: string,
  rev: string,
  expectedCommitCid: string | null | undefined,
  requiredBlobKeys: string[] = [],
): D1PreparedStatement {
  const blobPrecondition = blobPreconditionSql(requiredBlobKeys, did);
  if (expectedCommitCid === null) {
    return env.ALTERAN_DB.prepare(
      `INSERT INTO repo_root (did, commit_cid, rev)
       SELECT ?, ?, ?
       WHERE NOT EXISTS (
         SELECT 1 FROM repo_root WHERE did = ?
       )${blobPrecondition.clause}`,
    ).bind(did, commitCid, rev, did, ...blobPrecondition.binds);
  }
  if (typeof expectedCommitCid === 'string') {
    return env.ALTERAN_DB.prepare(
      `UPDATE repo_root
       SET commit_cid = ?, rev = ?
       WHERE did = ? AND commit_cid = ?${blobPrecondition.clause}`,
    ).bind(commitCid, rev, did, expectedCommitCid, ...blobPrecondition.binds);
  }
  if (requiredBlobKeys.length > 0) {
    return env.ALTERAN_DB.prepare(
      `INSERT INTO repo_root (did, commit_cid, rev)
       SELECT ?, ?, ?
       WHERE ${blobPrecondition.sql}
       ON CONFLICT(did) DO UPDATE SET
         commit_cid = excluded.commit_cid,
         rev = excluded.rev
       WHERE ${blobPrecondition.sql}`,
    ).bind(
      did,
      commitCid,
      rev,
      ...blobPrecondition.binds,
      ...blobPrecondition.binds,
    );
  }
  return env.ALTERAN_DB.prepare(
    `INSERT INTO repo_root (did, commit_cid, rev)
     VALUES (?, ?, ?)
     ON CONFLICT(did) DO UPDATE SET
       commit_cid = excluded.commit_cid,
       rev = excluded.rev`,
  ).bind(did, commitCid, rev);
}

function blobPreconditionSql(requiredBlobKeys: string[], did?: string): { sql: string; clause: string; binds: Array<string | number> } {
  if (requiredBlobKeys.length === 0) {
    return { sql: '1 = 1', clause: '', binds: [] };
  }
  if (!did) {
    throw new Error('did is required for blob preconditions');
  }
  const placeholders = requiredBlobKeys.map(() => '?').join(', ');
  const sql = `(SELECT COUNT(DISTINCT key) FROM blob WHERE did = ? AND key IN (${placeholders})) = ?`;
  return {
    sql,
    clause: ` AND ${sql}`,
    binds: [did, ...requiredBlobKeys, requiredBlobKeys.length],
  };
}

async function hasMissingBlobKey(env: Env, requiredBlobKeys: string[]): Promise<boolean> {
  const did = (await resolveSecret(env.PDS_DID)) ?? 'did:example:single-user';
  const precondition = blobPreconditionSql(requiredBlobKeys, did);
  const row = await env.ALTERAN_DB.prepare(
    `SELECT ${precondition.sql} AS ok`,
  )
    .bind(...precondition.binds)
    .first<{ ok: number }>();
  return row?.ok !== 1;
}

function changedRows(result: unknown): number {
  const meta = (result as { meta?: Record<string, unknown> } | undefined)?.meta;
  const changes = meta?.changes ?? meta?.rows_written ?? meta?.rowsWritten;
  return typeof changes === 'number' ? changes : 0;
}

export async function appendCommit(env: Env, cid: string, rev: string, data: string, sig: string) {
  const db = drizzle(env.ALTERAN_DB);
  const ts = Date.now();

  await db
    .insert(commit_log)
    .values({
      cid,
      rev,
      data,
      sig,
      ts,
    })
    .run();
}

// Cache for dev-mode ephemeral signing key (hex string)
let cachedDevSigningKey: string | undefined;

async function getSigningKey(env: Env): Promise<string> {
  const configured = await resolveSecret((env as any).REPO_SIGNING_KEY);
  if (configured && configured.trim() !== '') return configured.trim();

  const envName = (env as any).ENVIRONMENT || 'development';
  if (envName !== 'production') {
    if (cachedDevSigningKey) return cachedDevSigningKey;
    // Generate an ephemeral secp256k1 keypair and cache private key (hex)
    const { Secp256k1Keypair } = await import('@atproto/crypto');
    const kp = await Secp256k1Keypair.create({ exportable: true });
    const privBytes = await kp.export();
    // to hex
    let hex = '';
    for (const b of privBytes) hex += b.toString(16).padStart(2, '0');
    cachedDevSigningKey = hex;
    return cachedDevSigningKey;
  }

  throw new ServerMisconfigured('REPO_SIGNING_KEY not configured');
}
