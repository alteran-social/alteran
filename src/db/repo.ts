import type { Env } from '../env';
import { drizzle } from 'drizzle-orm/d1';
import { eq, sql } from 'drizzle-orm';
import { repo_root, commit_log } from './schema';
import { RepoManager } from '../services/repo-manager';
import { createCommit, signCommit, commitCid, generateTid, serializeCommit } from '../lib/commit';
import { CID } from 'multiformats/cid';
import { resolveSecret } from '../lib/secrets';
import { encodeBlocksForCommit } from '../services/car';
import { ServerMisconfigured } from '../lib/errors';

export async function getRoot(env: Env) {
  const db = drizzle(env.DB);
  const did = (await resolveSecret(env.PDS_DID)) ?? 'did:example:single-user';
  return db.select().from(repo_root).where(eq(repo_root.did, did)).get();
}

/**
 * Bump the repository root to a new revision with signed commit
 */
export async function bumpRoot(env: Env, prevMstRoot?: CID, currentMstRoot?: CID, opts?: {
  ops?: import('../lib/firehose/frames').RepoOp[];
  newMstBlocks?: Array<[CID, Uint8Array]>;
}): Promise<{
  commitCid: string;
  rev: string;
  ops: import('../lib/firehose/frames').RepoOp[];
  mstRoot: CID;
  commitData: string;
  sig: string;
  blocks: string; // base64-encoded CAR
}> {
  const db = drizzle(env.DB);
  const did = (await resolveSecret(env.PDS_DID)) ?? 'did:example:single-user';

  // Resolve signing key (use ephemeral dev key if not configured and not production)
  const signingKey = await getSigningKey(env);

  // Get current repo state
  const row = await db.select().from(repo_root).where(eq(repo_root.did, did)).get();
  const prevCommitCid = row?.commitCid ? CID.parse(row.commitCid) : null;

  // Get the current MST root (prefer caller-provided pointer if available)
  const repoManager = new RepoManager(env);
  const mstRootCid = currentMstRoot
    ? currentMstRoot
    : await (async () => {
        const mst = await repoManager.getOrCreateRoot();
        return mst.getPointer();
      })();

  // Use provided ops if available; else compute by diffing trees (more expensive)
  const ops = opts?.ops !== undefined
    ? opts.ops
    : (prevMstRoot ? await repoManager.extractOps(prevMstRoot, mstRootCid) : []);

  // Generate new revision (TID)
  const rev = generateTid();

  // Create commit
  const commit = createCommit(did, mstRootCid, rev, prevCommitCid);

  // Sign commit
  const signedCommit = await signCommit(commit, signingKey);

  // Calculate commit CID
  const cid = await commitCid(signedCommit);
  const cidString = cid.toString();

  // Update repo root - use sql.raw with excluded to properly reference INSERT values
  await db
    .insert(repo_root)
    .values({
      did,
      commitCid: cidString,
      rev, // Store TID as text
    })
    .onConflictDoUpdate({
      target: repo_root.did,
      set: {
        commitCid: sql.raw('excluded.commit_cid'),
        rev: sql.raw('excluded.rev'),
      },
    })
    .run();

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

  // Append to commit log
  await appendCommit(env, cidString, rev, commitData, sigBase64);

  // Encode blocks as CAR for firehose
  const blocksBytes = await encodeBlocksForCommit(env, cid, mstRootCid, ops, opts?.newMstBlocks);
  // Encode to base64 (workers-safe)
  let blocksBase64 = '';
  for (const b of blocksBytes) blocksBase64 += String.fromCharCode(b);
  blocksBase64 = btoa(blocksBase64);

  return { commitCid: cidString, rev, ops, mstRoot: mstRootCid, commitData, sig: sigBase64, blocks: blocksBase64 };
}

export async function appendCommit(env: Env, cid: string, rev: string, data: string, sig: string) {
  const db = drizzle(env.DB);
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
