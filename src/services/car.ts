import type { Env } from '../env';
import { listRecords } from '../db/dal';
import { drizzle } from 'drizzle-orm/d1';
import { desc, and, gte, lte } from 'drizzle-orm';
import { commit_log } from '../db/schema';
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { MST, Leaf, D1Blockstore } from '../lib/mst';

export type CarSnapshot = {
  bytes: Uint8Array;
  root: CID;
  blocks: { cid: CID; bytes: Uint8Array }[];
};

export async function encodeRecordBlock(value: unknown) {
  const bytes = dagCbor.encode(value);
  const hash = await sha256.digest(bytes);
  const cid = CID.createV1(dagCbor.code, hash);
  return { cid, bytes } as const;
}

export async function buildRepoCar(env: Env, did: string): Promise<CarSnapshot> {
  // Prefer the latest signed commit from commit_log (authoritative root)
  const db = drizzle(env.DB);
  const tip = await db.select().from(commit_log).orderBy(desc(commit_log.seq)).limit(1).get();

  if (tip) {
    try {
      // Reconstruct the exact signed commit object that produced tip.cid
      const parsed = JSON.parse(tip.data);
      const prevStr = parsed.prev ?? null;
      const signedCommit = {
        did: parsed.did as string,
        version: parsed.version as number,
        data: CID.parse(String(parsed.data)),
        rev: String(parsed.rev),
        prev: prevStr ? CID.parse(String(prevStr)) : null,
        sig: (() => {
          const bin = atob(String(tip.sig));
          const u8 = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
          return u8;
        })(),
      } as const;

      // Encode to CBOR and verify CID matches tip
      const commitBytes = dagCbor.encode(signedCommit);
      const hash = await sha256.digest(commitBytes);
      const commitCid = CID.createV1(dagCbor.code, hash);

      if (commitCid.toString() === (tip as any).cid) {
        // Build a full snapshot CAR: commit block + all MST nodes + all record blocks
        const blockstore = new D1Blockstore(env);
        const blocks: { cid: CID; bytes: Uint8Array }[] = [{ cid: commitCid, bytes: commitBytes }];
        const seen = new Set<string>([commitCid.toString()]);

        const addBlock = async (cid: CID) => {
          const key = cid.toString();
          if (seen.has(key)) return;
          const bytes = await blockstore.get(cid);
          if (bytes) {
            seen.add(key);
            blocks.push({ cid, bytes });
          }
        };

        const mstRoot = CID.parse(String(parsed.data));
        // 1) Add all MST node blocks (batched, non-recursive) and collect leaf CIDs
        const { mstBlocks, leafCids } = await collectMstBfs(blockstore, mstRoot);
        for (const [cid, bytes] of mstBlocks) {
          const k = cid.toString();
          if (seen.has(k)) continue;
          seen.add(k);
          blocks.push({ cid, bytes });
        }

        // 2) Add record leaf blocks by batched fetch
        const leafFetched = await blockstore.getMany(leafCids);
        for (const [cidStr, bytes] of leafFetched.blocks.entries()) {
          const cid = CID.parse(cidStr);
          if (seen.has(cidStr)) continue;
          seen.add(cidStr);
          blocks.push({ cid, bytes });
        }

        const bytes = encodeCar([commitCid], blocks);
        return { bytes, root: commitCid, blocks };
      }
    } catch (e) {
      // Fall through to deterministic snapshot
      console.warn('Failed to reconstruct signed commit from tip; falling back to snapshot:', e);
    }
  }
  // No authoritative head to build from
  throw new Error('RepoNotFound');
}

export async function buildRepoCarRange(env: Env, fromSeq: number, toSeq: number): Promise<CarSnapshot> {
  const db = drizzle(env.DB);
  const rows = await db.select().from(commit_log).where(and(gte(commit_log.seq, fromSeq), lte(commit_log.seq, toSeq))).all();
  const blocks: { cid: CID; bytes: Uint8Array }[] = [];
  for (const r of rows) {
    const b = await encodeRecordBlock({ type: 'commit', rev: r.rev, head: r.cid, ts: r.ts });
    blocks.push(b);
  }
  const root = blocks[blocks.length - 1]?.cid ?? (await encodeRecordBlock({})).cid;
  const bytes = encodeCar([root], blocks);
  return { bytes, root, blocks };
}

export async function buildBlocksCar(values: unknown[]): Promise<CarSnapshot> {
  const blocks: { cid: CID; bytes: Uint8Array }[] = [];
  for (const v of values) {
    const block = await encodeRecordBlock(v);
    blocks.push(block);
  }
  const root = blocks[0]?.cid ?? (await encodeRecordBlock({})).cid;
  const bytes = encodeCar([root], blocks);
  return { bytes, root, blocks };
}

/**
 * Encode a list of already-encoded blocks into a CAR v1 file.
 */
export function encodeBlocksToCAR(root: CID, blocks: { cid: CID; bytes: Uint8Array }[]): Uint8Array {
  return encodeCar([root], blocks);
}

export function encodeExistingBlocksToCAR(roots: CID[], blocks: { cid: CID; bytes: Uint8Array }[]): Uint8Array {
  return encodeCar(roots, blocks);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const size = parts.reduce((n, p) => n + p.byteLength, 0);
  const buf = new Uint8Array(size);
  let off = 0;
  for (const p of parts) { buf.set(p, off); off += p.byteLength; }
  return buf;
}

function varint(n: number): Uint8Array {
  const bytes: number[] = [];
  while (n >= 0x80) {
    bytes.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  bytes.push(n);
  return new Uint8Array(bytes);
}

function encodeCar(roots: CID[], blocks: { cid: CID; bytes: Uint8Array }[]): Uint8Array {
  const header = dagCbor.encode({ version: 1, roots });
  const chunks: Uint8Array[] = [];
  chunks.push(varint(header.byteLength));
  chunks.push(header);
  for (const { cid, bytes } of blocks) {
    const block = concat([cid.bytes, bytes]);
    chunks.push(varint(block.byteLength));
    chunks.push(block);
  }
  return concat(chunks);
}

/**
 * Encode blocks for firehose commit frame
 * Includes commit block, MST nodes, and record blocks
 */
export async function encodeBlocksForCommit(
  env: Env,
  commitCid: CID,
  mstRoot: CID,
  ops: Array<{ path: string; cid: CID | null }>,
  newMstBlocks?: Array<[CID, Uint8Array]>,
): Promise<Uint8Array> {
  const blockstore = new D1Blockstore(env);
  const blocks: { cid: CID; bytes: Uint8Array }[] = [];
  const seen = new Set<string>();

  // Helper to add block if not already seen
  const addBlock = async (cid: CID) => {
    const cidStr = cid.toString();
    if (seen.has(cidStr)) return;
    seen.add(cidStr);
    let bytes = await blockstore.get(cid);
    if (!bytes) {
      // Attempt to reconstruct commit block from commit_log if this is the commit cid
      if (cidStr === commitCid.toString()) {
        try {
          const row = await (env.DB as any)
            .prepare('SELECT data, sig FROM commit_log WHERE cid = ? LIMIT 1')
            .bind(cidStr)
            .first();
          if (row && row.data && row.sig) {
            const parsed = JSON.parse(String(row.data));
            const sigBin = atob(String(row.sig));
            const sig = new Uint8Array(sigBin.length);
            for (let i = 0; i < sigBin.length; i++) sig[i] = sigBin.charCodeAt(i);
            const signedCommit = {
              did: String(parsed.did),
              version: Number(parsed.version),
              data: CID.parse(String(parsed.data)),
              rev: String(parsed.rev),
              prev: parsed.prev ? CID.parse(String(parsed.prev)) : null,
              sig,
            } as const;
            bytes = dagCbor.encode(signedCommit);
          }
        } catch (e) {
          console.warn('Failed to reconstruct commit block from commit_log:', e);
        }
      }
    }
    if (bytes) blocks.push({ cid, bytes });
  };

  // 1. Add commit block
  await addBlock(commitCid);

  // 2. Add MST nodes
  if (newMstBlocks && newMstBlocks.length > 0) {
    // Prefer the exact set of MST nodes touched by this commit
    for (const [cid, bytes] of newMstBlocks) {
      const cidStr = cid.toString();
      if (seen.has(cidStr)) continue;
      seen.add(cidStr);
      blocks.push({ cid, bytes });
    }
  } else {
    // Fallback: add MST nodes by batched BFS
    const { mstBlocks } = await collectMstBfs(blockstore, mstRoot);
    for (const [cid, bytes] of mstBlocks) {
      const k = cid.toString();
      if (seen.has(k)) continue;
      seen.add(k);
      blocks.push({ cid, bytes });
    }
  }

  // 3. Add record blocks for all operations
  for (const op of ops) {
    if (op.cid) {
      await addBlock(op.cid);
    }
  }

  // Encode as CAR with commit as root
  return encodeCar([commitCid], blocks);
}

/**
 * Build a CAR proving existence or non-existence of a record at collection/rkey
 * Root is the latest signed commit block; includes MST path nodes and record block if present.
 */
export async function buildRecordProofCar(
  env: Env,
  did: string,
  collection: string,
  rkey: string,
): Promise<{ bytes: Uint8Array }> {
  const db = drizzle(env.DB);
  const tip = await db.select().from(commit_log).orderBy(desc(commit_log.seq)).limit(1).get();
  if (!tip) {
    throw new Error('HeadNotFound');
  }

  // Reconstruct signed commit block and CID
  const parsed = JSON.parse(tip.data as any);
  const prevStr = parsed.prev ?? null;
  const commitObj = {
    did: String(parsed.did),
    version: Number(parsed.version),
    data: CID.parse(String(parsed.data)),
    rev: String(parsed.rev),
    prev: prevStr ? CID.parse(String(prevStr)) : null,
    sig: (() => {
      const bin = atob(String(tip.sig));
      const u8 = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
      return u8;
    })(),
  } as const;
  const commitBytes = dagCbor.encode(commitObj);
  const hash = await sha256.digest(commitBytes);
  const commitCid = CID.createV1(dagCbor.code, hash);

  // Walk MST path to the target key
  const blockstore = new D1Blockstore(env);
  const mstRoot = CID.parse(String(parsed.data));
  const key = `${collection}/${rkey}`;
  const pathBlocks: Array<{ cid: CID; bytes: Uint8Array }> = [];
  let cursor: CID | null = mstRoot;
  let recordCid: CID | null = null;

  while (cursor) {
    const bytes = await blockstore.get(cursor);
    if (!bytes) break;
    pathBlocks.push({ cid: cursor, bytes });
    try {
      const node: any = dagCbor.decode(bytes);
      // Reconstruct ordered entries: [l? subtree], then (leaf, subtree?)*
      type Entry = { kind: 'tree'; cid: CID } | { kind: 'leaf'; key: string; value: CID };
      const entries: Entry[] = [];
      if (node?.l) entries.push({ kind: 'tree', cid: CID.asCID(node.l) ?? CID.parse(String(node.l)) });
      let lastKey = '';
      for (const e of (node?.e ?? [])) {
        const keyStr = new TextDecoder('ascii').decode(e.k as Uint8Array);
        const fullKey = lastKey.slice(0, e.p as number) + keyStr;
        entries.push({ kind: 'leaf', key: fullKey, value: CID.asCID(e.v) ?? CID.parse(String(e.v)) });
        lastKey = fullKey;
        if (e.t) entries.push({ kind: 'tree', cid: CID.asCID(e.t) ?? CID.parse(String(e.t)) });
      }
      // Find first leaf >= key
      let index = entries.findIndex((en) => en.kind === 'leaf' && (en as any).key >= key);
      if (index < 0) index = entries.length;
      const found = entries[index];
      if (found && found.kind === 'leaf' && (found as any).key === key) {
        recordCid = found.value;
        break;
      }
      const prev = entries[index - 1];
      if (prev && prev.kind === 'tree') {
        cursor = prev.cid;
        continue;
      }
      // Not found and no subtree to descend
      break;
    } catch {
      break;
    }
  }

  // Assemble CAR: commit as root; include path nodes; include record block if present
  const blocks: { cid: CID; bytes: Uint8Array }[] = [{ cid: commitCid, bytes: commitBytes }];
  const seen = new Set<string>([commitCid.toString()]);
  for (const b of pathBlocks) {
    const s = b.cid.toString();
    if (!seen.has(s)) { seen.add(s); blocks.push(b); }
  }
  if (recordCid) {
    const bytes = await blockstore.get(recordCid);
    if (bytes) blocks.push({ cid: recordCid, bytes });
  }
  const bytes = encodeCar([commitCid], blocks);
  return { bytes };
}

/**
 * Recursively add all MST node blocks
 */
async function collectMstBfs(
  blockstore: D1Blockstore,
  rootCid: CID,
): Promise<{ mstBlocks: Array<[CID, Uint8Array]>; leafCids: CID[] }> {
  const mstBlocks: Array<[CID, Uint8Array]> = [];
  const leafCids: CID[] = [];
  const seen = new Set<string>();

  let toFetch: CID[] = [rootCid];
  const BATCH = 200;

  while (toFetch.length > 0) {
    const chunk = toFetch.slice(0, BATCH);
    toFetch = toFetch.slice(BATCH);
    const { blocks, missing } = await blockstore.getMany(chunk);
    // Push node blocks we found
    for (const [cidStr, bytes] of blocks.entries()) {
      if (seen.has(cidStr)) continue;
      seen.add(cidStr);
      mstBlocks.push([CID.parse(cidStr), bytes]);
    }
    // Decode nodes to collect children and leaves
    for (const [cidStr, bytes] of blocks.entries()) {
      try {
        const node: any = dagCbor.decode(bytes);
        const l = node?.l ? (CID.asCID(node.l) ?? CID.parse(String(node.l))) : null;
        if (l) {
          const key = l.toString();
          if (!seen.has(key)) toFetch.push(l);
        }
        const entries: any[] = Array.isArray(node?.e) ? node.e : [];
        for (const e of entries) {
          const v = CID.asCID(e?.v) ?? CID.parse(String(e?.v));
          if (v) leafCids.push(v);
          const t = e?.t ? (CID.asCID(e.t) ?? CID.parse(String(e.t))) : null;
          if (t) {
            const key = t.toString();
            if (!seen.has(key)) toFetch.push(t);
          }
        }
      } catch (error) {
        console.warn('collectMstBfs: failed to decode node', cidStr, error);
      }
    }
    // Ignore missing here; caller might not need full tree for snapshots
  }

  return { mstBlocks, leafCids };
}
