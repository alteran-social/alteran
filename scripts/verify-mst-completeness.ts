#!/usr/bin/env -S deno run -A
/**
 * Verifies that all MST node blocks referenced by the current repo root
 * exist in D1 blockstore. Prints any missing CIDs.
 *
 * Usage:
 *   PDS_DID=did:plc:... bun scripts/verify-mst-completeness.ts
 *
 * Runs against the DB bound by wrangler (remote if using --remote).
 */

import { D1Blockstore } from '../src/lib/mst';
import { getDb } from '../src/db/client';
import { repo_root } from '../src/db/schema';
import { eq } from 'drizzle-orm';
import type { Env } from '../src/env';
import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';

async function main() {
  const did = process.env.PDS_DID;
  if (!did) {
    console.error('Set PDS_DID to the DID to verify');
    process.exit(1);
  }

  const env = { ALTERAN_DB: (globalThis as any).ALTERAN_DB ?? (globalThis as any).DB } as unknown as Env;
  if (!env.ALTERAN_DB) {
    console.error('No DB binding found. Run with wrangler d1 execute.');
    process.exit(1);
  }

  const db = getDb(env);
  const store = new D1Blockstore(env);

  const rootRow = await db.select().from(repo_root).where(eq(repo_root.did, did)).get();
  if (!rootRow) {
    console.error('No repo_root row for DID:', did);
    process.exit(1);
  }

  const commitCid = CID.parse(rootRow.commitCid);
  const commitBytes = await store.get(commitCid);
  if (!commitBytes) {
    console.error('Commit block missing in blockstore:', commitCid.toString());
    process.exit(1);
  }

  const commit = dagCbor.decode(commitBytes) as any;
  const mstRoot = CID.asCID(commit.data) ?? CID.parse(String(commit.data));

  // BFS MST nodes and test presence
  const seen = new Set<string>();
  const missing = new Set<string>();
  const queue: CID[] = [mstRoot];
  const BATCH = 200;

  while (queue.length) {
    const chunk = queue.splice(0, BATCH);
    const { blocks, missing: miss } = await store.getMany(chunk);
    for (const m of miss) missing.add(m.toString());

    // Decode found nodes to traverse children
    for (const [cidStr, bytes] of blocks.entries()) {
      if (seen.has(cidStr)) continue;
      seen.add(cidStr);
      try {
        const node = dagCbor.decode(bytes) as any;
        const l = node?.l ? (CID.asCID(node.l) ?? CID.parse(String(node.l))) : null;
        if (l && !seen.has(l.toString())) queue.push(l);
        const entries: any[] = Array.isArray(node?.e) ? node.e : [];
        for (const e of entries) {
          const t = e?.t ? (CID.asCID(e.t) ?? CID.parse(String(e.t))) : null;
          if (t && !seen.has(t.toString())) queue.push(t);
        }
      } catch (e) {
        console.warn('Failed to decode MST node:', cidStr, (e as Error).message);
      }
    }
  }

  if (missing.size === 0) {
    console.log('[OK] All MST node blocks present. Nodes:', seen.size);
  } else {
    console.error('[ERROR] Missing MST node blocks:', missing.size);
    for (const cid of missing) console.error('  -', cid);
    process.exit(2);
  }
}

if (import.meta.main) {
  main().catch((e) => {
    console.error('Verification failed:', e);
    process.exit(1);
  });
}

