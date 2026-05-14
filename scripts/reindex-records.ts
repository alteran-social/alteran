#!/usr/bin/env -S deno run -A
/**
 * Re-index records from imported repository blocks
 *
 * This script walks the MST tree from the repo_root and indexes all records
 * into the record table. Use this after importing a CAR file if records
 * weren't properly indexed during import.
 */

import { getDb } from '../src/db/client';
import { repo_root } from '../src/db/schema';
import { putRecord } from '../src/db/dal';
import { D1Blockstore, MST } from '../src/lib/mst';
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { eq } from 'drizzle-orm';
import type { Env } from '../types/env';

async function reindexRecords() {
  // Get environment from wrangler
  const did = process.env.PDS_DID || 'did:plc:35bdlgus7hihmup66o265nuy';

  console.log(`[INFO] Re-indexing records for DID: ${did}`);

  // Create mock env for local execution
  // Note: This needs to be run with wrangler for D1 access
  const env = {
    ALTERAN_DB: (globalThis as any).ALTERAN_DB ?? (globalThis as any).DB,
    PDS_DID: did,
  } as Env;

  if (!env.ALTERAN_DB) {
    console.error('[ERROR] D1 database not available. Run with: npx wrangler d1 execute alteran --remote --file=<(bun run scripts/reindex-records.ts)');
    process.exit(1);
  }

  const db = getDb(env);
  const blockstore = new D1Blockstore(env);

  // Get repo root
  const repoRoot = await db
    .select()
    .from(repo_root)
    .where(eq(repo_root.did, did))
    .get();

  if (!repoRoot || !repoRoot.commitCid) {
    console.error('[ERROR] No repo root found for DID:', did);
    process.exit(1);
  }

  console.log(`[INFO] Found repo root: ${repoRoot.commitCid}`);
  console.log(`[INFO] Revision: ${repoRoot.rev}`);

  // Parse commit to get MST root
  const commitCid = CID.parse(repoRoot.commitCid);
  const commitBytes = await blockstore.get(commitCid);

  if (!commitBytes) {
    console.error('[ERROR] Commit block not found:', commitCid.toString());
    process.exit(1);
  }

  const commit = dagCbor.decode(commitBytes) as any;
  const mstRootCid = typeof commit.data === 'string' ? CID.parse(commit.data) : commit.data;

  console.log(`[INFO] MST root CID: ${mstRootCid.toString()}`);

  // Load MST and walk all leaves
  const mst = MST.load(blockstore, mstRootCid);

  let recordsIndexed = 0;
  let errors = 0;

  console.log('[INFO] Walking MST tree...');

  try {
    for await (const leaf of mst.walkLeavesFrom('')) {
      try {
        const recordKey = leaf.key;
        const recordCid = leaf.value;

        // Read the record data from blockstore
        const recordBytes = await blockstore.get(recordCid);
        if (!recordBytes) {
          console.error(`[ERROR] Record block not found: ${recordCid.toString()} for key: ${recordKey}`);
          errors++;
          continue;
        }

        // Decode the record
        const recordData = dagCbor.decode(recordBytes);

        // Build the AT URI
        const uri = `at://${did}/${recordKey}`;

        // Index the record
        await putRecord(env, {
          uri,
          did,
          cid: recordCid.toString(),
          json: JSON.stringify(recordData),
          createdAt: Date.now(),
        });

        recordsIndexed++;

        if (recordsIndexed % 100 === 0) {
          console.log(`[INFO] Indexed ${recordsIndexed} records...`);
        }
      } catch (leafError: any) {
        console.error(`[ERROR] Failed to index leaf ${leaf.key}:`, leafError.message);
        errors++;
      }
    }
  } catch (walkError: any) {
    console.error('[ERROR] MST walk failed:', walkError.message);
    console.error(walkError.stack);
    process.exit(1);
  }

  console.log(`[SUCCESS] Re-indexing complete!`);
  console.log(`[INFO] Records indexed: ${recordsIndexed}`);
  console.log(`[INFO] Errors: ${errors}`);
}

// Run if executed directly
if (import.meta.main) {
  reindexRecords().catch((error) => {
    console.error('[ERROR] Re-indexing failed:', error);
    process.exit(1);
  });
}