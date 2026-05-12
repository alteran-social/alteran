import type { Env } from '../env';
import { drizzle } from 'drizzle-orm/d1';
import { blockstore, commit_log } from '../db/schema';
import { desc, notInArray, eq } from 'drizzle-orm';
import { logger } from './logger';
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';

/**
 * Collect CIDs referenced by recent commits
 * This traverses the MST structure to find all blocks that are still in use
 */
async function collectReferencedCids(env: Env, keepCommits: number = 10000): Promise<Set<string>> {
  const db = drizzle(env.ALTERAN_DB);
  const referenced = new Set<string>();

  // Get recent commits
  const commits = await db
    .select()
    .from(commit_log)
    .orderBy(desc(commit_log.seq))
    .limit(keepCommits)
    .all();

  logger.debug('blockstore_gc', { message: 'Collecting referenced CIDs', commits: commits.length });

  // For each commit, parse the commit data and collect referenced CIDs
  for (const commit of commits) {
    try {
      const commitData = JSON.parse(commit.data);

      // Add the commit CID itself
      referenced.add(commit.cid);

      // Add the data CID (MST root)
      if (commitData.data) {
        referenced.add(commitData.data);

        // Traverse the MST to collect all node CIDs
        await traverseMst(env, commitData.data, referenced);
      }

      // Add prev commit CID if present
      if (commitData.prev) {
        referenced.add(commitData.prev);
      }
    } catch (error) {
      logger.warn('blockstore_gc', {
        message: 'Failed to parse commit data',
        cid: commit.cid,
        error: String(error)
      });
    }
  }

  return referenced;
}

/**
 * Recursively traverse MST nodes to collect all CIDs
 */
async function traverseMst(env: Env, rootCid: string, referenced: Set<string>): Promise<void> {
  const db = drizzle(env.ALTERAN_DB);
  const visited = new Set<string>();
  const queue = [rootCid];

  while (queue.length > 0) {
    const cidStr = queue.shift();
    if (cidStr === undefined) break;

    if (visited.has(cidStr)) continue;
    visited.add(cidStr);
    referenced.add(cidStr);

    try {
      // Load the block
      const block = await db
        .select()
        .from(blockstore)
        .where(eq(blockstore.cid, cidStr))
        .get();

      if (!block || !block.bytes) continue;

      // Decode the CBOR data (workers-safe base64)
      const bin = atob(block.bytes);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const data = dagCbor.decode(bytes) as any;

      // If this is an MST node, collect child CIDs
      if (data.l) {
        // Left subtree
        const leftCid = CID.decode(data.l);
        queue.push(leftCid.toString());
      }

      if (data.e) {
        // Entries with subtrees
        for (const entry of data.e) {
          if (entry.t) {
            const treeCid = CID.decode(entry.t);
            queue.push(treeCid.toString());
          }
          if (entry.v) {
            // Record value CID
            const valueCid = CID.decode(entry.v);
            referenced.add(valueCid.toString());
          }
        }
      }
    } catch (error) {
      logger.warn('blockstore_gc', {
        message: 'Failed to traverse MST node',
        cid: cidStr,
        error: String(error)
      });
    }
  }
}

/**
 * Remove orphaned blocks from the blockstore
 * Keeps blocks referenced by recent commits (default: last 10000 commits)
 *
 * @param env - Worker environment
 * @param keepCommits - Number of recent commits to preserve blocks for (default: 10000)
 * @returns Number of blocks removed
 */
export async function pruneOrphanedBlocks(env: Env, keepCommits: number = 10000): Promise<number> {
  const db = drizzle(env.ALTERAN_DB);

  // Collect all CIDs referenced by recent commits
  const referenced = await collectReferencedCids(env, keepCommits);

  logger.info('blockstore_gc', {
    message: 'Collected referenced CIDs',
    count: referenced.size
  });

  // Get all blocks
  const allBlocks = await db.select({ cid: blockstore.cid }).from(blockstore).all();

  // Find orphaned blocks
  const orphaned = allBlocks
    .map(b => b.cid)
    .filter(cid => cid && !referenced.has(cid));

  if (orphaned.length === 0) {
    logger.debug('blockstore_gc', { message: 'No orphaned blocks to remove' });
    return 0;
  }

  // Delete orphaned blocks in batches
  const batchSize = 100;
  let removed = 0;

  for (let i = 0; i < orphaned.length; i += batchSize) {
    const batch = orphaned.slice(i, i + batchSize);
    const result = await db
      .delete(blockstore)
      .where(notInArray(blockstore.cid, Array.from(referenced)))
      .run();

    removed += result.meta.changes || 0;
  }

  logger.info('blockstore_gc', {
    message: 'Pruned orphaned blocks',
    removed,
    kept: referenced.size
  });

  return removed;
}

/**
 * Get blockstore statistics
 */
export async function getBlockstoreStats(env: Env): Promise<{
  total: number;
  totalSize: number;
}> {
  const db = drizzle(env.ALTERAN_DB);
  const blocks = await db.select().from(blockstore).all();

  const totalSize = blocks.reduce((sum, block) => {
    if (!block.bytes) return sum;
    // Approximate decoded size by counting base64 length * 3/4
    const len = Math.floor((block.bytes.length * 3) / 4);
    return sum + len;
  }, 0);

  return {
    total: blocks.length,
    totalSize,
  };
}
