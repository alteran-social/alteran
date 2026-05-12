import type { Env } from '../env';
import { drizzle } from 'drizzle-orm/d1';
import { commit_log } from '../db/schema';
import { lt, desc } from 'drizzle-orm';
import { logger } from './logger';

/**
 * Prune old commits from the commit log to prevent unbounded growth.
 * Keeps the most recent N commits (default: 10000).
 *
 * This is safe because:
 * - The current repo state is preserved in the MST and record tables
 * - Recent commits are kept for firehose subscribers
 * - Very old commits are not needed for sync operations
 *
 * @param env - Worker environment
 * @param keepCount - Number of recent commits to keep (default: 10000)
 * @returns Number of commits pruned
 */
export async function pruneOldCommits(env: Env, keepCount: number = 10000): Promise<number> {
  const db = drizzle(env.ALTERAN_DB);

  // Get the sequence number of the Nth most recent commit
  const threshold = await db
    .select({ seq: commit_log.seq })
    .from(commit_log)
    .orderBy(desc(commit_log.seq))
    .limit(1)
    .offset(keepCount)
    .get();

  if (!threshold) {
    // Less than keepCount commits exist, nothing to prune
    logger.debug('commit_log_pruning', { message: 'No commits to prune', totalCommits: keepCount });
    return 0;
  }

  // Delete all commits older than the threshold
  const result = await db
    .delete(commit_log)
    .where(lt(commit_log.seq, threshold.seq))
    .run();

  const pruned = result.meta.changes || 0;
  logger.info('commit_log_pruning', {
    message: 'Pruned old commits',
    pruned,
    threshold: threshold.seq,
    kept: keepCount
  });

  return pruned;
}

/**
 * Get commit log statistics
 */
export async function getCommitLogStats(env: Env): Promise<{
  total: number;
  oldest: number | null;
  newest: number | null;
}> {
  const db = drizzle(env.ALTERAN_DB);

  const [oldest, newest, count] = await Promise.all([
    db.select({ seq: commit_log.seq }).from(commit_log).orderBy(commit_log.seq).limit(1).get(),
    db.select({ seq: commit_log.seq }).from(commit_log).orderBy(desc(commit_log.seq)).limit(1).get(),
    db.select({ count: commit_log.seq }).from(commit_log).all(),
  ]);

  return {
    total: count.length,
    oldest: oldest?.seq ?? null,
    newest: newest?.seq ?? null,
  };
}