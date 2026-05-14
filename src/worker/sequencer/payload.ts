import type { D1Database } from '@cloudflare/workers-types';
import { drizzle } from 'drizzle-orm/d1';
import { commit_log } from '../../db/schema';
import { eq } from 'drizzle-orm';
import { CID } from 'multiformats/cid';
import type { CommitMessage } from '../../lib/firehose/frames';
import { encodeBlocksForCommit } from '../../services/car';
import type { Env } from '../../env';
import type { CommitEvent } from './types';

export async function createCommitPayload(
  env: Env,
  db: D1Database,
  event: CommitEvent,
): Promise<CommitMessage> {
  const commitData = JSON.parse(event.data) as { data?: string; prev?: string };

  let blocks = event.blocks;
  if (!blocks && event.ops && event.ops.length > 0) {
    try {
      const commitCid = CID.parse(event.commitCid);
      const mstRoot = commitData.data ? CID.parse(commitData.data) : commitCid;
      blocks = await encodeBlocksForCommit(env, commitCid, mstRoot, event.ops);
    } catch (error) {
      console.error('Failed to encode blocks for commit:', error);
      blocks = new Uint8Array();
    }
  }

  let prevCid: CID | null = null;
  let prevDataCid: CID | null = null;
  try {
    if (commitData.prev) prevCid = CID.parse(String(commitData.prev));
  } catch {
    // Stays null; firehose consumers can tolerate a missing prev pointer.
  }

  let since: string | null = null;
  try {
    const drizzleDb = drizzle(db);
    if (prevCid) {
      const previous = await drizzleDb
        .select()
        .from(commit_log)
        .where(eq(commit_log.cid, prevCid.toString()))
        .get();
      since = previous?.rev ?? null;
      if (previous?.data) {
        try {
          prevDataCid = CID.parse(String(JSON.parse(previous.data).data));
        } catch {
          // Older rows may have a different shape; leave prevDataCid null.
        }
      }
    }
  } catch (error) {
    console.warn('createCommitPayload: failed to resolve since/prev:', error);
  }

  return {
    seq: event.seq,
    rebase: false,
    tooBig: false,
    repo: event.did,
    commit: CID.parse(event.commitCid),
    prev: prevCid,
    rev: event.rev,
    since,
    blocks: blocks || new Uint8Array(),
    ops: event.ops || [],
    blobs: [],
    time: new Date(event.ts).toISOString(),
    ...(prevDataCid ? { prevData: prevDataCid } : {}),
  };
}
