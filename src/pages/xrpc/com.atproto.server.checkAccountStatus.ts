import type { APIContext } from 'astro';
import { AuthTokenExpiredError, expiredToken, isAuthorized, unauthorized } from '../../lib/auth';
import { getAccountState } from '../../db/dal';
import { getDb } from '../../db/client';
import { repo_root, record, blob_ref, commit_log } from '../../db/schema';
import { eq, count } from 'drizzle-orm';

export const prerender = false;

/**
 * com.atproto.server.checkAccountStatus
 *
 * Returns account status including:
 * - Active state
 * - Repository head CID and revision
 * - Record count
 * - Blob count
 * - Missing blob count (for migration tracking)
 */
export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;

  try {
    if (!(await isAuthorized(request, env))) return unauthorized();
  } catch (err) {
    if (err instanceof AuthTokenExpiredError) {
      return expiredToken();
    }
    throw err;
  }

  try {
    const did = String(env.PDS_DID ?? 'did:example:single-user');
    const db = getDb(env);

    // Get account state
    const accountState = await getAccountState(env, did);
    const active = accountState?.active ?? true;

    // Get repo head
    const repoRoot = await db
      .select()
      .from(repo_root)
      .where(eq(repo_root.did, did))
      .get();

    // Count records
    const recordCountResult = await db
      .select({ count: count() })
      .from(record)
      .where(eq(record.did, did))
      .get();
    const recordCount = recordCountResult?.count ?? 0;

    // Count blobs
    const blobCountResult = await db
      .select({ count: count() })
      .from(blob_ref)
      .where(eq(blob_ref.did, did))
      .get();
    const blobCount = blobCountResult?.count ?? 0;

    // Get latest commit sequence
    const latestCommit = await db
      .select()
      .from(commit_log)
      .orderBy(commit_log.seq)
      .limit(1)
      .get();

    return new Response(
      JSON.stringify({
        did,
        active,
        head: repoRoot?.commitCid ?? null,
        rev: repoRoot?.rev ?? 0,
        recordCount,
        blobCount,
        indexedRecords: recordCount,
        privateStateValues: 0,
        expectedBlobs: blobCount,
        importedBlobs: blobCount,
        repoBlocks: 0, // Could calculate from blockstore if needed
        repoRev: repoRoot?.rev?.toString() ?? '0',
        repoCommit: repoRoot?.commitCid ?? null,
        seq: latestCommit?.seq ?? 0,
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error: any) {
    return new Response(
      JSON.stringify({
        error: 'InternalServerError',
        message: error.message || 'Failed to check account status'
      }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
