import type { APIContext } from 'astro';
import { errorMessage } from '../../lib/errors';
import { authErrorResponse, isAuthorized, unauthorized } from '../../lib/auth';
import { getAccountState } from '../../db/dal';
import { toWireStatus } from '../../lib/account-state';
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
  } catch (error) {
    const handled = await authErrorResponse(env, error);
    if (handled) return handled;
    throw error;
  }

  try {
    const did = String(env.PDS_DID ?? 'did:example:single-user');
    const db = getDb(env);

    // Get account state. No row means an unmigrated account, treated as active
    // for backward compatibility.
    const accountState = await getAccountState(env, did);
    const wire = accountState ? toWireStatus(accountState) : { active: true };
    const { active, status } = wire;

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
        ...(status ? { status } : {}),
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
  } catch (error) {
    return new Response(
      JSON.stringify({
        error: 'InternalServerError',
        message: errorMessage(error) || 'Failed to check account status'
      }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
