import type { APIContext } from 'astro';
import { AuthTokenExpiredError, expiredToken, isAuthorized, unauthorized } from '../../lib/auth';
import { getDb } from '../../db/client';
import { record, blob_ref } from '../../db/schema';
import { eq } from 'drizzle-orm';
import { extractBlobRefs } from '../../lib/blob-refs';

export const prerender = false;

/**
 * com.atproto.repo.listMissingBlobs
 *
 * Lists blob CIDs that are referenced in records but not present in blob storage.
 * Used during migration to identify which blobs need to be transferred.
 */
export async function GET({ locals, request, url }: APIContext) {
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
    const limit = parseInt(url.searchParams.get('limit') || '500');
    const cursor = url.searchParams.get('cursor') || '';

    const db = getDb(env);

    // Get all records for this DID
    const records = await db
      .select()
      .from(record)
      .where(eq(record.did, did))
      .all();

    // Get all blob refs for this DID
    const blobs = await db
      .select()
      .from(blob_ref)
      .where(eq(blob_ref.did, did))
      .all();

    // Create a set of existing blob CIDs
    const existingBlobCids = new Set(blobs.map(b => b.cid));

    // Extract blob references from records
    const referencedBlobs = new Set<string>();
    for (const rec of records) {
      try {
        const data = JSON.parse(rec.json);
        const refs = extractBlobRefs(data);
        refs.forEach(ref => referencedBlobs.add(ref));
      } catch {
        // Skip invalid JSON
      }
    }

    // Find missing blobs
    const missingBlobs: string[] = [];
    for (const cid of referencedBlobs) {
      if (!existingBlobCids.has(cid)) {
        if (!cursor || cid > cursor) {
          missingBlobs.push(cid);
        }
      }
    }

    // Sort and limit
    missingBlobs.sort();
    const page = missingBlobs.slice(0, limit);
    const nextCursor = page.length === limit ? page[page.length - 1] : undefined;

    return new Response(
      JSON.stringify({
        blobs: page.map(cid => ({ cid })),
        cursor: nextCursor,
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error: any) {
    return new Response(
      JSON.stringify({
        error: 'InternalServerError',
        message: error.message || 'Failed to list missing blobs'
      }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
