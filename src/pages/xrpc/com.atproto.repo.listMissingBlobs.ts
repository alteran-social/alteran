import type { APIContext } from 'astro';
import type { Env } from '../../env';
import { errorMessage } from '../../lib/errors';
import { authErrorResponse, authenticateRequest, unauthorized } from '../../lib/auth';
import { canUseAppPasswordLevelAccess } from '../../lib/auth-scope';
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
    const auth = await authenticateRequest(request, env);
    if (!auth || !canUseAppPasswordLevelAccess(auth.access)) return unauthorized();
  } catch (error) {
    const handled = await authErrorResponse(env, error);
    if (handled) return handled;
    throw error;
  }

  try {
    const did = String(env.PDS_DID ?? 'did:example:single-user');
    const parsedLimit = parseInt(url.searchParams.get('limit') || '500', 10);
    const limit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? Math.min(parsedLimit, 1000) : 500;
    const cursor = url.searchParams.get('cursor') || '';
    const cursorKey = decodeCursor(cursor) ?? '';

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

    const blobsByCid = new Map<string, Array<{ key: string; state: string; takedownRef: string | null }>>();
    for (const blob of blobs) {
      const rows = blobsByCid.get(blob.cid) ?? [];
      rows.push({
        key: blob.key,
        state: blob.state,
        takedownRef: blob.takedownRef,
      });
      blobsByCid.set(blob.cid, rows);
    }

    // Extract blob references from records. Pagination is over record/blob
    // pairs because one missing CID can be referenced by multiple records.
    const referencedBlobs: Array<{ cid: string; recordUri: string }> = [];
    for (const rec of records) {
      try {
        const data = JSON.parse(rec.json);
        const refs = extractBlobRefs(data);
        refs.forEach(ref => referencedBlobs.push({ cid: ref, recordUri: rec.uri }));
      } catch {
        // Skip invalid JSON
      }
    }

    // Find missing blobs
    const missingBlobs: Array<{ cid: string; recordUri: string }> = [];
    const availabilityByCid = new Map<string, boolean>();
    for (const pair of referencedBlobs) {
      const pairKey = pairCursorKey(pair);
      if (cursorKey && pairKey <= cursorKey) continue;
      const { cid } = pair;
      let isAvailable = availabilityByCid.get(cid);
      if (isAvailable === undefined) {
        isAvailable = await hasAvailableBlobObject(env, blobsByCid.get(cid) ?? []);
        availabilityByCid.set(cid, isAvailable);
      }
      if (!isAvailable) {
        missingBlobs.push(pair);
      }
    }

    // Sort and limit
    missingBlobs.sort((a, b) => pairCursorKey(a).localeCompare(pairCursorKey(b)));
    const pagePlusOne = missingBlobs.slice(0, limit + 1);
    const page = pagePlusOne.slice(0, limit);
    const nextCursor = pagePlusOne.length > limit ? encodeCursor(page[page.length - 1]) : undefined;

    return new Response(
      JSON.stringify({
        blobs: page.map(({ cid, recordUri }) => ({
          $type: 'com.atproto.repo.listMissingBlobs#recordBlob',
          cid,
          recordUri,
        })),
        cursor: nextCursor,
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    return new Response(
      JSON.stringify({
        error: 'InternalServerError',
        message: errorMessage(error) || 'Failed to list missing blobs'
      }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

async function hasAvailableBlobObject(
  env: Env,
  rows: Array<{ key: string; state: string; takedownRef: string | null }>,
): Promise<boolean> {
  for (const row of rows) {
    if (row.state !== 'permanent' || row.takedownRef !== null) continue;
    const object = typeof (env.ALTERAN_BLOBS as any).head === 'function'
      ? await (env.ALTERAN_BLOBS as any).head(row.key)
      : await env.ALTERAN_BLOBS.get(row.key);
    if (object) return true;
  }
  return false;
}

function pairCursorKey(pair: { cid: string; recordUri: string }): string {
  return `${pair.cid}\0${pair.recordUri}`;
}

function encodeCursor(pair: { cid: string; recordUri: string }): string {
  return btoa(JSON.stringify([pair.cid, pair.recordUri]))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
}

function decodeCursor(cursor: string): string | null {
  if (!cursor) return null;
  try {
    const padded = cursor.replaceAll('-', '+').replaceAll('_', '/')
      .padEnd(Math.ceil(cursor.length / 4) * 4, '=');
    const parsed = JSON.parse(atob(padded));
    if (!Array.isArray(parsed) || typeof parsed[0] !== 'string' || typeof parsed[1] !== 'string') {
      return null;
    }
    return pairCursorKey({ cid: parsed[0], recordUri: parsed[1] });
  } catch {
    return null;
  }
}
