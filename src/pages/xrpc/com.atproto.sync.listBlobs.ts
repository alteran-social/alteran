import type { APIContext } from 'astro';
import { drizzle } from 'drizzle-orm/d1';
import { blob_ref } from '../../db/schema';
import { and, asc, eq, gt } from 'drizzle-orm';
import { invalidRequest, parseLimit, requireLocalDid } from '../../lib/local-xrpc';

export const prerender = false;

/**
 * com.atproto.sync.listBlobs
 * List blob CIDs for a DID
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals.runtime;

  const did = requireLocalDid(env, url);
  if (!did.ok) return did.response;

  if (url.searchParams.has('since')) {
    return invalidRequest('listBlobs does not support revision-based since filtering');
  }

  const limit = parseLimit(url, { defaultValue: 500, max: 1000 });
  if (!limit.ok) return limit.response;

  const cursor = url.searchParams.get('cursor')?.trim() ?? '';

  try {
    const db = drizzle(env.ALTERAN_DB);

    const rows = cursor
      ? await db
          .select()
          .from(blob_ref)
          .where(and(eq(blob_ref.did, did.value), gt(blob_ref.cid, cursor)))
          .orderBy(asc(blob_ref.cid))
          .limit(limit.value + 1)
          .all()
      : await db
          .select()
          .from(blob_ref)
          .where(eq(blob_ref.did, did.value))
          .orderBy(asc(blob_ref.cid))
          .limit(limit.value + 1)
          .all();

    const blobs = rows.slice(0, limit.value);
    const nextCursor = rows.length > limit.value ? blobs[blobs.length - 1]?.cid : undefined;

    return new Response(
      JSON.stringify({
        cids: blobs.map(b => b.cid),
        ...(nextCursor ? { cursor: nextCursor } : {}),
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    console.error('listBlobs error:', error);
    return new Response(
      JSON.stringify({ error: 'InternalServerError', message: String(error) }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
