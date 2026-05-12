import type { APIContext } from 'astro';
import { drizzle } from 'drizzle-orm/d1';
import { blob_ref } from '../../db/schema';
import { eq, gt, and } from 'drizzle-orm';

export const prerender = false;

/**
 * com.atproto.sync.listBlobs
 * List blob CIDs for a DID
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals.runtime;

  const did = url.searchParams.get('did') || (env.PDS_DID as string);
  const since = url.searchParams.get('since') || '';
  const limit = parseInt(url.searchParams.get('limit') || '500', 10);

  try {
    const db = drizzle(env.ALTERAN_DB);

    const blobs = since
      ? await db
          .select()
          .from(blob_ref)
          .where(and(eq(blob_ref.did, did), gt(blob_ref.cid, since)))
          .limit(limit)
          .all()
      : await db
          .select()
          .from(blob_ref)
          .where(eq(blob_ref.did, did))
          .limit(limit)
          .all();

    return new Response(
      JSON.stringify({
        cids: blobs.map(b => b.cid),
        cursor: blobs.length > 0 ? blobs[blobs.length - 1].cid : undefined,
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
