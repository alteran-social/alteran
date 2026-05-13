import type { APIContext } from 'astro';
import { isAccountActive } from '../../db/dal';

export const prerender = false;

/**
 * com.atproto.sync.listBlobs
 * List blob CIDs for a DID
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals.runtime;

  const did = url.searchParams.get('did') || (env.PDS_DID as string);
  const cursor = url.searchParams.get('cursor') || url.searchParams.get('since') || '';
  const limit = parseInt(url.searchParams.get('limit') || '500', 10);

  try {
    const active = await isAccountActive(env, did);
    if (!active) {
      return new Response(
        JSON.stringify({ error: 'RepoDeactivated', message: 'Account is not active' }),
        { status: 403, headers: { 'Content-Type': 'application/json' } },
      );
    }

    const blobs = cursor
      ? await env.ALTERAN_DB.prepare(
          `SELECT DISTINCT b.cid
           FROM blob b
           INNER JOIN blob_usage u ON u.did = b.did AND u.key = b.key
           WHERE b.did = ? AND b.cid > ?
           ORDER BY b.cid
           LIMIT ?`,
        )
          .bind(did, cursor, limit)
          .all<{ cid: string }>()
      : await env.ALTERAN_DB.prepare(
          `SELECT DISTINCT b.cid
           FROM blob b
           INNER JOIN blob_usage u ON u.did = b.did AND u.key = b.key
           WHERE b.did = ?
           ORDER BY b.cid
           LIMIT ?`,
        )
          .bind(did, limit)
          .all<{ cid: string }>();

    const rows = blobs.results ?? [];

    return new Response(
      JSON.stringify({
        cids: rows.map(b => b.cid),
        cursor: rows.length > 0 ? rows[rows.length - 1].cid : undefined,
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
