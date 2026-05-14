import type { APIContext } from 'astro';
import { isAccountActive } from '../../db/dal';
import { isValidTid } from '../../lib/commit';

export const prerender = false;

/**
 * com.atproto.sync.listBlobs
 * List blob CIDs for a DID
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals.runtime;

  const did = url.searchParams.get('did');
  const cursor = url.searchParams.get('cursor') || '';
  const since = url.searchParams.get('since') || '';
  const parsedLimit = parseInt(url.searchParams.get('limit') || '500', 10);
  const limit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? Math.min(parsedLimit, 1000) : 500;

  try {
    if (!did) {
      return new Response(
        JSON.stringify({ error: 'InvalidRequest', message: 'did parameter is required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }

    const active = await isAccountActive(env, did);
    if (!active) {
      return new Response(
        JSON.stringify({ error: 'RepoDeactivated', message: 'Account is not active' }),
        { status: 403, headers: { 'Content-Type': 'application/json' } },
      );
    }
    if (since && !isValidTid(since)) {
      return new Response(
        JSON.stringify({ error: 'InvalidRequest', message: 'since must be a valid repo revision TID' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      );
    }

    const conditions = [
      'b.did = ?',
      "b.state = 'permanent'",
      'b.takedown_ref IS NULL',
    ];
    const binds: Array<string | number> = [did];
    if (since) {
      conditions.push('u.commit_rev IS NOT NULL');
      conditions.push('u.commit_rev > ?');
      binds.push(since);
    }
    if (cursor) {
      conditions.push('b.cid > ?');
      binds.push(cursor);
    }
    binds.push(limit + 1);

    const blobs = await env.ALTERAN_DB.prepare(
      `SELECT DISTINCT b.cid
       FROM blob b
       INNER JOIN blob_usage u ON u.did = b.did AND u.key = b.key
       WHERE ${conditions.join(' AND ')}
       ORDER BY b.cid
       LIMIT ?`,
    )
      .bind(...binds)
      .all<{ cid: string }>();

    const rows = blobs.results ?? [];
    const page = rows.slice(0, limit);
    const nextCursor = rows.length > limit ? page[page.length - 1]?.cid : undefined;

    return new Response(
      JSON.stringify({
        cids: page.map(b => b.cid),
        cursor: nextCursor,
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
