import type { APIContext } from 'astro';
import { getRoot } from '../../db/repo';

export const prerender = false;

/**
 * com.atproto.sync.getLatestCommit
 * Get the latest commit CID and revision for a repository
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals;

  const did = url.searchParams.get('did') || (env.PDS_DID as string);

  try {
    const root = await getRoot(env);

    if (!root) {
      return new Response(
        JSON.stringify({ error: 'RepoNotFound' }),
        { status: 404, headers: { 'Content-Type': 'application/json' } }
      );
    }

    return new Response(
      JSON.stringify({
        cid: root.commitCid,
        rev: root.rev.toString(),
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    console.error('getLatestCommit error:', error);
    return new Response(
      JSON.stringify({ error: 'InternalServerError', message: String(error) }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
