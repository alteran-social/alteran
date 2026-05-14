import type { APIContext } from 'astro';
import { getRoot } from '../../db/repo';
import { requireLocalDid, xrpcError } from '../../lib/local-xrpc';

export const prerender = false;

/**
 * com.atproto.sync.getLatestCommit
 * Get the latest commit CID and revision for a repository
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals.runtime;

  const did = requireLocalDid(env, url);
  if (!did.ok) return did.response;

  try {
    const root = await getRoot(env);

    if (!root) {
      return xrpcError('RepoNotFound', 'Repo not found');
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
