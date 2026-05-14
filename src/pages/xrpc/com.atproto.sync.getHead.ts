import type { APIContext } from 'astro';
import { getRoot as getRepoRoot } from '../../db/repo';
import { requireLocalDid, xrpcError } from '../../lib/local-xrpc';

export const prerender = false;

export async function GET({ locals, url }: APIContext) {
  const { env } = locals.runtime;
  const did = requireLocalDid(env, url, { notFoundError: 'HeadNotFound', notFoundStatus: 404 });
  if (!did.ok) return did.response;

  const root = await getRepoRoot(env);
  if (!root) {
    return xrpcError('HeadNotFound', 'Head not found', 404);
  }
  return new Response(JSON.stringify({ root: root.commitCid }), { headers: { 'Content-Type': 'application/json' } });
}
