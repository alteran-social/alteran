import type { APIContext } from 'astro';
import { listOrphanBlobKeys, deleteBlobByKey } from '../../../db/dal';
import { debugNotFound, isDebugRouteAllowed } from '../../../lib/debug-routes';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  if (!isDebugRouteAllowed(env, request)) return debugNotFound();

  const keys = await listOrphanBlobKeys(env);
  let deleted = 0;
  for (const key of keys) {
    await env.ALTERAN_BLOBS.delete(key).catch(() => {});
    await deleteBlobByKey(env, key);
    deleted++;
  }
  return new Response(JSON.stringify({ deleted }), { headers: { 'Content-Type': 'application/json' } });
}
