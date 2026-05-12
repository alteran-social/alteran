import type { APIContext } from 'astro';
import { listOrphanBlobKeys, deleteBlobByKey } from '../../../db/dal';

export const prerender = false;

export async function POST({ locals }: APIContext) {
  const { env } = locals.runtime;
  const keys = await listOrphanBlobKeys(env);
  let deleted = 0;
  for (const key of keys) {
    await env.ALTERAN_BLOBS.delete(key).catch(() => {});
    await deleteBlobByKey(env, key);
    deleted++;
  }
  return new Response(JSON.stringify({ deleted }), { headers: { 'Content-Type': 'application/json' } });
}
