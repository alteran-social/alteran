import type { APIContext } from 'astro';
import type { Env } from '../../../env';
import { deleteUnreferencedBlobKeys, listOrphanBlobRefs } from '../../../db/dal';

export const prerender = false;

function isLocalDebugAllowed(env: Env): boolean {
  const envName = (env as any).ENVIRONMENT as string | undefined;
  const host = env.PDS_HOSTNAME as string | undefined;
  return envName !== 'production' && (!host || host.includes('localhost') || host.startsWith('127.') || host === '::1');
}

export async function POST({ locals }: APIContext) {
  const { env } = locals.runtime;
  if (!isLocalDebugAllowed(env)) return new Response('Not Found', { status: 404 });

  const deleted = await deleteUnreferencedBlobKeys(env, await listOrphanBlobRefs(env));
  return new Response(JSON.stringify({ deleted }), { headers: { 'Content-Type': 'application/json' } });
}
