import type { APIContext } from 'astro';
import { drizzle } from 'drizzle-orm/d1';
import { commit_log } from '../../../db/schema';
import { desc } from 'drizzle-orm';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const host = env.PDS_HOSTNAME as string | undefined;
  const envName = (env as any).ENVIRONMENT as string | undefined;
  const isLocal = envName !== 'production' && (!host || host.includes('localhost') || host.startsWith('127.') || host === '::1');
  if (!isLocal) return new Response('Not Found', { status: 404 });

  const url = new URL(request.url);
  const n = Math.min(Number(url.searchParams.get('n') ?? '20') || 20, 200);
  const db = drizzle(env.ALTERAN_DB);
  const rows = await db.select().from(commit_log).orderBy(desc(commit_log.seq)).limit(n).all();
  return new Response(JSON.stringify({ commits: rows }), { headers: { 'content-type': 'application/json' } });
}
