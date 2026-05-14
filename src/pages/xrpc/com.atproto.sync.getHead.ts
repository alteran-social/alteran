import type { APIContext } from 'astro';
import { getRoot as getRepoRoot } from '../../db/repo';

export const prerender = false;

export async function GET({ locals }: APIContext) {
  const { env } = locals;
  const root = await getRepoRoot(env);
  if (!root) {
    return new Response(
      JSON.stringify({ error: 'HeadNotFound', message: 'Head not found' }),
      { status: 404, headers: { 'Content-Type': 'application/json' } }
    );
  }
  return new Response(JSON.stringify({ root: root.commitCid }), { headers: { 'Content-Type': 'application/json' } });
}
