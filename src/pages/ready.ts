import type { APIContext } from 'astro';

export const prerender = false;

export async function GET({ locals }: APIContext) {
  const { env } = locals.runtime;

  try {
    if (env.ALTERAN_DB) {
      await env.ALTERAN_DB.prepare('select 1').first();
    }
    return new Response('ok');
  } catch (e) {
    return new Response('db not ready', { status: 503 });
  }
}