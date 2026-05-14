import type { APIContext } from 'astro';

export async function GET(ctx: APIContext) {
  try {
    const db = (ctx.locals as any).env?.ALTERAN_DB ?? (ctx.locals as any).ALTERAN_DB ?? (globalThis as any).ALTERAN_DB;
    if (db) {
      await db.prepare('select 1').first();
    }
    return new Response('ok', { status: 200 });
  } catch {
    return new Response('db not ready', { status: 503 });
  }
}

