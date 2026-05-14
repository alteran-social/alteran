import type { APIContext } from 'astro';

export async function GET(ctx: APIContext) {
  const env: any = (ctx.locals as any).env ?? (ctx.locals as any) ?? (globalThis as any);
  return new Response(env.PDS_DID ?? '', { status: 200 });
}

