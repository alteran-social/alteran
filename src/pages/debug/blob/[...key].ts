import type { APIContext } from 'astro';

export const prerender = false;

export async function GET({ locals, params }: APIContext) {
  const { env } = locals.runtime;
  const key = params.key;
  if (!key) return new Response('missing key', { status: 400 });

  const obj = await env.ALTERAN_BLOBS.get(key);
  if (!obj) return new Response('not found', { status: 404 });

  const body = obj.body as unknown as BodyInit | null;
  return new Response(body ?? undefined, {
    headers: { 'content-type': obj.httpMetadata?.contentType ?? 'application/octet-stream' },
  });
}

export async function PUT({ locals, request, params }: APIContext) {
  const { env } = locals.runtime;
  const key = params.key;
  if (!key) return new Response('missing key', { status: 400 });

  const body = await request.arrayBuffer();
  await env.ALTERAN_BLOBS.put(key, body, { httpMetadata: { contentType: request.headers.get('content-type') ?? 'application/octet-stream' } });
  return new Response('uploaded');
}
