import type { APIContext } from 'astro';
import { getLabelerServiceViews } from '../../lib/labeler';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals;
  const url = new URL(request.url);

  const didParams = url.searchParams.getAll('dids');
  const dids = didParams
    .flatMap((entry) => entry.split(',').map((did) => did.trim()))
    .filter(Boolean);

  if (dids.length === 0) {
    return new Response(JSON.stringify({ error: 'BadRequest', message: 'dids parameter required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const detailed = url.searchParams.get('detailed') === 'true';

  const views = await getLabelerServiceViews(env, dids, { detailed });

  return new Response(JSON.stringify({ views }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
