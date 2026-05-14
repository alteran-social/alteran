import type { APIContext } from 'astro';
import { getRecordsByCids as dalGetByCids } from '../../db/dal';
import { tryParse } from '../../lib/util';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals;
  const url = new URL(request.url);
  const cids = (url.searchParams.get('cids') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const rows = await dalGetByCids(env, cids);
  const blocks = rows.map((r) => ({ cid: r.cid, value: tryParse(r.json) }));
  return new Response(JSON.stringify({ blocks }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
