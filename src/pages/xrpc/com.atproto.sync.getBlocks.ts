import type { APIContext } from 'astro';
import { NotFound } from '../../lib/errors';
import { D1Blockstore } from '../../lib/mst';
import { CID } from 'multiformats/cid';
import { encodeExistingBlocksToCAR } from '../../services/car';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals;
  const url = new URL(request.url);
  const cids = (url.searchParams.get('cids') ?? '').split(',').map((s) => s.trim()).filter(Boolean);

  if (!cids.length) {
    return new Response(
      JSON.stringify({ error: 'InvalidRequest', message: 'cids parameter required' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const blockstore = new D1Blockstore(env);
  const roots: CID[] = [];
  const blocks: { cid: CID; bytes: Uint8Array }[] = [];
  const missingCids: string[] = [];

  for (const c of cids) {
    try {
      const cid = CID.parse(c);
      const bytes = await blockstore.get(cid);
      if (bytes) {
        roots.push(cid);
        blocks.push({ cid, bytes });
      } else {
        missingCids.push(c);
      }
    } catch {
      missingCids.push(c);
    }
  }

  if (missingCids.length > 0) {
    return new NotFound(
      `Blocks not found: ${missingCids.join(', ')}`,
      { missingCids }
    ).toResponse(locals.requestId);
  }

  const carBytes = encodeExistingBlocksToCAR(roots, blocks);

  return new Response(carBytes as any, {
    headers: {
      'Content-Type': 'application/vnd.ipld.car; version=1',
      'Content-Disposition': 'inline; filename="blocks.car"',
    },
  });
}
