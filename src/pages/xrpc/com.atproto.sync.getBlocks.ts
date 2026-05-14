import type { APIContext } from 'astro';
import { D1Blockstore } from '../../lib/mst';
import { requireCidArray, requireLocalDid, xrpcError } from '../../lib/local-xrpc';
import { encodeExistingBlocksToCAR } from '../../services/car';
import type { CID } from 'multiformats/cid';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const url = new URL(request.url);
  const did = requireLocalDid(env, url);
  if (!did.ok) return did.response;

  const cids = requireCidArray(url);
  if (!cids.ok) return cids.response;

  const blockstore = new D1Blockstore(env);
  const roots: CID[] = [];
  const blocks: { cid: CID; bytes: Uint8Array }[] = [];
  const missingCids: string[] = [];

  for (const cid of cids.value) {
    const bytes = await blockstore.get(cid);
    if (bytes) {
      roots.push(cid);
      blocks.push({ cid, bytes });
    } else {
      missingCids.push(cid.toString());
    }
  }

  if (missingCids.length > 0) {
    return xrpcError('BlockNotFound', `Blocks not found: ${missingCids.join(', ')}`);
  }

  const carBytes = encodeExistingBlocksToCAR(roots, blocks);

  return new Response(carBytes as any, {
    headers: {
      'Content-Type': 'application/vnd.ipld.car; version=1',
      'Content-Disposition': 'inline; filename="blocks.car"',
    },
  });
}
