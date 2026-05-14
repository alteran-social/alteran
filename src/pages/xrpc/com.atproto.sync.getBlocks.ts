import type { APIContext } from 'astro';
import { lexicons } from '@atproto/api';
import { isAccountActive } from '../../db/dal';
import { D1Blockstore } from '../../lib/mst';
import { CID } from 'multiformats/cid';
import { encodeExistingBlocksToCAR } from '../../services/car';

export const prerender = false;

export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const url = new URL(request.url);
  const did = url.searchParams.get('did');
  const cids = url.searchParams.getAll('cids');

  if (did === null) {
    return new Response(
      JSON.stringify({ error: 'InvalidRequest', message: 'did parameter required' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (cids.length === 0) {
    return new Response(
      JSON.stringify({ error: 'InvalidRequest', message: 'cids parameter required' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  try {
    lexicons.assertValidXrpcParams('com.atproto.sync.getBlocks', { did, cids });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'invalid getBlocks parameters';
    return new Response(
      JSON.stringify({ error: 'InvalidRequest', message }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const localDid = String(env.PDS_DID ?? '').trim();
  if (!localDid) {
    return new Response(
      JSON.stringify({ error: 'InvalidRequest', message: 'PDS_DID is not configured' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (did !== localDid) {
    return new Response(
      JSON.stringify({ error: 'RepoNotFound', message: 'Repo not found' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (!(await isAccountActive(env, did))) {
    return new Response(
      JSON.stringify({ error: 'RepoDeactivated', message: 'Repo is deactivated' }),
      { status: 403, headers: { 'Content-Type': 'application/json' } }
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
    return new Response(
      JSON.stringify({
        error: 'BlockNotFound',
        message: `Blocks not found: ${missingCids.join(', ')}`,
        details: { missingCids },
      }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const carBytes = encodeExistingBlocksToCAR(roots, blocks);

  return new Response(carBytes as any, {
    headers: {
      'Content-Type': 'application/vnd.ipld.car; version=1',
      'Content-Disposition': 'inline; filename="blocks.car"',
    },
  });
}
