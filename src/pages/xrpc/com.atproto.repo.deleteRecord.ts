import type { APIContext } from 'astro';
import { errorCode, errorMessage } from '../../lib/errors';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError } from '../../lib/oauth/resource';
import { checkRate } from '../../lib/ratelimit';
import { readJsonBounded } from '../../lib/util';
import { RepoManager } from '../../services/repo-manager';
import { bumpRoot } from '../../db/repo';
import { notifySequencer } from '../../lib/sequencer';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  try {
    const auth = await verifyResourceRequestHybrid(env, request);
    if (!auth) return dpopResourceUnauthorized(env);
  } catch (error) {
    const handled = await handleResourceAuthError(env, error);
    if (handled) return handled;
    throw error;
  }

  const rateLimitResponse = await checkRate(env, request, 'writes');
  if (rateLimitResponse) return rateLimitResponse;

  let body: any;
  try {
    body = await readJsonBounded(env, request);
  } catch (e) {
    if (errorCode(e) === 'PayloadTooLarge') {
      return new Response(JSON.stringify({ error: 'PayloadTooLarge' }), { status: 413 });
    }
    return new Response(JSON.stringify({ error: 'BadRequest' }), { status: 400 });
  }
  const { collection, rkey } = body ?? {};
  if (!collection || !rkey) return new Response(JSON.stringify({ error: 'BadRequest' }), { status: 400 });

  const repo = new RepoManager(env);
  // Perform the delete in the MST, gather prev/new roots & new blocks
  const { mst, prevMstRoot, uri, newMstBlocks } = await repo.deleteRecord(collection, rkey);

  // Build ops & bump the repo root to create a signed commit
  const currentRoot = await mst.getPointer();
  const opsForCommit = [{ action: 'delete' as const, path: `${collection}/${rkey}`, cid: null }];
  const { commitCid, rev, commitData, sig, blocks } = await bumpRoot(env, prevMstRoot ?? undefined, currentRoot, {
    ops: opsForCommit,
    newMstBlocks: Array.from(newMstBlocks),
  });

  // Notify sequencer with a complete payload matching handleCommitNotification
  await notifySequencer(env, {
    did: env.PDS_DID as string,
    commitCid,
    rev,
    data: commitData,
    sig,
    ops: opsForCommit,
    blocks,
  });

  // Respond with official schema
  const out = {
    commit: {
      cid: commitCid,
      rev,
    },
  };

  return new Response(JSON.stringify(out), {
    headers: { 'Content-Type': 'application/json' },
  });
}
