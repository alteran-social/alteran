import type { APIContext } from 'astro';
import { errorCode } from '../../lib/errors';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError, insufficientScopeResponse } from '../../lib/oauth/resource';
import { canWriteRepo } from '../../lib/auth-scope';
import { checkRate } from '../../lib/ratelimit';
import { readJsonBounded } from '../../lib/util';
import { bumpRoot } from '../../db/repo';
import { notifySequencer } from '../../lib/sequencer';
import { setRecordBlobUsage } from '../../db/dal';
import {
  handleRepoWriteError,
  prepareDeleteRecord,
} from '../../lib/repo-write-validation';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  let auth: NonNullable<Awaited<ReturnType<typeof verifyResourceRequestHybrid>>>;
  try {
    const verified = await verifyResourceRequestHybrid(env, request);
    if (!verified) return dpopResourceUnauthorized(env);
    auth = verified;
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

  try {
    const prepared = await prepareDeleteRecord(env, auth, body);
    const { write, repo } = prepared;
    if (!canWriteRepo(auth.access, write.collection, 'delete')) return insufficientScopeResponse();

    if (!prepared.currentCid) {
      return new Response(JSON.stringify({}), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const { mst, prevMstRoot, uri, newMstBlocks } = await repo.deleteRecord(write.collection, write.rkey);
    const currentRoot = await mst.getPointer();
    const opsForCommit = [{
      action: 'delete' as const,
      path: `${write.collection}/${write.rkey}`,
      cid: null,
      prev: prepared.currentCid,
    }];
    const { commitCid, rev, commitData, sig, blocks } = await bumpRoot(env, prevMstRoot ?? undefined, currentRoot, {
      ops: opsForCommit,
      newMstBlocks: Array.from(newMstBlocks),
    });
    await setRecordBlobUsage(env, uri, []);
    await notifySequencer(env, {
      did: prepared.did,
      commitCid,
      rev,
      data: commitData,
      sig,
      ops: opsForCommit,
      blocks,
    });

    return new Response(JSON.stringify({
      commit: {
        cid: commitCid,
        rev,
      },
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return handleRepoWriteError(error);
  }
}
