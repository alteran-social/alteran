import type { APIContext } from 'astro';
import { errorCode } from '../../lib/errors';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError, insufficientScopeResponse } from '../../lib/oauth/resource';
import { canWriteRepo } from '../../lib/auth-scope';
import { checkRate } from '../../lib/ratelimit';
import { readJsonBounded } from '../../lib/util';
import { bumpRoot } from '../../db/repo';
import { notifySequencer } from '../../lib/sequencer';
import { deleteRecordStatements, setRecordBlobUsageStatements } from '../../db/dal';
import {
  assertRepoWriteInput,
  deleteRecordAuthorizations,
  handleRepoWriteError,
  jsonError,
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

  let body: any;
  try {
    body = await readJsonBounded(env, request);
  } catch (e) {
    if (errorCode(e) === 'PayloadTooLarge') {
      return jsonError('PayloadTooLarge', undefined, 413);
    }
    return jsonError('BadRequest');
  }

  try {
    const input = assertRepoWriteInput('com.atproto.repo.deleteRecord', body);
    for (const write of deleteRecordAuthorizations(input)) {
      if (!canWriteRepo(auth.access, write.collection, write.action)) return insufficientScopeResponse();
    }

    const rateLimitResponse = await checkRate(env, request, 'writes');
    if (rateLimitResponse) return rateLimitResponse;

    const prepared = await prepareDeleteRecord(env, auth, input);
    const { write, repo } = prepared;
    if (!prepared.currentCid) {
      return new Response(JSON.stringify({}), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const { mst, prevMstRoot, uri, newMstBlocks, currentCid } = await repo.deleteRecord(
      write.collection,
      write.rkey,
    );
    const currentRoot = await mst.getPointer();
    const opsForCommit = [{
      action: 'delete' as const,
      path: `${write.collection}/${write.rkey}`,
      cid: null,
      prev: currentCid,
    }];
    const { commitCid, rev, commitData, sig, blocks } = await bumpRoot(env, prevMstRoot ?? undefined, currentRoot, {
      ops: opsForCommit,
      newMstBlocks: Array.from(newMstBlocks),
      expectedCommitCid: prepared.currentCommitCid,
      sideEffectStatements: (guard) => [
        ...deleteRecordStatements(env, uri, guard),
        ...setRecordBlobUsageStatements(env, uri, [], guard),
      ],
    });
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
