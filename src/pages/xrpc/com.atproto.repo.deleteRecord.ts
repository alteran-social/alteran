import type { APIContext } from 'astro';
import { errorCode } from '../../lib/errors';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError, insufficientScopeResponse } from '../../lib/oauth/resource';
import { canWriteRepo } from '../../lib/auth-scope';
import { checkRate } from '../../lib/ratelimit';
import { readJsonBounded } from '../../lib/util';
import { assertRepoHead, bumpRoot } from '../../db/repo';
import { notifySequencer } from '../../lib/sequencer';
import {
  deleteRecordStatements,
  deleteUnreferencedBlobKeys,
  getRecordBlobKeys,
  isAccountActive,
  setRecordBlobUsageStatements,
} from '../../db/dal';
import {
  assertRepoWriteInput,
  deleteRecordAuthorizations,
  handleRepoWriteError,
  jsonError,
  prepareDeleteRecord,
  RepoWriteError,
  retryNoSwapCommit,
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
    const rateLimitResponse = await checkRate(env, request, 'writes', { key: auth.did });
    if (rateLimitResponse) return rateLimitResponse;
    if (errorCode(e) === 'PayloadTooLarge') {
      return jsonError('PayloadTooLarge', undefined, 413);
    }
    return jsonError('BadRequest');
  }

  let writeRateCharged = false;
  try {
    const input = assertRepoWriteInput('com.atproto.repo.deleteRecord', body);
    for (const write of deleteRecordAuthorizations(input)) {
      if (!canWriteRepo(auth.access, write.collection, write.action)) return insufficientScopeResponse();
    }

    const rateLimitResponse = await checkRate(env, request, 'writes', { key: auth.did });
    writeRateCharged = true;
    if (rateLimitResponse) return rateLimitResponse;

    if (!(await isAccountActive(env, auth.did))) {
      return jsonError('AccountDeactivated', 'Account is deactivated. Activate it before making changes.', 403);
    }

    const committed = await retryNoSwapCommit(input, async () => {
      const prepared = await prepareDeleteRecord(env, auth, input);
      const { write, repo } = prepared;
      if (!prepared.currentCid) {
        await assertRepoHead(env, prepared.did, prepared.expectedCommitCid);
        return { prepared, result: null };
      }

      const { mst, prevMstRoot, uri, newMstBlocks, currentCid } = await repo.deleteRecord(
        write.collection,
        write.rkey,
      );
      const previousBlobKeys = await getRecordBlobKeys(env, prepared.did, uri);
      const currentRoot = await mst.getPointer();
      const opsForCommit = [{
        action: 'delete' as const,
        path: `${write.collection}/${write.rkey}`,
        cid: null,
        prev: currentCid,
      }];
      const result = await bumpRoot(env, prevMstRoot ?? undefined, currentRoot, {
        ops: opsForCommit,
        newMstBlocks: Array.from(newMstBlocks),
        expectedCommitCid: prepared.expectedCommitCid,
        sideEffectStatements: (guard) => [
          ...deleteRecordStatements(env, uri, guard),
          ...setRecordBlobUsageStatements(env, prepared.did, uri, [], guard),
        ],
      });
      return {
        prepared,
        result: {
          ...result,
          opsForCommit,
          dereferencedBlobKeys: previousBlobKeys.map((key) => ({ did: prepared.did, key })),
        },
      };
    });
    if (!committed.result) {
      return new Response(JSON.stringify({}), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    const { prepared, result } = committed;
    const { commitCid, rev, commitData, sig, blocks, opsForCommit } = result;
    await notifySequencer(env, {
      did: prepared.did,
      commitCid,
      rev,
      data: commitData,
      sig,
      ops: opsForCommit,
      blocks,
    });
    await deleteUnreferencedBlobKeys(env, result.dereferencedBlobKeys).catch((error) => {
      console.warn('[deleteRecord] Failed to clean dereferenced blobs:', error);
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
    if (!writeRateCharged && error instanceof RepoWriteError) {
      const rateLimitResponse = await checkRate(env, request, 'writes', { key: auth.did });
      if (rateLimitResponse) return rateLimitResponse;
    }
    return handleRepoWriteError(error);
  }
}
