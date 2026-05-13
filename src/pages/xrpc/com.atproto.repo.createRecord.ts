import type { APIContext } from 'astro';
import { errorCode } from '../../lib/errors';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError, insufficientScopeResponse } from '../../lib/oauth/resource';
import { canWriteRepo } from '../../lib/auth-scope';
import { checkRate } from '../../lib/ratelimit';
import { readJsonBounded } from '../../lib/util';
import { notifySequencer } from '../../lib/sequencer';
import { isAccountActive } from '../../db/dal';
import {
  assertRepoWriteInput,
  createRecordAuthorizations,
  handleRepoWriteError,
  jsonError,
  prepareCreateRecord,
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
    const input = assertRepoWriteInput('com.atproto.repo.createRecord', body);
    for (const write of createRecordAuthorizations(input)) {
      if (!canWriteRepo(auth.access, write.collection, write.action)) return insufficientScopeResponse();
    }

    const rateLimitResponse = await checkRate(env, request, 'writes', { key: auth.did });
    writeRateCharged = true;
    if (rateLimitResponse) return rateLimitResponse;

    if (!(await isAccountActive(env, auth.did))) {
      return jsonError('AccountDeactivated', 'Account is deactivated. Activate it before making changes.', 403);
    }

    const { prepared, result } = await retryNoSwapCommit(input, async () => {
      const prepared = await prepareCreateRecord(env, auth, input);
      const { write, repo } = prepared;
      const result = await repo.createRecord(
        write.collection,
        write.record,
        write.rkey,
        write.blobKeys,
        prepared.expectedCommitCid,
      );
      return { prepared, result };
    });
    await notifySequencer(env, {
      did: prepared.did,
      commitCid: result.commitCid,
      rev: result.rev,
      data: result.commitData,
      sig: result.sig,
      ops: result.ops,
      blocks: result.blocks
    });

    return new Response(JSON.stringify({
      uri: result.uri,
      cid: result.cid,
      commit: {
        cid: result.commitCid,
        rev: result.rev,
      },
      validationStatus: prepared.write.validationStatus,
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
