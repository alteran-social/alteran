import type { APIContext } from 'astro';
import { errorCode } from '../../lib/errors';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError, insufficientScopeResponse } from '../../lib/oauth/resource';
import { canWriteRepo } from '../../lib/auth-scope';
import { checkRate } from '../../lib/ratelimit';
import { readJsonBounded } from '../../lib/util';
import { notifySequencer } from '../../lib/sequencer';
import {
  assertRepoWriteInput,
  createRecordAuthorizations,
  handleRepoWriteError,
  jsonError,
  prepareCreateRecord,
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
    const input = assertRepoWriteInput('com.atproto.repo.createRecord', body);
    for (const write of createRecordAuthorizations(input)) {
      if (!canWriteRepo(auth.access, write.collection, write.action)) return insufficientScopeResponse();
    }

    const rateLimitResponse = await checkRate(env, request, 'writes');
    if (rateLimitResponse) return rateLimitResponse;

    const prepared = await prepareCreateRecord(env, auth, input);
    const { write, repo } = prepared;
    const result = await repo.createRecord(
      write.collection,
      write.record,
      write.rkey,
      write.blobKeys,
      prepared.currentCommitCid,
    );
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
      validationStatus: write.validationStatus,
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return handleRepoWriteError(error);
  }
}
