import type { APIContext } from 'astro';
import { errorCode } from '../../lib/errors';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError, insufficientScopeResponse } from '../../lib/oauth/resource';
import { canWriteRepo } from '../../lib/auth-scope';
import { checkRate } from '../../lib/ratelimit';
import { readJsonBounded } from '../../lib/util';
import { notifySequencer } from '../../lib/sequencer';
import { setRecordBlobUsage } from '../../db/dal';
import {
  handleRepoWriteError,
  preparePutRecord,
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
    const prepared = await preparePutRecord(env, auth, body);
    const { write, repo } = prepared;
    if (!canWriteRepo(auth.access, write.collection, 'update')) return insufficientScopeResponse();

    const result = await repo.putRecord(write.collection, write.rkey, write.record);
    await setRecordBlobUsage(env, result.uri, write.blobKeys);
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
