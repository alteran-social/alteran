import type { APIContext } from 'astro';
import { errorCode } from '../../lib/errors';
import { readJsonBounded } from '../../lib/util';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError, insufficientScopeResponse } from '../../lib/oauth/resource';
import { canWriteRepo } from '../../lib/auth-scope';
import { deleteUnreferencedBlobKeys, isAccountActive } from '../../db/dal';
import { checkRate } from '../../lib/ratelimit';
import { notifySequencer } from '../../lib/sequencer';
import {
  applyWritesAuthorizations,
  assertRepoWriteInput,
  handleRepoWriteError,
  jsonError,
  prepareApplyWrites,
  RepoWriteError,
  retryNoSwapCommit,
} from '../../lib/repo-write-validation';

export const prerender = false;

/**
 * com.atproto.repo.applyWrites
 * Apply a batch of repository writes atomically
 */
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
    const input = assertRepoWriteInput('com.atproto.repo.applyWrites', body);
    if (input.writes.length > 200) {
      const rateLimitResponse = await checkRate(env, request, 'writes', { key: auth.did });
      writeRateCharged = true;
      if (rateLimitResponse) return rateLimitResponse;
      return jsonError('InvalidRequest', 'Too many writes. Max: 200');
    }
    for (const write of applyWritesAuthorizations(input)) {
      if (!canWriteRepo(auth.access, write.collection, write.action)) return insufficientScopeResponse();
    }

    const rateLimitResponse = await checkRate(env, request, 'writes', {
      key: auth.did,
      cost: input.writes.length,
    });
    writeRateCharged = true;
    if (rateLimitResponse) return rateLimitResponse;

    // Check if account is active
    const did = env.PDS_DID as string;
    const active = await isAccountActive(env, did);
    if (!active) {
      return new Response(
        JSON.stringify({
          error: 'AccountDeactivated',
          message: 'Account is deactivated. Activate it before making changes.'
        }),
        { status: 403, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const { prepared, applied } = await retryNoSwapCommit(input, async () => {
      const prepared = await prepareApplyWrites(env, auth, input);
      const applied = await prepared.repo.applyPreparedWrites(prepared.writes, prepared.expectedCommitCid);
      return { prepared, applied };
    });

    // Notify sequencer about the commit for firehose
    if (applied.commit && applied.commitCid && applied.rev && applied.commitData && applied.sig && applied.blocks) {
      await notifySequencer(env, {
        did: prepared.did,
        commitCid: applied.commitCid,
        rev: applied.rev,
        data: applied.commitData,
        sig: applied.sig,
        ops: applied.ops,
        blocks: applied.blocks,
      });
      await deleteUnreferencedBlobKeys(env, applied.dereferencedBlobKeys).catch((error) => {
        console.warn('[applyWrites] Failed to clean dereferenced blobs:', error);
      });
    }

    return new Response(
      JSON.stringify({
        ...(applied.commit ? { commit: applied.commit } : {}),
        results: applied.results,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    if (!writeRateCharged && error instanceof RepoWriteError) {
      const rateLimitResponse = await checkRate(env, request, 'writes', { key: auth.did });
      if (rateLimitResponse) return rateLimitResponse;
    }
    try {
      return handleRepoWriteError(error);
    } catch (unhandled) {
      console.error('applyWrites error:', unhandled);
      console.error('Error stack:', unhandled instanceof Error ? unhandled.stack : 'No stack');
      return new Response(
        JSON.stringify({ error: 'InternalServerError', message: String(unhandled) }),
        { status: 500, headers: { 'Content-Type': 'application/json' } }
      );
    }
  }
}
