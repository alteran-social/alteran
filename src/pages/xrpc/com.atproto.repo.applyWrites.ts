import type { APIContext } from 'astro';
import { readJson } from '../../lib/util';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError, insufficientScopeResponse } from '../../lib/oauth/resource';
import { canWriteRepo } from '../../lib/auth-scope';
import { isAccountActive } from '../../db/dal';
import { checkRate } from '../../lib/ratelimit';
import { notifySequencer } from '../../lib/sequencer';
import {
  handleRepoWriteError,
  prepareApplyWrites,
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

  const rateLimitResponse = await checkRate(env, request, 'writes');
  if (rateLimitResponse) return rateLimitResponse;

  try {
    const body = await readJson(request);
    const prepared = await prepareApplyWrites(env, auth, body);
    for (const write of prepared.writes) {
      if (!canWriteRepo(auth.access, write.collection, write.action)) return insufficientScopeResponse();
    }
    const applied = await prepared.repo.applyPreparedWrites(prepared.writes);

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
