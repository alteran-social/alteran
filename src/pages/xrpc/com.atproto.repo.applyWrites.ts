import type { APIContext } from 'astro';
import { RepoManager } from '../../services/repo-manager';
import { readJson } from '../../lib/util';
import { bumpRoot } from '../../db/repo';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError } from '../../lib/oauth/resource';
import { isAccountActive } from '../../db/dal';
import { checkRate } from '../../lib/ratelimit';
import { notifySequencer } from '../../lib/sequencer';
import { encodeBlocksForCommit } from '../../services/car';
import { CID } from 'multiformats/cid';
import { putRecord as dalPutRecord } from '../../db/dal';

export const prerender = false;

/**
 * com.atproto.repo.applyWrites
 * Apply a batch of repository writes atomically
 */
export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  try {
    const auth = await verifyResourceRequestHybrid(env, request);
    if (!auth) return dpopResourceUnauthorized(env);
  } catch (err) {
    const handled = await handleResourceAuthError(env, err);
    if (handled) return handled;
    throw err;
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
    const { repo, writes, validate = true, swapCommit } = body;

    if (!writes || !Array.isArray(writes)) {
      return new Response(
        JSON.stringify({ error: 'InvalidRequest', message: 'writes must be an array' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const repoManager = new RepoManager(env);
    const pdsDid = typeof env.PDS_DID === 'string' ? env.PDS_DID : '';
    type WriteResult = { $type: string; uri?: string; cid?: string; validationStatus?: string };
    const results: WriteResult[] = [];
    // Accumulate ops and new MST blocks for this batch
    const opsForCommit: { action: 'create'|'update'|'delete'; path: string; cid: import('multiformats/cid').CID | null }[] = [];
    const newMstBlocksAll: Array<[import('multiformats/cid').CID, Uint8Array]> = [];
    let firstPrevMst: import('multiformats/cid').CID | null = null;
    let lastMst: import('../../lib/mst').MST | null = null;

    // Apply all writes atomically
    for (const write of writes) {
      const { $type, collection, rkey, value } = write;

      if ($type === 'com.atproto.repo.applyWrites#create') {
        const { mst, recordCid, prevMstRoot, newMstBlocks } = await repoManager.addRecord(collection, rkey, value);
        if (!firstPrevMst) firstPrevMst = prevMstRoot;
        lastMst = mst;
        opsForCommit.push({ action: 'create', path: `${collection}/${rkey}`, cid: recordCid });
        for (const [cid, bytes] of newMstBlocks) newMstBlocksAll.push([cid, bytes]);
        // Persist JSON for local reads
        await dalPutRecord(env, {
          uri: `at://${pdsDid}/${collection}/${rkey}`,
          did: pdsDid,
          cid: recordCid.toString(),
          json: JSON.stringify(value),
        });
        results.push({
          $type: 'com.atproto.repo.applyWrites#createResult',
          uri: `at://${repo}/${collection}/${rkey}`,
          cid: recordCid.toString(),
          validationStatus: 'valid',
        });
      } else if ($type === 'com.atproto.repo.applyWrites#update') {
        const { mst, recordCid, prevMstRoot, newMstBlocks } = await repoManager.updateRecord(collection, rkey, value);
        if (!firstPrevMst) firstPrevMst = prevMstRoot;
        lastMst = mst;
        opsForCommit.push({ action: 'update', path: `${collection}/${rkey}`, cid: recordCid });
        for (const [cid, bytes] of newMstBlocks) newMstBlocksAll.push([cid, bytes]);
        await dalPutRecord(env, {
          uri: `at://${pdsDid}/${collection}/${rkey}`,
          did: pdsDid,
          cid: recordCid.toString(),
          json: JSON.stringify(value),
        });
        results.push({
          $type: 'com.atproto.repo.applyWrites#updateResult',
          uri: `at://${repo}/${collection}/${rkey}`,
          cid: recordCid.toString(),
          validationStatus: 'valid',
        });
      } else if ($type === 'com.atproto.repo.applyWrites#delete') {
        const { mst, prevMstRoot, newMstBlocks } = await repoManager.deleteRecord(collection, rkey);
        if (!firstPrevMst) firstPrevMst = prevMstRoot;
        lastMst = mst;
        opsForCommit.push({ action: 'delete', path: `${collection}/${rkey}`, cid: null });
        for (const [cid, bytes] of newMstBlocks) newMstBlocksAll.push([cid, bytes]);
        results.push({
          $type: 'com.atproto.repo.applyWrites#deleteResult',
        });
      }
    }

    // Bump repo root to create new commit
    const currentRoot = lastMst ? await lastMst.getPointer() : undefined;
    const { commitCid, rev, commitData, sig, blocks } = await bumpRoot(env, firstPrevMst ?? undefined, currentRoot, {
      ops: opsForCommit,
      newMstBlocks: newMstBlocksAll,
    });

    // Notify sequencer about the commit for firehose
    try {
      // Prefer commitData/sig/blocks returned by bumpRoot (authoritative)
      await notifySequencer(env, {
        did: pdsDid,
        commitCid,
        rev,
        data: commitData,
        sig,
        ops: opsForCommit,
        ...(blocks ? { blocks } : {}),
      });
    } catch (err) {
      console.error('Failed to notify sequencer:', err);
      // Don't fail the request if sequencer notification fails
    }

    return new Response(
      JSON.stringify({
        commit: { cid: commitCid, rev },
        results,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    console.error('applyWrites error:', error);
    console.error('Error stack:', error instanceof Error ? error.stack : 'No stack');
    return new Response(
      JSON.stringify({ error: 'InternalServerError', message: String(error) }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
