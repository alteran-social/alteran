import type { APIContext } from 'astro';
import { verifyResourceRequestHybrid, dpopResourceUnauthorized, handleResourceAuthError } from '../../lib/oauth/resource';
import { checkRate } from '../../lib/ratelimit';
import { readJsonBounded } from '../../lib/util';
import { RepoManager } from '../../services/repo-manager';
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
  } catch (e: any) {
    if (e?.code === 'PayloadTooLarge') {
      return new Response(JSON.stringify({ error: 'PayloadTooLarge' }), { status: 413 });
    }
    return new Response(JSON.stringify({ error: 'BadRequest' }), { status: 400 });
  }
  const { collection, rkey } = body ?? {};
  let { record } = body ?? {};
  if (!collection || !record) return new Response(JSON.stringify({ error: 'BadRequest' }), { status: 400 });

  // Minimal schema alignment for app.bsky.feed.post: ensure required fields
  if (collection === 'app.bsky.feed.post' && record && typeof record === 'object') {
    if (typeof record.text !== 'string') {
      record.text = '';
    }
    if (typeof record.createdAt !== 'string') {
      record.createdAt = new Date().toISOString();
    }
  }

  const repo = new RepoManager(env);
  const result = await repo.createRecord(collection, record, rkey);
  await notifySequencer(env, {
    did: env.PDS_DID as string,
    commitCid: result.commitCid,
    rev: result.rev,
    data: result.commitData,
    sig: result.sig,
    ops: result.ops,
    blocks: result.blocks
  });

  // Conform to official PDS response schema
  const out = {
    uri: result.uri,
    cid: result.cid,
    commit: {
      cid: result.commitCid,
      rev: result.rev,
    },
    validationStatus: 'unknown' as const,
  };

  return new Response(JSON.stringify(out), {
    headers: { 'Content-Type': 'application/json' },
  });
}
