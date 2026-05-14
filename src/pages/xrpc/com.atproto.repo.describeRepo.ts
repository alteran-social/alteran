import type { APIContext } from 'astro';
import { buildDidDocument } from '../../lib/did-document';
import {
  configuredDid,
  configuredHandle,
  didDocClaimsHandle,
  handleResolvesToDid,
} from '../../lib/public-host';

export const prerender = false;

/**
 * com.atproto.repo.describeRepo
 * Get metadata about a repository
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals;

  const repo = url.searchParams.get('repo');
  const did = await configuredDid(env);
  const handle = await configuredHandle(env);
  if (repo && repo !== did && repo.toLowerCase() !== handle.toLowerCase()) {
    return new Response(
      JSON.stringify({ error: 'NotFound', message: 'Repo not found' }),
      { status: 404, headers: { 'Content-Type': 'application/json' } },
    );
  }

  const didDoc = await buildDidDocument(env, did, handle);
  const handleIsCorrect = didDocClaimsHandle(didDoc, handle) &&
    await handleResolvesToDid(env, handle, did);

  return new Response(
    JSON.stringify({
      did,
      handle,
      didDoc,
      collections: [
        'app.bsky.feed.post',
        'app.bsky.feed.like',
        'app.bsky.feed.repost',
        'app.bsky.graph.follow',
        'app.bsky.actor.profile',
      ],
      handleIsCorrect,
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }
  );
}
