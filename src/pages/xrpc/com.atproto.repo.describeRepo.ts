import type { APIContext } from 'astro';
import { configuredHandle, requireLocalRepo } from '../../lib/local-xrpc';

export const prerender = false;

/**
 * com.atproto.repo.describeRepo
 * Get metadata about a repository
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals.runtime;

  const repo = requireLocalRepo(env, url);
  if (!repo.ok) return repo.response;

  const did = repo.value;
  const handle = configuredHandle(env) || 'user.example.com';

  return new Response(
    JSON.stringify({
      did,
      handle,
      didDoc: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: did,
        alsoKnownAs: [`at://${handle}`],
        verificationMethod: [],
        service: [
          {
            id: '#atproto_pds',
            type: 'AtprotoPersonalDataServer',
            serviceEndpoint: `https://${handle}`,
          },
        ],
      },
      collections: [
        'app.bsky.feed.post',
        'app.bsky.feed.like',
        'app.bsky.feed.repost',
        'app.bsky.graph.follow',
        'app.bsky.actor.profile',
      ],
      handleIsCorrect: true,
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }
  );
}
