import type { APIContext } from 'astro';
import { getRoot as getRepoRoot } from '../../db/repo';

export const prerender = false;

/**
 * com.atproto.sync.listRepos
 * List repositories (single-user PDS returns one repo)
 */
export async function GET({ locals, url }: APIContext) {
  const { env } = locals;

  const did = env.PDS_DID || 'did:example:single-user';
  const handle = env.PDS_HANDLE || 'user.example.com';
  const head = await getRepoRoot(env);

  return new Response(
    JSON.stringify({
      repos: [
        {
          did,
          head: head?.commitCid ?? null,
          rev: head?.rev ?? null,
          active: true,
        },
      ],
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }
  );
}
