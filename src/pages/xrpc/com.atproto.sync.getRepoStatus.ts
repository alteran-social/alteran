import type { APIContext } from 'astro';
import { getRoot as getRepoRoot } from '../../db/repo';
import { isAccountActive, getAccountState } from '../../db/dal';

export const prerender = false;

/**
 * com.atproto.sync.getRepoStatus
 * Mirrors upstream PDS: returns did, active, optional status, and rev if active.
 */
export async function GET({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const url = new URL(request.url);
  const configuredDid = typeof env.PDS_DID === 'string' ? env.PDS_DID : '';
  const did = url.searchParams.get('did') ?? configuredDid;

  try {
    const active = await isAccountActive(env, did);
    let status: string | undefined = undefined;
    try {
      const state = await getAccountState(env, did);
      if (state && state.active === false) status = 'desynchronized';
    } catch (stateError) {
      // Account-state lookup is best-effort; falls through with status undefined.
      console.warn('getAccountState failed:', stateError);
    }

    let rev: string | undefined;
    if (active) {
      const head = await getRepoRoot(env);
      if (head?.rev) rev = String(head.rev);
    }

    return new Response(
      JSON.stringify({ did, active, ...(status ? { status } : {}), ...(rev ? { rev } : {}) }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('RepoNotFound')) {
      return new Response(JSON.stringify({ error: 'RepoNotFound', message }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({ error: 'InternalServerError', message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

