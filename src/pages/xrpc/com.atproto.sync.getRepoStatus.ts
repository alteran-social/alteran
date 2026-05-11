import type { APIContext } from 'astro';
import { getRoot as getRepoRoot } from '../../db/repo';
import { getAccountState } from '../../db/dal';
import { toWireStatus } from '../../lib/account-state';

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
    // Best-effort FSM lookup: an unmigrated row or a transient DB error both
    // fall through to active=true so reads aren't blocked by an internal hiccup.
    let active = true;
    let status: string | undefined;
    try {
      const state = await getAccountState(env, did);
      if (state) {
        const wire = toWireStatus(state);
        active = wire.active;
        status = wire.status;
      }
    } catch (stateError) {
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

