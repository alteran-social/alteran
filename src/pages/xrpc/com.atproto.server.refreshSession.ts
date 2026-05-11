import type { APIContext } from 'astro';
import { bearerToken } from '../../lib/util';
import { lazyCleanupExpiredTokens } from '../../lib/token-cleanup';
import { attemptRefresh, type RefreshOutcome } from '../../lib/refresh-session';
import { buildDidDocument } from '../../lib/did-document';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals.runtime;
  const token = bearerToken(request);
  const nowSec = Math.floor(Date.now() / 1000);

  const outcome: RefreshOutcome = await attemptRefresh({ env, token, nowSec });

  // Cleanup is best-effort and runs ~1% of the time regardless of outcome.
  lazyCleanupExpiredTokens(env).catch(console.error);

  if (outcome.tag === 'failure') {
    return new Response(
      JSON.stringify({ error: outcome.code, message: outcome.message }),
      { status: outcome.status, headers: { 'Content-Type': 'application/json' } },
    );
  }

  const didDoc = await buildDidDocument(env, outcome.did, outcome.handle);

  return new Response(
    JSON.stringify({
      did: outcome.did,
      didDoc,
      handle: outcome.handle,
      accessJwt: outcome.accessJwt,
      refreshJwt: outcome.refreshJwt,
      active: true,
    }),
    { headers: { 'Content-Type': 'application/json' } },
  );
}
