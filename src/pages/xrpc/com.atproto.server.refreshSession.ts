import type { APIContext } from 'astro';
import { bearerToken } from '../../lib/util';
import { lazyCleanupExpiredTokens } from '../../lib/token-cleanup';
import { attemptRefresh, type RefreshOutcome } from '../../lib/refresh-session';
import { buildDidDocument } from '../../lib/did-document';
import { getAccountState } from '../../db/dal';
import { getAccountByIdentifier } from '../../db/account';
import { toWireStatus } from '../../lib/account-state';

export const prerender = false;

export async function POST({ locals, request }: APIContext) {
  const { env } = locals;
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
  const accountState = await getAccountState(env, outcome.did);
  const wire = accountState ? toWireStatus(accountState) : { active: true };
  const account = await getAccountByIdentifier(env, outcome.did);
  const email = account?.email ?? (env.PDS_EMAIL as string | undefined);

  return new Response(
    JSON.stringify({
      did: outcome.did,
      didDoc,
      handle: outcome.handle,
      accessJwt: outcome.accessJwt,
      refreshJwt: outcome.refreshJwt,
      active: wire.active,
      ...(wire.status ? { status: wire.status } : {}),
      ...(email ? { email, emailConfirmed: true, emailAuthFactor: false } : {}),
    }),
    { headers: { 'Content-Type': 'application/json' } },
  );
}
