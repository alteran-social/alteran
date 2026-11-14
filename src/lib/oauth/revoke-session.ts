import type { Env } from '../../env';
import type { OAuthSessionRow, RefreshTokenRow } from '../../db/account';
import { loadOAuthRefreshSnapshot, loadOAuthSessionSnapshot, refreshSnapshotValues, sessionSnapshotValues } from '../../db/oauth-exchange-read';
import { OAuthWorkerExpiry } from '../../db/oauth-exchange';
import { prepareReplayTransaction, replayProofBlocked, replayProofExpired } from '../../db/oauth-replay-transaction';
import { revokeOAuthSessionSnapshot } from '../../db/oauth-revoke';
import { requireStoredClientAuthentication } from './clients';
import { getAuthzNonce, type DpopVerification } from './dpop';
import { DpopNonceError } from './dpop-errors';
import type { OAuthSpaceGrant } from '../../db/oauth-space-grant';

export async function revokeAuthenticatedSession(
  env: Env,
  session: OAuthSessionRow,
  proof: DpopVerification,
  issuer: string,
  form: URLSearchParams,
  accessExpiry?: number,
  presentedRefresh?: RefreshTokenRow,
  spaceGrant?: OAuthSpaceGrant,
): Promise<void> {
  if (session.revokedAt !== null) return;
  const currentSnapshot = await loadOAuthRefreshSnapshot(env, session.currentRefreshTokenId);
  if (!currentSnapshot) throw new Error('OAuth current refresh unavailable');
  if (!equalValues(sessionSnapshotValues(currentSnapshot.session), sessionSnapshotValues(session))) return;
  const currentRefresh = currentSnapshot.refresh;
  if (currentRefresh.tokenKind !== 'oauth' || currentRefresh.revokedAt !== null || currentRefresh.nextId !== null ||
    currentRefresh.did !== session.did || currentRefresh.clientId !== session.clientId ||
    currentRefresh.clientAuthMethod !== session.clientAuthMethod || currentRefresh.clientAuthKeyId !== session.clientAuthKeyId ||
    currentRefresh.dpopJkt !== session.dpopJkt || currentRefresh.oauthScope !== session.scope ||
    currentRefresh.accessJti !== session.accessJti ||
    (presentedRefresh?.id === currentRefresh.id && !equalValues(refreshSnapshotValues(presentedRefresh), refreshSnapshotValues(currentRefresh)))) {
    throw new Error('Invalid OAuth current refresh state');
  }
  const auth = await requireStoredClientAuthentication(env, session.clientId, issuer, form, {
    method: session.clientAuthMethod, keyId: session.clientAuthKeyId, keyBinding: session.clientAuthKeyBinding,
  }, { deferReplay: true });
  const nonce = await getAuthzNonce(env);
  const replay = prepareReplayTransaction(env, proof, auth.replay);
  if (!replay) throw new DpopNonceError('Invalid DPoP proof', nonce);
  try {
    await revokeOAuthSessionSnapshot(env, session, currentRefresh, presentedRefresh, replay, accessExpiry, spaceGrant);
  } catch (error) {
    if (error instanceof OAuthWorkerExpiry) {
      if (error.reason === 'proof') throw new DpopNonceError('DPoP proof expired', nonce);
      return;
    }
    const current = await loadOAuthSessionSnapshot(env, session.id);
    const expected = sessionSnapshotValues(session);
    if (!current || !equalValues(sessionSnapshotValues(current), expected)) return;
    const latestRefresh = await loadOAuthRefreshSnapshot(env, currentRefresh.id);
    if (!latestRefresh || !equalValues(refreshSnapshotValues(latestRefresh.refresh), refreshSnapshotValues(currentRefresh))) throw error;
    if (presentedRefresh) {
      const latestPresented = await loadOAuthRefreshSnapshot(env, presentedRefresh.id);
      if (!latestPresented || !equalValues(refreshSnapshotValues(latestPresented.refresh), refreshSnapshotValues(presentedRefresh))) return;
    }
    if (await replayProofExpired(env, replay.proofIssuedAt)) throw new DpopNonceError('DPoP proof expired', nonce);
    if (await replayProofBlocked(env, replay.proofKey)) throw new DpopNonceError('DPoP proof replayed', nonce);
    const clock = await env.ALTERAN_DB.prepare('SELECT MAX(seconds, unixepoch()) AS seconds FROM oauth_replay_clock WHERE id = 1')
      .first<{ seconds: number }>();
    if (!clock || !Number.isSafeInteger(clock.seconds)) throw new Error('Invalid OAuth replay clock');
    if (session.expiresAt <= clock.seconds || (accessExpiry !== undefined && accessExpiry <= clock.seconds)) return;
    throw error;
  }
}

function equalValues(left: readonly (string | number | null)[], right: readonly (string | number | null)[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
