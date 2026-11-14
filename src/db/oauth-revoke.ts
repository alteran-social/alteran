import type { Env } from '../env';
import type { OAuthSessionRow, RefreshTokenRow } from './account';
import { refreshSnapshotValues, refreshSnapshotWhere, sessionSnapshotValues, sessionSnapshotWhere } from './oauth-exchange-read';
import { ensureWorkerWindow } from './oauth-exchange';
import type { ReplayTransaction } from './oauth-replay-transaction';
import { oauthSpaceGrantFence, oauthSpaceGrantFenceValues, type OAuthSpaceGrant } from './oauth-space-grant';

/** An explicit revoke only affects the exact session state the caller authenticated. */
export async function revokeOAuthSessionSnapshot(
  env: Env,
  session: OAuthSessionRow,
  currentRefresh: RefreshTokenRow,
  presentedRefresh: RefreshTokenRow | undefined,
  replay: ReplayTransaction,
  accessExpiry?: number,
  spaceGrant?: OAuthSpaceGrant,
): Promise<void> {
  if (session.revokedAt !== null || currentRefresh.revokedAt !== null || currentRefresh.nextId !== null ||
    currentRefresh.id !== session.currentRefreshTokenId) throw new Error('Invalid OAuth revocation state');
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(now) || now < 0) throw new Error('Invalid revocation time');
  const database = env.ALTERAN_DB;
  const revoked = { ...session, revokedAt: now, updatedAt: now };
  const revokedRefresh = { ...currentRefresh, revokedAt: now };
  const presentedResult = presentedRefresh?.id === currentRefresh.id ? revokedRefresh : presentedRefresh;
  const refreshMatch = `EXISTS (SELECT 1 FROM refresh_token r WHERE ${refreshSnapshotWhere('r')})`;
  const presentedMatch = presentedRefresh ? `AND ${refreshMatch}` : '';
  const expiries = accessExpiry === undefined ? [session.expiresAt] : [session.expiresAt, accessExpiry];
  const live = `EXISTS (SELECT 1 FROM oauth_replay_clock WHERE id = 1 AND nonce = ?
    ${expiries.map(() => 'AND ? > seconds').join(' ')})`;
  const liveValues = [replay.nonce, ...expiries];
  const statements = [
    ...replay.begin,
    database.prepare(`UPDATE oauth_session AS s SET revoked_at = ?, updated_at = ?
      WHERE ${sessionSnapshotWhere('s')} AND ${refreshMatch} ${presentedMatch} AND ${live} AND ${oauthSpaceGrantFence('s', false)}`)
      .bind(now, now, ...sessionSnapshotValues(session), ...refreshSnapshotValues(currentRefresh),
        ...(presentedRefresh ? refreshSnapshotValues(presentedRefresh) : []), ...liveValues,
        ...oauthSpaceGrantFenceValues(spaceGrant)),
    database.prepare(`UPDATE refresh_token AS r SET revoked_at = ? WHERE ${refreshSnapshotWhere('r')}
      AND EXISTS (SELECT 1 FROM oauth_session s WHERE ${sessionSnapshotWhere('s')} AND ${oauthSpaceGrantFence('s', false)})`)
      .bind(now, ...refreshSnapshotValues(currentRefresh), ...sessionSnapshotValues(revoked), ...oauthSpaceGrantFenceValues(spaceGrant)),
    ...replay.finish,
    database.prepare(`SELECT CASE WHEN ${live} AND EXISTS (SELECT 1 FROM oauth_session s WHERE ${sessionSnapshotWhere('s')}
        AND ${oauthSpaceGrantFence('s', false)})
      AND ${refreshMatch} ${presentedMatch} THEN 1 ELSE json('{') END AS valid`)
      .bind(...liveValues, ...sessionSnapshotValues(revoked), ...oauthSpaceGrantFenceValues(spaceGrant), ...refreshSnapshotValues(revokedRefresh),
        ...(presentedResult ? refreshSnapshotValues(presentedResult) : [])),
  ];
  ensureWorkerWindow(replay, expiries);
  const results = await database.batch(statements);
  const row = results.at(-1)?.results?.[0] as { valid?: unknown } | undefined;
  if (row?.valid !== 1) throw new Error('OAuth revocation postcondition unavailable');
  ensureWorkerWindow(replay, expiries);
}
