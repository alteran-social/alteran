import type { Env } from '../env';
import type { CodeSnapshot } from '../lib/oauth/store';
import type { OAuthSessionRow, RefreshTokenRow } from './account';
import type { ReplayTransaction } from './oauth-replay-transaction';
import { DPOP_PROOF_FUTURE_SKEW_SEC, DPOP_PROOF_MAX_AGE_SEC } from '../lib/oauth/dpop-window';
import { refreshSnapshotValues, refreshSnapshotWhere, sessionSnapshotValues, sessionSnapshotWhere } from './oauth-exchange-read';

type SqlValue = string | number | null;
export class OAuthWorkerExpiry extends Error {
  constructor(readonly reason: 'proof' | 'grant') {
    super('OAuth exchange expired on the Worker clock');
  }
}

export function ensureWorkerWindow(replay: ReplayTransaction, expiries: readonly number[]): void {
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(now) || now < 0) throw new OAuthWorkerExpiry('grant');
  if (now - replay.proofIssuedAt > DPOP_PROOF_MAX_AGE_SEC ||
    replay.proofIssuedAt - now > DPOP_PROOF_FUTURE_SKEW_SEC) throw new OAuthWorkerExpiry('proof');
  const assertion = replay.assertion;
  if (assertion && (now - assertion.issuedAt > DPOP_PROOF_MAX_AGE_SEC ||
    assertion.issuedAt - now > DPOP_PROOF_FUTURE_SKEW_SEC || assertion.expiresAt <= now ||
    assertion.expiresAt - now > DPOP_PROOF_MAX_AGE_SEC)) throw new OAuthWorkerExpiry('grant');
  if (expiries.some((expiry) => !Number.isFinite(expiry) || expiry <= now)) throw new OAuthWorkerExpiry('grant');
}

export type OAuthIssuedRows = {
  readonly session: OAuthSessionRow;
  readonly refresh: RefreshTokenRow;
  readonly accessExpiresAt: number;
  readonly refreshExpiresAt: number;
};

const INSERT_SESSION = `INSERT INTO oauth_session
  (id, did, client_id, client_auth_method, client_auth_key_id, client_auth_key_binding, dpop_jkt, scope,
   current_refresh_token_id, access_jti, created_at, updated_at, expires_at, revoked_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
const INSERT_REFRESH = `INSERT INTO refresh_token
  (id, did, expires_at, app_password_name, next_id, token_kind, oauth_session_id, client_id,
   client_auth_method, client_auth_key_id, dpop_jkt, oauth_scope, access_jti, revoked_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
const SESSION_MATCHES = `EXISTS (SELECT 1 FROM oauth_session s WHERE ${sessionSnapshotWhere('s')})`;
const REFRESH_MATCHES = `EXISTS (SELECT 1 FROM refresh_token r WHERE ${refreshSnapshotWhere('r')})`;

function finalClock(nonce: string, expiries: readonly number[]): { sql: string; values: SqlValue[] } {
  if (!expiries.every(Number.isFinite)) throw new Error('Invalid OAuth expiry');
  return {
    sql: `EXISTS (SELECT 1 FROM oauth_replay_clock clock WHERE clock.id = 1 AND clock.nonce = ?
      ${expiries.map(() => 'AND ? > clock.seconds').join(' ')})`,
    values: [nonce, ...expiries],
  };
}

function ensureResult(results: D1Result[], index: number): void {
  const row = results[index]?.results?.[0] as { valid?: unknown } | undefined;
  if (row?.valid !== 1) throw new Error('OAuth exchange postcondition unavailable');
}

/** Consume the exact verified code and create both token rows in one transaction. */
export async function commitOAuthCodeExchange(
  env: Env,
  code: CodeSnapshot,
  replay: ReplayTransaction,
  issued: OAuthIssuedRows,
): Promise<void> {
  const database = env.ALTERAN_DB;
  const key = `oauth:code:${code.record.code}`;
  const receipt = JSON.stringify({ used: true, attempt: replay.nonce });
  const expiries = [code.record.expiresAt, issued.session.expiresAt, issued.accessExpiresAt, issued.refreshExpiresAt];
  const clock = finalClock(replay.nonce, expiries);
  const statements = [
    ...replay.begin,
    database.prepare(`UPDATE secret SET value = ?, updated_at = ? WHERE key = ? AND value = ? AND ${clock.sql}`)
      .bind(receipt, issued.session.createdAt * 1000, key, code.value, ...clock.values),
    database.prepare(INSERT_SESSION).bind(...sessionSnapshotValues(issued.session)),
    database.prepare(INSERT_REFRESH).bind(...refreshSnapshotValues(issued.refresh)),
    ...replay.finish,
    database.prepare(`SELECT CASE WHEN ${clock.sql}
      AND EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
      AND ${SESSION_MATCHES} AND ${REFRESH_MATCHES} THEN 1 ELSE json('{') END AS valid`)
      .bind(...clock.values, key, receipt, ...sessionSnapshotValues(issued.session), ...refreshSnapshotValues(issued.refresh)),
  ];
  ensureWorkerWindow(replay, expiries);
  const results = await database.batch(statements);
  ensureResult(results, statements.length - 1);
}

/** Atomically rotate an exact live refresh/session snapshot. */
export async function commitOAuthRefreshRotation(
  env: Env,
  previous: { readonly refresh: RefreshTokenRow; readonly session: OAuthSessionRow },
  replay: ReplayTransaction,
  issued: OAuthIssuedRows,
  signedExpiry: number,
  now: number,
): Promise<void> {
  if (previous.refresh.revokedAt !== null || previous.refresh.nextId !== null || previous.session.revokedAt !== null ||
    previous.session.currentRefreshTokenId !== previous.refresh.id || previous.session.accessJti !== previous.refresh.accessJti) {
    throw new Error('Invalid OAuth refresh rotation state');
  }
  const database = env.ALTERAN_DB;
  const oldRefresh = { ...previous.refresh, nextId: issued.refresh.id, revokedAt: now };
  const updatedSession = { ...previous.session, currentRefreshTokenId: issued.refresh.id,
    accessJti: issued.session.accessJti, expiresAt: issued.session.expiresAt, updatedAt: now };
  const expiries = [previous.refresh.expiresAt, previous.session.expiresAt, signedExpiry,
    issued.session.expiresAt, issued.accessExpiresAt, issued.refreshExpiresAt];
  const clock = finalClock(replay.nonce, expiries);
  const statements = [
    ...replay.begin,
    database.prepare(`UPDATE refresh_token AS r SET next_id = ?, revoked_at = ? WHERE ${refreshSnapshotWhere('r')} AND ${clock.sql}`)
      .bind(issued.refresh.id, now, ...refreshSnapshotValues(previous.refresh), ...clock.values),
    database.prepare(INSERT_REFRESH).bind(...refreshSnapshotValues(issued.refresh)),
    database.prepare(`UPDATE oauth_session AS s SET current_refresh_token_id = ?, access_jti = ?, expires_at = ?, updated_at = ?
      WHERE ${sessionSnapshotWhere('s')} AND ${clock.sql}`)
      .bind(issued.refresh.id, issued.session.accessJti, issued.session.expiresAt, now,
        ...sessionSnapshotValues(previous.session), ...clock.values),
    ...replay.finish,
    database.prepare(`SELECT CASE WHEN ${clock.sql} AND ${REFRESH_MATCHES} AND ${REFRESH_MATCHES}
      AND ${SESSION_MATCHES} THEN 1 ELSE json('{') END AS valid`)
      .bind(...clock.values, ...refreshSnapshotValues(oldRefresh), ...refreshSnapshotValues(issued.refresh),
        ...sessionSnapshotValues(updatedSession)),
  ];
  ensureWorkerWindow(replay, expiries);
  const results = await database.batch(statements);
  ensureResult(results, statements.length - 1);
}

/** Revoke only an authenticated replay whose already-used snapshots still match. */
export async function commitOAuthRefreshReplay(
  env: Env,
  previous: { readonly refresh: RefreshTokenRow; readonly session: OAuthSessionRow },
  replay: ReplayTransaction,
  signedExpiry: number,
  now: number,
): Promise<void> {
  if (previous.refresh.revokedAt === null || !previous.refresh.nextId || previous.session.revokedAt !== null ||
    previous.session.currentRefreshTokenId === previous.refresh.id) {
    throw new Error('Invalid OAuth refresh replay state');
  }
  const database = env.ALTERAN_DB;
  const revokedSession = { ...previous.session, revokedAt: now, updatedAt: now };
  const expiries = [previous.refresh.expiresAt, previous.session.expiresAt, signedExpiry];
  const clock = finalClock(replay.nonce, expiries);
  const statements = [
    ...replay.begin,
    database.prepare(`UPDATE oauth_session AS s SET revoked_at = ?, updated_at = ?
      WHERE ${sessionSnapshotWhere('s')} AND ${REFRESH_MATCHES} AND ${clock.sql}`)
      .bind(now, now, ...sessionSnapshotValues(previous.session), ...refreshSnapshotValues(previous.refresh), ...clock.values),
    ...replay.finish,
    database.prepare(`SELECT CASE WHEN ${clock.sql} AND ${REFRESH_MATCHES} AND ${SESSION_MATCHES}
      THEN 1 ELSE json('{') END AS valid`)
      .bind(...clock.values, ...refreshSnapshotValues(previous.refresh), ...sessionSnapshotValues(revokedSession)),
  ];
  ensureWorkerWindow(replay, expiries);
  const results = await database.batch(statements);
  ensureResult(results, statements.length - 1);
}
