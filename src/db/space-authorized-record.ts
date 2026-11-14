import { MAX_RECORD_SIZE } from '@atproto/space';
import { isValidNsid, isValidRecordKey } from '@atproto/syntax-spaces';
import type { Env } from '../env';
import { DPOP_PROOF_FUTURE_SKEW_SEC, DPOP_PROOF_MAX_AGE_SEC } from '../lib/oauth/dpop-window';
import { consumeVerifiedSpacePrincipal, type VerifiedSpacePrincipal } from '../lib/oauth/space-principal';
import { allowsSpacePermission } from '../lib/spaces/oauth-scopes';
import { restoreExplicitSpaceConsent } from '../lib/spaces/explicit-read-consent';
import { assertLocalSpaceRepo, parseSpaceRef } from './space-ref';
import { oauthSpaceGrantFence, oauthSpaceGrantFenceValues } from './oauth-space-grant';
import { ASSERT_CLOCK, REFRESH_CLOCK } from './oauth-replay';
import { decodeSpaceRecord, SPACE_RECORD_COLUMNS, SPACE_RECORD_TABLES,
  type SpaceRecordRow, type StoredSpaceRecord } from './space-record-projection';
import { SpaceStorageError } from './space-types';

type CompleteRead = (request: Request, database: D1Database) => Promise<boolean>;

export type AuthorizedSpaceRecordResult =
  | { readonly tag: 'found'; readonly record: StoredSpaceRecord; readonly complete: CompleteRead }
  | { readonly tag: 'notFound'; readonly complete: CompleteRead }
  | { readonly tag: 'unauthorized' };

type SelectedRow = SpaceRecordRow & {
  readonly sentinel: number;
  readonly session_expires_at: number | null;
  readonly epoch_id: string | null;
};

/** Read private data only while the exact verified grant and account remain live. */
export async function readAuthorizedSpaceRecord(
  env: Env,
  principal: VerifiedSpacePrincipal,
  request: Request,
  space: string,
  repo: string,
  collection: string,
  rkey: string,
): Promise<AuthorizedSpaceRecordResult> {
  if (!consumeVerifiedSpacePrincipal(principal, request, env.ALTERAN_DB) ||
    !matchesRequest(request, space, repo, collection, rkey) || !windowIsLive(principal)) {
    return { tag: 'unauthorized' };
  }
  const ref = parseSpaceRef(space);
  if (!isValidNsid(collection) || !isValidRecordKey(rkey)) {
    throw new SpaceStorageError('InvalidRequest', 'Invalid collection or record key');
  }
  if (repo !== principal.did) return { tag: 'unauthorized' };
  const restored = await restoreExplicitSpaceConsent(principal.grant.snapshot, principal.grant.digest, {
    subject: principal.did, accountIncarnation: principal.grant.accountIncarnation,
    clientId: principal.clientId, dpopJkt: principal.jkt,
    clientAuthMethod: principal.grant.clientAuthMethod, clientAuthKeyId: principal.grant.clientAuthKeyId,
    clientAuthKeyBinding: principal.grant.clientAuthKeyBinding,
  }, principal.scope);
  if (!restored || !restored.grants.some((grant) => allowsSpacePermission(grant.permission, {
    spaceType: ref.spaceType, authority: ref.authorityDid, skey: ref.skey,
  }, { action: 'read_self' })) || !windowIsLive(principal)) return { tag: 'unauthorized' };
  await assertLocalSpaceRepo(env, repo);
  if (!windowIsLive(principal)) return { tag: 'unauthorized' };
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(now) || now < 0) return { tag: 'unauthorized' };
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const db = env.ALTERAN_DB;
  const authorization = authorizationSql('nonce');
  const authValues = authorizationValues(principal, nonce);
  const activeEpoch = `SELECT CASE WHEN typeof(e.id) = 'text' AND length(CAST(e.id AS BLOB)) BETWEEN 1 AND 128
      THEN e.id END FROM space s JOIN space_repo h ON h.space_ref = s.space_ref AND h.repo_did = ?
      JOIN space_owned_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
        AND e.repo_did = h.repo_did AND e.state = 'active'
      WHERE s.space_ref = ? AND s.authority_did = ? AND s.space_type = ? AND s.skey = ?
        AND s.deleted_at IS NULL AND e.owner_incarnation = ?`;
  const epochValues = [repo, ref.ref, ref.authorityDid, ref.spaceType, ref.skey, principal.grant.accountIncarnation];
  const read = db.prepare(`${authorization}
    SELECT ${SPACE_RECORD_COLUMNS}, 0 AS sentinel, NULL AS session_expires_at,
      CASE WHEN typeof(e.id) = 'text' AND length(CAST(e.id AS BLOB)) BETWEEN 1 AND 128
        THEN e.id END AS epoch_id ${SPACE_RECORD_TABLES}
    WHERE record.space_ref = ? AND record.repo_did = ? AND record.collection = ? AND record.rkey = ?
      AND space.authority_did = ? AND space.space_type = ? AND space.skey = ?
      AND EXISTS (SELECT 1 FROM authorized)
      AND EXISTS (SELECT 1 FROM space_owned_epoch owned WHERE owned.id = e.id AND owned.space_ref = e.space_ref
        AND owned.repo_did = e.repo_did AND owned.owner_incarnation = ?)
    UNION ALL SELECT NULL, NULL, NULL, NULL, 0, 1, session_expires_at, (${activeEpoch}) FROM authorized`)
    .bind(...authValues, MAX_RECORD_SIZE, MAX_RECORD_SIZE,
      ref.ref, repo, collection, rkey, ref.authorityDid, ref.spaceType, ref.skey,
      principal.grant.accountIncarnation, ...epochValues);
  const result = await db.batch([
    db.prepare(`UPDATE oauth_replay_clock SET seconds = MAX(seconds, unixepoch(), ?), nonce = ?
      WHERE id = 1 AND typeof(seconds) = 'integer' AND seconds BETWEEN 0 AND 9007199254740991`).bind(now, nonce),
    db.prepare(ASSERT_CLOCK).bind(nonce),
    read,
    db.prepare(REFRESH_CLOCK).bind(nonce),
    db.prepare(ASSERT_CLOCK).bind(nonce),
    db.prepare(`${authorization}
      SELECT clock.seconds, (SELECT session_expires_at FROM authorized) AS session_expires_at,
        EXISTS (SELECT 1 FROM space s JOIN space_repo h ON h.space_ref = s.space_ref AND h.repo_did = ?
          JOIN space_owned_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
            AND e.repo_did = h.repo_did AND e.state = 'active'
          WHERE s.space_ref = ? AND s.authority_did = ? AND s.space_type = ? AND s.skey = ?
            AND s.deleted_at IS NULL AND e.owner_incarnation = ?) AS space_active,
        (${activeEpoch}) AS epoch_id FROM clock`)
      .bind(...authValues, repo, ref.ref, ref.authorityDid, ref.spaceType, ref.skey, principal.grant.accountIncarnation,
        ...epochValues),
  ]);
  if (!Array.isArray(result) || result.length !== 6 || result.some((entry: { success?: unknown } | null) => entry?.success !== true) ||
    !clockAssertionPassed(result[1]?.results) || !clockAssertionPassed(result[4]?.results)) {
    return { tag: 'unauthorized' };
  }
  if (!windowIsLive(principal)) return { tag: 'unauthorized' };
  const finalRows = result[5]?.results;
  if (!Array.isArray(finalRows) || finalRows.length !== 1) return { tag: 'unauthorized' };
  const final = finalRows[0];
  const clock = final.seconds;
  if (typeof clock !== 'number' || !Number.isSafeInteger(clock) || clock < now ||
    principal.expiresAt <= clock || clock - principal.proofIssuedAt > DPOP_PROOF_MAX_AGE_SEC ||
    principal.proofIssuedAt - clock > DPOP_PROOF_FUTURE_SKEW_SEC) return { tag: 'unauthorized' };
  const rows = (result[2]?.results ?? []) as SelectedRow[];
  const sentinels = rows.filter((row) => row.sentinel === 1);
  const records = rows.filter((row) => row.sentinel === 0);
  if (!sentinels.length && !rows.length) return { tag: 'unauthorized' };
  if (sentinels.length !== 1 || records.length > 1 || sentinels.length + records.length !== rows.length) {
    throw new SpaceStorageError('InvalidRepoState', 'Invalid authorized Space record result');
  }
  const sessionExpiresAt = final.session_expires_at;
  if (typeof sessionExpiresAt !== 'number' || !Number.isSafeInteger(sessionExpiresAt) || sessionExpiresAt <= clock ||
    (final.space_active !== 0 && final.space_active !== 1)) {
    return { tag: 'unauthorized' };
  }
  const epoch = final.epoch_id;
  if ((final.space_active === 0 && epoch !== null) ||
    (final.space_active === 1 && (typeof epoch !== 'string' || epoch.length < 1 || epoch.length > 128 ||
      new TextEncoder().encode(epoch).byteLength > 128))) return { tag: 'unauthorized' };
  if (sentinels[0].epoch_id !== final.epoch_id ||
    (records.length > 0 && (typeof final.epoch_id !== 'string' || records[0].epoch_id !== final.epoch_id))) {
    return { tag: 'unauthorized' };
  }
  const record = records.length && final.space_active === 1 ? decodeSpaceRecord(records[0], collection) : null;
  const after = Math.floor(Date.now() / 1000);
  if (request.signal.aborted || !windowIsLiveAt(principal, after) || sessionExpiresAt <= after) {
    return { tag: 'unauthorized' };
  }
  const complete = completion(env, request, principal, ref, repo,
    typeof epoch === 'string' && epoch.length > 0 && epoch.length <= 128 ? epoch : null);
  return record ? Object.freeze({ tag: 'found', record, complete }) : Object.freeze({ tag: 'notFound', complete });
}

function authorizationSql(clockFence: 'nonce' | 'seconds'): string {
  return `WITH clock AS MATERIALIZED (
    SELECT seconds FROM oauth_replay_clock
    WHERE id = 1 AND ${clockFence === 'nonce' ? 'nonce = ?' : 'seconds >= ?'}
      AND typeof(seconds) = 'integer' AND seconds BETWEEN 0 AND 9007199254740991
  ), authorized AS MATERIALIZED (
    SELECT session.expires_at AS session_expires_at FROM oauth_session session JOIN clock
    WHERE ${authorizationPredicate('clock.seconds')}
  )`;
}

function authorizationValues(principal: VerifiedSpacePrincipal, clockFence: string | number) {
  return [clockFence, ...sessionValues(principal)];
}

function sessionValues(principal: VerifiedSpacePrincipal) {
  return [principal.sessionId, principal.accessJti, principal.did, principal.clientId,
    principal.jkt, principal.scope, principal.expiresAt, principal.proofIssuedAt, DPOP_PROOF_MAX_AGE_SEC,
    principal.proofIssuedAt, DPOP_PROOF_FUTURE_SKEW_SEC, ...oauthSpaceGrantFenceValues(principal.grant)];
}

function authorizationPredicate(clock: 'clock.seconds' | 'oauth_replay_clock.seconds'): string {
  return `session.id = ? AND session.access_jti = ? AND session.did = ? AND session.client_id = ?
    AND session.dpop_jkt = ? AND session.scope = ? AND session.revoked_at IS NULL
    AND typeof(session.expires_at) = 'integer' AND session.expires_at BETWEEN 0 AND 9007199254740991
    AND session.expires_at > ${clock}
    AND ? > ${clock} AND ${clock} - ? <= ? AND ? - ${clock} <= ?
    AND ${oauthSpaceGrantFence('session')}
    AND EXISTS (SELECT 1 FROM account_state state WHERE state.did = session.did
      AND typeof(state.active) = 'integer' AND state.active = 1
      AND state.status IS NULL AND state.suspended_until IS NULL)`;
}

// Completion is a one-use capability for the request and database that read
// the record. Its clock sample commits even when the later state check denies.
function completion(
  env: Env, request: Request, principal: VerifiedSpacePrincipal, ref: ReturnType<typeof parseSpaceRef>,
  repo: string, epoch: string | null,
): CompleteRead {
  const database = env.ALTERAN_DB;
  let consumed = false;
  return async (suppliedRequest, suppliedDatabase) => {
    if (consumed) return false;
    consumed = true;
    if (!epoch || request !== suppliedRequest || database !== suppliedDatabase || request.signal.aborted ||
      !windowIsLive(principal)) return false;
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(now) || now < 0) return false;
    const nonce = crypto.randomUUID().replaceAll('-', '');
    const sample = await database.prepare(`UPDATE oauth_replay_clock SET seconds = MAX(seconds, unixepoch(), ?), nonce = ?
      WHERE id = 1 AND typeof(seconds) = 'integer' AND seconds BETWEEN 0 AND 9007199254740991
      RETURNING seconds, nonce, EXISTS (
        SELECT 1 FROM oauth_session session WHERE ${authorizationPredicate('oauth_replay_clock.seconds')}
          AND EXISTS (SELECT 1 FROM space s JOIN space_repo h ON h.space_ref = s.space_ref AND h.repo_did = ?
            JOIN space_owned_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
              AND e.repo_did = h.repo_did AND e.state = 'active'
            WHERE s.space_ref = ? AND s.authority_did = ? AND s.space_type = ? AND s.skey = ?
              AND s.deleted_at IS NULL AND h.active_epoch_id = ? AND e.owner_incarnation = ?)
      ) AS authorized`)
      .bind(now, nonce, ...sessionValues(principal), repo, ref.ref, ref.authorityDid, ref.spaceType, ref.skey, epoch,
        principal.grant.accountIncarnation)
      .first<{ seconds: unknown; nonce: unknown; authorized: unknown }>();
    if (!sample || sample.authorized !== 1 || sample.nonce !== nonce || typeof sample.seconds !== 'number' ||
      !Number.isSafeInteger(sample.seconds) || sample.seconds < now || request.signal.aborted ||
      !windowIsLive(principal)) return false;
    const row = await database.prepare(`${authorizationSql('seconds')}
      SELECT clock.seconds, authorized.session_expires_at FROM clock JOIN authorized
      WHERE EXISTS (SELECT 1 FROM space s JOIN space_repo h ON h.space_ref = s.space_ref AND h.repo_did = ?
        JOIN space_owned_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
          AND e.repo_did = h.repo_did AND e.state = 'active'
        WHERE s.space_ref = ? AND s.authority_did = ? AND s.space_type = ? AND s.skey = ?
          AND s.deleted_at IS NULL AND h.active_epoch_id = ? AND e.owner_incarnation = ?)`)
      .bind(...authorizationValues(principal, sample.seconds), repo, ref.ref, ref.authorityDid, ref.spaceType, ref.skey, epoch,
        principal.grant.accountIncarnation)
      .first<{ seconds: unknown; session_expires_at: unknown }>();
    const after = Math.floor(Date.now() / 1000);
    return !!row && typeof row.seconds === 'number' && Number.isSafeInteger(row.seconds) && row.seconds >= sample.seconds &&
      typeof row.session_expires_at === 'number' && Number.isSafeInteger(row.session_expires_at) &&
      row.session_expires_at > row.seconds && row.session_expires_at > after &&
      !request.signal.aborted && windowIsLiveAt(principal, after);
  };
}

function clockAssertionPassed(rows: unknown): boolean {
  return Array.isArray(rows) && rows.length === 1 && rows[0]?.valid === 1;
}

function matchesRequest(request: Request, space: string, repo: string, collection: string, rkey: string): boolean {
  if (request.signal.aborted || request.method !== 'GET') return false;
  const url = new URL(request.url);
  return url.pathname === '/xrpc/com.atproto.space.getRecord' &&
    Array.from(url.searchParams.keys()).every((key) => ['space', 'repo', 'collection', 'rkey'].includes(key)) &&
    Object.entries({ space, repo, collection, rkey }).every(([key, expected]) => {
      const values = url.searchParams.getAll(key);
      return values.length === 1 && values[0] === expected;
    });
}

function windowIsLive(principal: VerifiedSpacePrincipal): boolean {
  return windowIsLiveAt(principal, Math.floor(Date.now() / 1000));
}

function windowIsLiveAt(principal: VerifiedSpacePrincipal, now: number): boolean {
  return Number.isSafeInteger(now) && now >= 0 && Number.isSafeInteger(principal.expiresAt) &&
    principal.expiresAt > now && Number.isFinite(principal.proofIssuedAt) &&
    now - principal.proofIssuedAt <= DPOP_PROOF_MAX_AGE_SEC &&
    principal.proofIssuedAt - now <= DPOP_PROOF_FUTURE_SKEW_SEC;
}
