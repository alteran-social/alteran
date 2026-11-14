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

export type AuthorizedSpaceRecordResult =
  | { readonly tag: 'found'; readonly record: StoredSpaceRecord }
  | { readonly tag: 'notFound' | 'unauthorized' };

type SelectedRow = SpaceRecordRow & { readonly sentinel: number; readonly session_expires_at: number | null };

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
  const authorization = `WITH clock AS MATERIALIZED (
    SELECT seconds FROM oauth_replay_clock
    WHERE id = 1 AND nonce = ? AND typeof(seconds) = 'integer' AND seconds BETWEEN 0 AND 9007199254740991
  ), authorized AS MATERIALIZED (
    SELECT session.expires_at AS session_expires_at FROM oauth_session session JOIN clock
    WHERE session.id = ? AND session.access_jti = ? AND session.did = ? AND session.client_id = ?
      AND session.dpop_jkt = ? AND session.scope = ? AND session.revoked_at IS NULL
      AND typeof(session.expires_at) = 'integer' AND session.expires_at BETWEEN 0 AND 9007199254740991
      AND session.expires_at > clock.seconds
      AND ? > clock.seconds AND clock.seconds - ? <= ? AND ? - clock.seconds <= ?
      AND ${oauthSpaceGrantFence('session')}
      AND EXISTS (SELECT 1 FROM account_state state WHERE state.did = session.did
        AND typeof(state.active) = 'integer' AND state.active = 1
        AND state.status IS NULL AND state.suspended_until IS NULL)
  )`;
  const authValues = [nonce, principal.sessionId, principal.accessJti, principal.did, principal.clientId,
    principal.jkt, principal.scope, principal.expiresAt, principal.proofIssuedAt, DPOP_PROOF_MAX_AGE_SEC,
    principal.proofIssuedAt, DPOP_PROOF_FUTURE_SKEW_SEC, ...oauthSpaceGrantFenceValues(principal.grant)];
  const read = db.prepare(`${authorization}
    SELECT ${SPACE_RECORD_COLUMNS}, 0 AS sentinel, NULL AS session_expires_at ${SPACE_RECORD_TABLES}
    WHERE record.space_ref = ? AND record.repo_did = ? AND record.collection = ? AND record.rkey = ?
      AND space.authority_did = ? AND space.space_type = ? AND space.skey = ?
      AND EXISTS (SELECT 1 FROM authorized)
    UNION ALL SELECT NULL, NULL, NULL, NULL, 0, 1, session_expires_at FROM authorized`)
    .bind(...authValues, MAX_RECORD_SIZE, MAX_RECORD_SIZE,
      ref.ref, repo, collection, rkey, ref.authorityDid, ref.spaceType, ref.skey);
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
          JOIN space_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
            AND e.repo_did = h.repo_did AND e.state = 'active'
          WHERE s.space_ref = ? AND s.authority_did = ? AND s.space_type = ? AND s.skey = ?
            AND s.deleted_at IS NULL) AS space_active FROM clock`)
      .bind(...authValues, repo, ref.ref, ref.authorityDid, ref.spaceType, ref.skey),
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
  const record = records.length && final.space_active === 1 ? decodeSpaceRecord(records[0], collection) : null;
  const after = Math.floor(Date.now() / 1000);
  if (request.signal.aborted || !windowIsLiveAt(principal, after) || sessionExpiresAt <= after) {
    return { tag: 'unauthorized' };
  }
  return record ? { tag: 'found', record } : { tag: 'notFound' };
}

function clockAssertionPassed(rows: unknown): boolean {
  return Array.isArray(rows) && rows.length === 1 && rows[0]?.valid === 1;
}

function matchesRequest(request: Request, space: string, repo: string, collection: string, rkey: string): boolean {
  if (request.signal.aborted || request.method !== 'GET') return false;
  const url = new URL(request.url);
  return url.pathname === '/xrpc/com.atproto.space.getRecord' &&
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
