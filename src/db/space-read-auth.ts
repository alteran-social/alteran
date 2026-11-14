import type { Env } from '../env';
import { DPOP_PROOF_FUTURE_SKEW_SEC, DPOP_PROOF_MAX_AGE_SEC } from '../lib/oauth/dpop-window';
import { consumeVerifiedSpacePrincipal, type VerifiedSpacePrincipal } from '../lib/oauth/space-principal';
import { allowsSpacePermission } from '../lib/spaces/oauth-scopes';
import { restoreExplicitSpaceConsent } from '../lib/spaces/explicit-read-consent';
import { oauthSpaceGrantFence, oauthSpaceGrantFenceValues } from './oauth-space-grant';
import { assertLocalSpaceRepo, parseSpaceRef } from './space-ref';

type CompleteRead = (request: Request, database: D1Database) => Promise<boolean>;
declare const readBrand: unique symbol;
export type SpaceReadHandle = { readonly [readBrand]: true };
type ReadState = {
  env: Env; database: D1Database; request: Request; principal: VerifiedSpacePrincipal;
  phase: 'new' | 'checking' | 'allowed'; ref?: ReturnType<typeof parseSpaceRef>; repo?: string;
};
const handles = new WeakMap<SpaceReadHandle, ReadState>();

/** Consume the resource verifier's request-bound principal before reading. */
export function consumeSpaceRead(
  env: Env, principal: VerifiedSpacePrincipal, request: Request, database: D1Database,
): SpaceReadHandle | null {
  if (!consumeVerifiedSpacePrincipal(principal, request, database) || env.ALTERAN_DB !== database) return null;
  const handle = Object.freeze({}) as SpaceReadHandle;
  handles.set(handle, { env, database, request, principal, phase: 'new' });
  return handle;
}

/** Bind a consumed request to the exact authorized Space and local repository. */
export async function authorizeSpaceRead(handle: SpaceReadHandle, operation: 'getRecord' | 'listRecords',
  space: string, repo: string): Promise<boolean> {
  const state = handles.get(handle);
  if (!state || state.phase !== 'new') return false;
  state.phase = 'checking';
  const { env, database, request, principal } = state;
  const url = new URL(request.url);
  if (request.method !== 'GET' || request.signal.aborted || env.ALTERAN_DB !== database ||
    url.pathname !== `/xrpc/com.atproto.space.${operation}` ||
    url.searchParams.getAll('space').length !== 1 || url.searchParams.get('space') !== space ||
    url.searchParams.getAll('repo').length !== 1 || url.searchParams.get('repo') !== repo ||
    repo !== principal.did || !windowIsLive(principal)) return false;
  const ref = parseSpaceRef(space);
  const restored = await restoreExplicitSpaceConsent(principal.grant.snapshot, principal.grant.digest, {
    subject: principal.did, accountIncarnation: principal.grant.accountIncarnation,
    clientId: principal.clientId, dpopJkt: principal.jkt,
    clientAuthMethod: principal.grant.clientAuthMethod, clientAuthKeyId: principal.grant.clientAuthKeyId,
    clientAuthKeyBinding: principal.grant.clientAuthKeyBinding,
  }, principal.scope);
  if (!restored || !restored.grants.some((grant) => allowsSpacePermission(grant.permission, {
    spaceType: ref.spaceType, authority: ref.authorityDid, skey: ref.skey,
  }, { action: 'read_self' })) || !windowIsLive(principal)) return false;
  await assertLocalSpaceRepo(env, repo);
  if (request.signal.aborted || env.ALTERAN_DB !== database || !windowIsLive(principal)) return false;
  state.ref = Object.freeze(ref);
  state.repo = repo;
  state.phase = 'allowed';
  return true;
}

export function authorizationSql(clockFence: 'nonce' | 'seconds'): string {
  return `WITH clock AS MATERIALIZED (
    SELECT seconds FROM oauth_replay_clock
    WHERE id = 1 AND ${clockFence === 'nonce' ? 'nonce = ?' : 'seconds >= ?'}
      AND typeof(seconds) = 'integer' AND seconds BETWEEN 0 AND 9007199254740991
  ), authorized AS MATERIALIZED (
    SELECT session.expires_at AS session_expires_at FROM oauth_session session JOIN clock
    WHERE ${authorizationPredicate('clock.seconds')}
  )`;
}

export function authorizationValues(principal: VerifiedSpacePrincipal, clockFence: string | number) {
  return [clockFence, ...sessionValues(principal)];
}

export function sessionValues(principal: VerifiedSpacePrincipal) {
  return [principal.sessionId, principal.accessJti, principal.did, principal.clientId,
    principal.jkt, principal.scope, principal.expiresAt, principal.proofIssuedAt, DPOP_PROOF_MAX_AGE_SEC,
    principal.proofIssuedAt, DPOP_PROOF_FUTURE_SKEW_SEC, ...oauthSpaceGrantFenceValues(principal.grant)];
}

export function authorizationPredicate(clock: 'clock.seconds' | 'oauth_replay_clock.seconds'): string {
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
export function completion(handle: SpaceReadHandle, epoch: string | null): CompleteRead {
  const state = handles.get(handle);
  handles.delete(handle);
  if (!state || state.phase !== 'allowed' || !state.ref || !state.repo) return async () => false;
  const { env, database, request, principal, ref, repo } = state;
  let consumed = false;
  return async (suppliedRequest, suppliedDatabase) => {
    if (consumed) return false;
    consumed = true;
    if (!epoch || request !== suppliedRequest || database !== suppliedDatabase || env.ALTERAN_DB !== database || request.signal.aborted ||
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
      !Number.isSafeInteger(sample.seconds) || sample.seconds < now || env.ALTERAN_DB !== database || request.signal.aborted ||
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
      env.ALTERAN_DB === database && !request.signal.aborted && windowIsLiveAt(principal, after);
  };
}

export function windowIsLive(principal: VerifiedSpacePrincipal): boolean {
  return windowIsLiveAt(principal, Math.floor(Date.now() / 1000));
}

export function windowIsLiveAt(principal: VerifiedSpacePrincipal, now: number): boolean {
  return Number.isSafeInteger(now) && now >= 0 && Number.isSafeInteger(principal.expiresAt) &&
    principal.expiresAt > now && Number.isFinite(principal.proofIssuedAt) &&
    now - principal.proofIssuedAt <= DPOP_PROOF_MAX_AGE_SEC &&
    principal.proofIssuedAt - now <= DPOP_PROOF_FUTURE_SKEW_SEC;
}
