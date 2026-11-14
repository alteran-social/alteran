import type { Env } from '../env';
import { DPOP_PROOF_FUTURE_SKEW_SEC, DPOP_PROOF_MAX_AGE_SEC } from '../lib/oauth/dpop-window';
import { consumeVerifiedSpacePrincipal, type VerifiedSpacePrincipal } from '../lib/oauth/space-principal';
import { allowsSpacePermission } from '../lib/spaces/oauth-scopes';
import { restoreExplicitSpaceConsent } from '../lib/spaces/explicit-read-consent';
import { parseGetSpaceRequest } from '../lib/spaces/get-space-request';
import { ASSERT_CLOCK, REFRESH_CLOCK } from './oauth-replay';
import { assertLocalSpaceRepo, parseSpaceRef } from './space-ref';
import { validLifecycleNonce } from './space-lifecycle-types';
import { authorizationPredicate, authorizationSql, authorizationValues, sessionValues,
  windowIsLive, windowIsLiveAt } from './space-read-auth';

type CompletePolicy = (request: Request, database: D1Database) => Promise<boolean>;
type Identity = { readonly nonce: string; readonly createdAt: number };
type Context = { readonly env: Env; readonly database: D1Database; readonly request: Request;
  readonly principal: VerifiedSpacePrincipal; readonly ref: ReturnType<typeof parseSpaceRef> };
type PolicyRow = { sentinel: unknown; session_expires_at: unknown; valid: unknown;
  creation_nonce: unknown; created_at: unknown };

export type AuthorizedSpacePolicyResult =
  | { readonly tag: 'found'; readonly space: string; readonly complete: CompletePolicy }
  | { readonly tag: 'notFound'; readonly complete: CompletePolicy }
  | { readonly tag: 'unauthorized' };

// The candidate is independently bounded and keyed by the exact authority,
// incarnation and Space. Its fields are projected only after authorization.
const POLICY_CANDIDATE = `SELECT CASE
    WHEN typeof(p.creation_nonce) = 'text' AND length(CAST(p.creation_nonce AS BLOB)) = 36
      AND typeof(p.created_at) = 'integer' AND p.created_at BETWEEN 0 AND 9007199254740991
      AND typeof(s.created_at) = 'integer' AND s.created_at BETWEEN 0 AND 9007199254740991
      AND typeof(s.authority_did) = 'text' AND length(CAST(s.authority_did AS BLOB)) BETWEEN 1 AND 2048
      AND typeof(s.space_type) = 'text' AND length(CAST(s.space_type AS BLOB)) BETWEEN 1 AND 317
      AND typeof(s.skey) = 'text' AND length(CAST(s.skey AS BLOB)) BETWEEN 1 AND 512
      AND typeof(p.policy_type) = 'text' AND length(CAST(p.policy_type AS BLOB)) BETWEEN 1 AND 128
      AND typeof(p.notification_state) = 'text' AND length(CAST(p.notification_state AS BLOB)) BETWEEN 1 AND 16
    THEN CASE WHEN s.authority_did = ? AND s.space_type = ? AND s.skey = ?
      AND p.policy_type = 'com.atproto.personalspace.policy' AND p.notification_state = 'none'
      AND p.created_at = s.created_at THEN 1 ELSE 0 END ELSE 0 END AS valid,
    CASE WHEN typeof(p.creation_nonce) = 'text' AND length(CAST(p.creation_nonce AS BLOB)) = 36
      THEN p.creation_nonce END AS creation_nonce,
    CASE WHEN typeof(p.created_at) = 'integer' AND p.created_at BETWEEN 0 AND 9007199254740991
      THEN p.created_at END AS created_at
  FROM space s JOIN space_personal_policy p ON p.space_ref = s.space_ref
  WHERE s.space_ref = ? AND s.deleted_at IS NULL AND p.authority_did = ? AND p.authority_incarnation = ?`;

/** Read only the authenticated owner's current personal policy, independently of repo epochs. */
export async function readAuthorizedSpacePolicy(
  env: Env, principal: VerifiedSpacePrincipal, request: Request,
): Promise<AuthorizedSpacePolicyResult> {
  try {
    const database = env.ALTERAN_DB;
    if (!consumeVerifiedSpacePrincipal(principal, request, database) || env.ALTERAN_DB !== database) return denied();
    const space = parseGetSpaceRequest(request);
    if (!space || !windowIsLive(principal)) return denied();
    const ref = Object.freeze(parseSpaceRef(space));
    if (ref.authorityDid !== principal.did) return denied();
    const restored = await restoreExplicitSpaceConsent(principal.grant.snapshot, principal.grant.digest, {
      subject: principal.did, accountIncarnation: principal.grant.accountIncarnation,
      clientId: principal.clientId, dpopJkt: principal.jkt,
      clientAuthMethod: principal.grant.clientAuthMethod, clientAuthKeyId: principal.grant.clientAuthKeyId,
      clientAuthKeyBinding: principal.grant.clientAuthKeyBinding,
    }, principal.scope);
    if (!restored || !restored.grants.some((grant) => allowsSpacePermission(grant.permission, {
      spaceType: ref.spaceType, authority: ref.authorityDid, skey: ref.skey,
    }, { action: 'read_self' })) || !windowIsLive(principal)) return denied();
    await assertLocalSpaceRepo(env, principal.did);
    if (request.signal.aborted || env.ALTERAN_DB !== database || !windowIsLive(principal)) return denied();
    const context = { env, database, request, principal, ref };
    return await selectPolicy(context);
  } catch {
    return denied();
  }
}

async function selectPolicy(context: Context): Promise<AuthorizedSpacePolicyResult> {
  const { env, database, request, principal, ref } = context;
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(now) || now < 0) return denied();
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const authorization = authorizationSql('nonce');
  const authValues = authorizationValues(principal, nonce);
  const candidate = `candidate AS MATERIALIZED (
    SELECT policy.* FROM authorized CROSS JOIN (${POLICY_CANDIDATE}) policy
  )`;
  const values = policyValues(context);
  const result = await database.batch([
    database.prepare(`UPDATE oauth_replay_clock SET seconds = MAX(seconds, unixepoch(), ?), nonce = ?
      WHERE id = 1 AND typeof(seconds) = 'integer' AND seconds BETWEEN 0 AND 9007199254740991`).bind(now, nonce),
    database.prepare(ASSERT_CLOCK).bind(nonce),
    database.prepare(`${authorization}, ${candidate}
      SELECT 0 AS sentinel, NULL AS session_expires_at, valid, creation_nonce, created_at FROM candidate
      UNION ALL SELECT 1, session_expires_at, NULL, NULL, NULL FROM authorized`).bind(...authValues, ...values),
    database.prepare(REFRESH_CLOCK).bind(nonce),
    database.prepare(ASSERT_CLOCK).bind(nonce),
    database.prepare(`${authorization}, ${candidate}
      SELECT clock.seconds, (SELECT session_expires_at FROM authorized) AS session_expires_at,
        (SELECT valid FROM candidate) AS valid, (SELECT creation_nonce FROM candidate) AS creation_nonce,
        (SELECT created_at FROM candidate) AS created_at FROM clock`).bind(...authValues, ...values),
  ]);
  if (!Array.isArray(result) || result.length !== 6 || result.some((row) => row?.success !== true) ||
    !clockPassed(result[1]?.results) || !clockPassed(result[4]?.results) ||
    env.ALTERAN_DB !== database || request.signal.aborted || !windowIsLive(principal)) return denied();
  const finalRows = result[5]?.results;
  const selected = result[2]?.results;
  if (!Array.isArray(finalRows) || finalRows.length !== 1 || !finalRows[0] || typeof finalRows[0] !== 'object' ||
    !Array.isArray(selected) || selected.length > 2 ||
    selected.some((row) => !row || typeof row !== 'object' || Array.isArray(row))) return denied();
  const final = finalRows[0] as Record<string, unknown>;
  const clock = final.seconds, expiry = final.session_expires_at;
  if (typeof clock !== 'number' || !Number.isSafeInteger(clock) || clock < now ||
    principal.expiresAt <= clock || clock - principal.proofIssuedAt > DPOP_PROOF_MAX_AGE_SEC ||
    principal.proofIssuedAt - clock > DPOP_PROOF_FUTURE_SKEW_SEC ||
    typeof expiry !== 'number' || !Number.isSafeInteger(expiry) || expiry <= clock) return denied();
  const rows = selected as PolicyRow[];
  const sentinels = rows.filter((row) => row.sentinel === 1);
  const policies = rows.filter((row) => row.sentinel === 0);
  if (sentinels.length !== 1 || policies.length > 1 || sentinels.length + policies.length !== rows.length ||
    sentinels[0].session_expires_at !== expiry || sentinels[0].valid !== null ||
    sentinels[0].creation_nonce !== null || sentinels[0].created_at !== null) return denied();
  let identity: Identity | null = null;
  if (policies.length === 0) {
    if (final.valid !== null || final.creation_nonce !== null || final.created_at !== null) return denied();
  } else {
    const row = policies[0];
    if (row.session_expires_at !== null || row.valid !== 1 || !validLifecycleNonce(row.creation_nonce) ||
      typeof row.created_at !== 'number' || !Number.isSafeInteger(row.created_at) || row.created_at < 0 ||
      final.valid !== 1 || final.creation_nonce !== row.creation_nonce || final.created_at !== row.created_at) return denied();
    identity = Object.freeze({ nonce: row.creation_nonce, createdAt: row.created_at });
  }
  const after = Math.floor(Date.now() / 1000);
  if (request.signal.aborted || env.ALTERAN_DB !== database || !windowIsLiveAt(principal, after) || expiry <= after) return denied();
  const complete = policyCompletion(context, identity);
  return identity ? Object.freeze({ tag: 'found', space: ref.ref, complete }) : Object.freeze({ tag: 'notFound', complete });
}

function policyValues({ principal, ref }: Context) {
  return [ref.authorityDid, ref.spaceType, ref.skey, ref.ref, principal.did, principal.grant.accountIncarnation];
}

function policyCondition(identity: Identity | null): string {
  return identity
    ? `EXISTS (SELECT 1 FROM (${POLICY_CANDIDATE}) candidate WHERE candidate.valid = 1
        AND candidate.creation_nonce = ? AND candidate.created_at = ?)`
    : `NOT EXISTS (SELECT 1 FROM (${POLICY_CANDIDATE}) candidate)`;
}

function policyCompletion(context: Context, identity: Identity | null): CompletePolicy {
  const { env, database, request, principal } = context;
  let consumed = false;
  return async (suppliedRequest, suppliedDatabase) => {
    if (consumed) return false;
    consumed = true;
    try {
      if (request !== suppliedRequest || database !== suppliedDatabase || env.ALTERAN_DB !== database ||
        request.signal.aborted || !windowIsLive(principal)) return false;
      const now = Math.floor(Date.now() / 1000);
      if (!Number.isSafeInteger(now) || now < 0) return false;
      const nonce = crypto.randomUUID().replaceAll('-', '');
      const condition = policyCondition(identity);
      const values = [...policyValues(context), ...(identity ? [identity.nonce, identity.createdAt] : [])];
      const sample = await database.prepare(`UPDATE oauth_replay_clock SET seconds = MAX(seconds, unixepoch(), ?), nonce = ?
        WHERE id = 1 AND typeof(seconds) = 'integer' AND seconds BETWEEN 0 AND 9007199254740991
        RETURNING seconds, nonce, EXISTS (SELECT 1 FROM oauth_session session
          WHERE ${authorizationPredicate('oauth_replay_clock.seconds')} AND ${condition}) AS authorized`)
        .bind(now, nonce, ...sessionValues(principal), ...values)
        .first<{ seconds: unknown; nonce: unknown; authorized: unknown }>();
      if (!sample || sample.authorized !== 1 || sample.nonce !== nonce || typeof sample.seconds !== 'number' ||
        !Number.isSafeInteger(sample.seconds) || sample.seconds < now || env.ALTERAN_DB !== database ||
        request.signal.aborted || !windowIsLive(principal)) return false;
      const row = await database.prepare(`${authorizationSql('seconds')}
        SELECT clock.seconds, authorized.session_expires_at FROM clock JOIN authorized WHERE ${condition}`)
        .bind(...authorizationValues(principal, sample.seconds), ...values)
        .first<{ seconds: unknown; session_expires_at: unknown }>();
      const after = Math.floor(Date.now() / 1000);
      return !!row && typeof row.seconds === 'number' && Number.isSafeInteger(row.seconds) && row.seconds >= sample.seconds &&
        typeof row.session_expires_at === 'number' && Number.isSafeInteger(row.session_expires_at) &&
        row.session_expires_at > row.seconds && row.session_expires_at > after &&
        env.ALTERAN_DB === database && !request.signal.aborted && windowIsLiveAt(principal, after);
    } catch {
      return false;
    }
  };
}

function clockPassed(rows: unknown): boolean {
  return Array.isArray(rows) && rows.length === 1 && rows[0]?.valid === 1;
}
function denied(): AuthorizedSpacePolicyResult {
  return { tag: 'unauthorized' };
}
