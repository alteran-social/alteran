import type { Env } from '../env';
import type { DpopVerification } from '../lib/oauth/dpop';
import { DPOP_PROOF_FUTURE_SKEW_SEC, DPOP_PROOF_MAX_AGE_SEC, dpopProofReplayExpiresAt } from '../lib/oauth/dpop-window';
import {
  ASSERT_CLOCK,
  INSERT_ASSERTION,
  INSERT_DPOP,
  OAUTH_REPLAY_ADMISSION_CLEANUP_SQL,
  OAUTH_REPLAY_AMORTIZED_SWEEP_SQL,
  REFRESH_CLOCK,
  UPDATE_CLOCK,
} from './oauth-replay';

export type AssertionReplay = { readonly key: string; readonly issuedAt: number; readonly expiresAt: number };
type ReplayClaim = {
  readonly key: string;
  readonly value: string;
  readonly issuedAt: number;
  readonly expiresAt: number | null;
};
export type ReplayTransaction = {
  readonly nonce: string;
  readonly proofKey: string;
  readonly proofIssuedAt: number;
  readonly assertion?: AssertionReplay;
  readonly begin: readonly D1PreparedStatement[];
  readonly finish: readonly D1PreparedStatement[];
};

/** Prepare proof claims that commit or roll back with the enclosing D1 batch. */
export function prepareReplayTransaction(
  env: Env,
  proof: DpopVerification,
  assertion?: AssertionReplay,
): ReplayTransaction | null {
  const jti = proof.payload.jti;
  const issuedAt = proof.payload.iat;
  if (typeof jti !== 'string' || jti.length < 8 || typeof issuedAt !== 'number' || !Number.isFinite(issuedAt)) return null;
  const nonce = crypto.randomUUID().replace(/-/g, '');
  const key = `oauth:dpop:jti:authz:${jti}`;
  if (!validKey(key)) return null;
  const claims: ReplayClaim[] = [{
    key, issuedAt, expiresAt: null,
    value: JSON.stringify({ iat: issuedAt, exp: dpopProofReplayExpiresAt(issuedAt), attempt: nonce }),
  }];
  if (assertion) {
    if (!assertion.key.startsWith('oauth:client-assertion:jti:') || !validKey(assertion.key) ||
      !Number.isFinite(assertion.issuedAt) || !Number.isFinite(assertion.expiresAt)) return null;
    claims.push({
      ...assertion,
      value: JSON.stringify({ exp: Math.ceil(assertion.expiresAt), attempt: nonce }),
    });
  }
  const database = env.ALTERAN_DB;
  const begin: D1PreparedStatement[] = [
    database.prepare(UPDATE_CLOCK).bind(nonce), database.prepare(ASSERT_CLOCK).bind(nonce),
  ];
  for (const claim of claims) {
    const issuedAt = claim.issuedAt;
    const expiresAt = claim.expiresAt;
    begin.push(
      database.prepare(OAUTH_REPLAY_ADMISSION_CLEANUP_SQL).bind(nonce, claim.key, DPOP_PROOF_MAX_AGE_SEC),
      expiresAt === null
        ? database.prepare(INSERT_DPOP).bind(claim.key, claim.value, nonce, issuedAt, DPOP_PROOF_MAX_AGE_SEC, issuedAt, DPOP_PROOF_FUTURE_SKEW_SEC)
        : database.prepare(INSERT_ASSERTION).bind(claim.key, claim.value, nonce, issuedAt, DPOP_PROOF_MAX_AGE_SEC, issuedAt, DPOP_PROOF_FUTURE_SKEW_SEC, expiresAt, expiresAt, DPOP_PROOF_MAX_AGE_SEC),
      database.prepare(`SELECT CASE WHEN changes() = 1 AND EXISTS
        (SELECT 1 FROM secret WHERE key = ? AND value = ?) THEN 1 ELSE json('{') END AS valid`).bind(claim.key, claim.value),
      database.prepare(OAUTH_REPLAY_AMORTIZED_SWEEP_SQL).bind(
        claim.key, claim.value, issuedAt, DPOP_PROOF_MAX_AGE_SEC, issuedAt, DPOP_PROOF_FUTURE_SKEW_SEC,
        expiresAt, expiresAt, expiresAt, DPOP_PROOF_MAX_AGE_SEC, 0, '', '', '', '', '', '', 0, 0, 0, 0,
        issuedAt - DPOP_PROOF_FUTURE_SKEW_SEC, nonce,
      ),
    );
  }
  const predicates: string[] = [];
  const args: (string | number)[] = [nonce];
  for (const claim of claims) {
    predicates.push(`EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
      AND seconds - ? <= ? AND ? - seconds <= ?`);
    args.push(claim.key, claim.value, claim.issuedAt, DPOP_PROOF_MAX_AGE_SEC, claim.issuedAt, DPOP_PROOF_FUTURE_SKEW_SEC);
    if (claim.expiresAt !== null) {
      predicates.push('? > seconds AND ? - seconds <= ?');
      args.push(claim.expiresAt, claim.expiresAt, DPOP_PROOF_MAX_AGE_SEC);
    }
  }
  const finish = [
    database.prepare(REFRESH_CLOCK).bind(nonce), database.prepare(ASSERT_CLOCK).bind(nonce),
    database.prepare(`SELECT CASE WHEN EXISTS (SELECT 1 FROM oauth_replay_clock
      WHERE id = 1 AND nonce = ? AND ${predicates.join(' AND ')})
      THEN 1 ELSE json('{') END AS valid`).bind(...args),
  ];
  return { nonce, proofKey: key, proofIssuedAt: issuedAt, assertion: assertion ? { ...assertion } : undefined, begin, finish };
}

function validKey(key: string): boolean {
  return key.length <= 8192 && new TextEncoder().encode(key).byteLength <= 8192;
}

/** Classify a failed batch only; this query never authorizes or revokes. */
export async function replayProofBlocked(env: Env, key: string): Promise<boolean> {
  const row = await env.ALTERAN_DB.prepare(`SELECT EXISTS (
    SELECT 1 FROM secret, oauth_replay_clock clock WHERE key = ? AND clock.id = 1
      AND NOT CASE WHEN json_valid(value) THEN
        COALESCE(json_type(value, '$.exp') IN ('integer', 'real')
          AND CAST(json_extract(value, '$.exp') AS REAL) <= clock.seconds
          AND json_type(value, '$.iat') IN ('integer', 'real')
          AND CAST(json_extract(value, '$.iat') AS REAL) + ? < clock.seconds, 0)
      ELSE 0 END
  ) AS blocked`).bind(key, DPOP_PROOF_MAX_AGE_SEC).first<{ blocked: number }>();
  if (row?.blocked !== 0 && row?.blocked !== 1) throw new Error('Invalid OAuth replay lookup');
  return row.blocked === 1;
}

export async function replayProofExpired(env: Env, issuedAt: number): Promise<boolean> {
  const clock = await env.ALTERAN_DB.prepare('SELECT MAX(seconds, unixepoch()) AS seconds FROM oauth_replay_clock WHERE id = 1')
    .first<{ seconds: number }>();
  if (!clock || !Number.isSafeInteger(clock.seconds)) throw new Error('Invalid OAuth replay clock');
  return clock.seconds - issuedAt > DPOP_PROOF_MAX_AGE_SEC || issuedAt - clock.seconds > DPOP_PROOF_FUTURE_SKEW_SEC;
}
