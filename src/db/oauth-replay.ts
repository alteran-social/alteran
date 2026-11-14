import type { Env } from "../env";
import { oauthSpaceGrantFence, oauthSpaceGrantFenceValues, type OAuthSpaceGrant } from "./oauth-space-grant";
import {
  DPOP_PROOF_FUTURE_SKEW_SEC,
  DPOP_PROOF_MAX_AGE_SEC,
  dpopProofReplayExpiresAt,
} from "../lib/oauth/dpop-window";

export type OAuthReplayClaims =
  | { readonly tag: "dpop"; readonly issuedAt: number }
  | {
    readonly tag: "assertion";
    readonly issuedAt: number;
    readonly expiresAt: number;
  };

export type OAuthReplayResult = {
  readonly tag: "accepted" | "expired" | "replayed";
};
export type OAuthResourceBinding = {
  readonly sessionId: string;
  readonly accessJti: string;
  readonly did: string;
  readonly clientId: string;
  readonly jkt: string;
  readonly scope: string;
  readonly expiresAt: number;
  readonly spaceGrant?: OAuthSpaceGrant;
};
export type OAuthResourceReplayResult = OAuthReplayResult | {
  readonly tag: "invalidSession";
};
export const OAUTH_REPLAY_CLEANUP_LIMIT = 512;
const MAX_REPLAY_KEY_BYTES = 8192;
const MAX_RESOURCE_FIELD_BYTES = 131_072;
const VALID_SESSION_CLIENT_BINDING = `(session.client_auth_method = 'none' OR
  (session.client_auth_method = 'private_key_jwt' AND session.client_auth_key_binding = 'jwk-thumbprint-v1'
    AND typeof(session.client_auth_key_id) = 'text' AND length(CAST(session.client_auth_key_id AS BLOB)) = 43))`;

export const UPDATE_CLOCK = `UPDATE oauth_replay_clock
  SET seconds = MAX(seconds, unixepoch()), nonce = ? WHERE id = 1`;
export const REFRESH_CLOCK = `UPDATE oauth_replay_clock
  SET seconds = MAX(seconds, unixepoch()) WHERE id = 1 AND nonce = ?`;
export const ASSERT_CLOCK = `SELECT CASE WHEN changes() = 1 AND EXISTS (
  SELECT 1 FROM oauth_replay_clock WHERE id = 1 AND nonce = ? AND typeof(seconds) = 'integer'
) THEN 1 ELSE json('{') END AS valid`;
const ASSERT_CLOCK_AT_LEAST = `SELECT CASE WHEN changes() = 1 AND EXISTS (
  SELECT 1 FROM oauth_replay_clock WHERE id = 1 AND nonce = ?
    AND typeof(seconds) = 'integer' AND seconds >= ?
) THEN 1 ELSE json('{') END AS valid`;
export const OAUTH_REPLAY_ADMISSION_CLEANUP_SQL =
  `WITH clock AS (SELECT seconds FROM oauth_replay_clock WHERE id = 1 AND nonce = ?)
  DELETE FROM secret
  WHERE key = ?
    AND EXISTS (SELECT 1 FROM clock)
    AND CASE WHEN json_valid(value) THEN
      json_type(value, '$.exp') IN ('integer', 'real')
      AND CAST(json_extract(value, '$.exp') AS REAL) <= (SELECT seconds FROM clock)
      AND (key NOT GLOB 'oauth:dpop:jti:*' OR (
        json_type(value, '$.iat') IN ('integer', 'real')
        AND CAST(json_extract(value, '$.iat') AS REAL) + ? < (SELECT seconds FROM clock)
      ))
    ELSE 0 END`;
export const OAUTH_REPLAY_SWEEP_SQL =
  `WITH clock AS (SELECT seconds FROM oauth_replay_clock WHERE id = 1 AND nonce = ?),
  expired AS (
    SELECT key FROM (
      SELECT key, (CASE WHEN json_valid(value) THEN CASE
        WHEN key GLOB 'oauth:dpop:jti:*'
          AND json_type(value, '$.exp') IN ('integer', 'real')
          AND json_type(value, '$.iat') IN ('integer', 'real')
          THEN MAX(CAST(json_extract(value, '$.exp') AS REAL), CAST(json_extract(value, '$.iat') AS REAL) + 300)
        WHEN key GLOB 'oauth:client-assertion:jti:*'
          AND json_type(value, '$.exp') IN ('integer', 'real')
          THEN CAST(json_extract(value, '$.exp') AS REAL)
        ELSE NULL END ELSE NULL END) AS horizon
      FROM secret WHERE key GLOB 'oauth:dpop:jti:*' OR key GLOB 'oauth:client-assertion:jti:*'
    ) WHERE horizon IS NOT NULL AND horizon < ? AND horizon < (SELECT seconds FROM clock)
    ORDER BY horizon, key LIMIT ?
  ) DELETE FROM secret WHERE key IN (SELECT key FROM expired) AND EXISTS (SELECT 1 FROM clock)`;
export const OAUTH_REPLAY_AMORTIZED_SWEEP_SQL = `WITH bound AS (
  SELECT CASE WHEN changes() = 1 AND EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
    AND seconds - ? <= ? AND ? - seconds <= ?
    AND (? IS NULL OR (? > seconds AND ? - seconds <= ?))
    AND (? = 0 OR EXISTS (SELECT 1 FROM oauth_session session
      WHERE session.id = ? AND session.access_jti = ? AND session.did = ? AND session.client_id = ?
        AND session.dpop_jkt = ? AND session.scope = ? AND session.revoked_at IS NULL
        AND ${VALID_SESSION_CLIENT_BINDING}
        AND typeof(session.expires_at) = 'integer' AND session.expires_at > seconds
        AND session.expires_at > ? AND ? > seconds AND ? > ? AND ${oauthSpaceGrantFence('session')}))
    THEN MIN(?, seconds) ELSE NULL END AS before
  FROM oauth_replay_clock WHERE id = 1 AND nonce = ?
), expired AS (
  SELECT key FROM (
    SELECT key, (CASE WHEN json_valid(value) THEN CASE
      WHEN key GLOB 'oauth:dpop:jti:*'
        AND json_type(value, '$.exp') IN ('integer', 'real')
        AND json_type(value, '$.iat') IN ('integer', 'real')
        THEN MAX(CAST(json_extract(value, '$.exp') AS REAL), CAST(json_extract(value, '$.iat') AS REAL) + 300)
      WHEN key GLOB 'oauth:client-assertion:jti:*'
        AND json_type(value, '$.exp') IN ('integer', 'real')
        THEN CAST(json_extract(value, '$.exp') AS REAL)
      ELSE NULL END ELSE NULL END) AS horizon
    FROM secret WHERE key GLOB 'oauth:dpop:jti:*' OR key GLOB 'oauth:client-assertion:jti:*'
  ) WHERE horizon IS NOT NULL AND horizon < (SELECT before FROM bound)
  ORDER BY horizon, key LIMIT 1
) DELETE FROM secret WHERE key IN (SELECT key FROM expired)`;
export const INSERT_DPOP = `INSERT OR IGNORE INTO secret (key, value, updated_at)
  SELECT ?, ?, seconds * 1000 FROM oauth_replay_clock
  WHERE id = 1 AND nonce = ? AND seconds - ? <= ? AND ? - seconds <= ?`;
const INSERT_RESOURCE_DPOP =
  `INSERT OR IGNORE INTO secret (key, value, updated_at)
  SELECT ?, ?, clock.seconds * 1000 FROM oauth_replay_clock clock
  WHERE clock.id = 1 AND clock.nonce = ? AND clock.seconds - ? <= ? AND ? - clock.seconds <= ?
    AND EXISTS (SELECT 1 FROM oauth_session session WHERE session.id = ? AND session.access_jti = ?
      AND session.did = ? AND session.client_id = ? AND session.dpop_jkt = ? AND session.scope = ?
      AND session.revoked_at IS NULL AND ${VALID_SESSION_CLIENT_BINDING} AND typeof(session.expires_at) = 'integer'
      AND session.expires_at > clock.seconds AND session.expires_at > ? AND ? > clock.seconds AND ? > ?
      AND ${oauthSpaceGrantFence('session')})`;
export const INSERT_ASSERTION = `INSERT OR IGNORE INTO secret (key, value, updated_at)
  SELECT ?, ?, seconds * 1000 FROM oauth_replay_clock
  WHERE id = 1 AND nonce = ? AND seconds - ? <= ? AND ? - seconds <= ?
    AND ? > seconds AND ? - seconds <= ?`;
const INSERT_OUTCOME = `SELECT changes() AS inserted,
  (SELECT seconds FROM oauth_replay_clock WHERE id = 1 AND nonce = ?) AS seconds,
  EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?) AS marker`;
const FINAL_OUTCOME = `SELECT seconds,
  EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?) AS marker
  FROM oauth_replay_clock WHERE id = 1 AND nonce = ?`;
const FINAL_RESOURCE_OUTCOME = `SELECT clock.seconds,
  EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?) AS marker,
  EXISTS (SELECT 1 FROM oauth_session session WHERE session.id = ? AND session.access_jti = ?
    AND session.did = ? AND session.client_id = ? AND session.dpop_jkt = ? AND session.scope = ?
    AND session.revoked_at IS NULL AND ${VALID_SESSION_CLIENT_BINDING} AND typeof(session.expires_at) = 'integer'
    AND session.expires_at > clock.seconds AND session.expires_at > ? AND ? > clock.seconds AND ? > ?
    AND ${oauthSpaceGrantFence('session')}) AS session_valid,
  (SELECT CASE WHEN typeof(session.expires_at) = 'integer' THEN session.expires_at END
    FROM oauth_session session WHERE session.id = ?) AS session_expires_at
  FROM oauth_replay_clock clock WHERE clock.id = 1 AND clock.nonce = ?`;

/** Consume one verified proof against a primary-D1, nondecreasing clock. */
export async function consumeOAuthReplay(
  env: Env,
  key: string,
  claims: OAuthReplayClaims,
): Promise<OAuthReplayResult> {
  if (typeof key !== "string" || key.startsWith("oauth:dpop:jti:resource:")) {
    throw new Error("Invalid OAuth replay key");
  }
  const result = await consumeOAuthReplayInternal(env, key, claims);
  if (result.tag === "invalidSession") {
    throw new Error("Unexpected resource replay result");
  }
  return result;
}

/** Resource admission linearizes at the D1 commit that claims its proof. */
export async function consumeOAuthResourceReplay(
  env: Env,
  jti: string,
  issuedAt: number,
  binding: OAuthResourceBinding,
): Promise<OAuthResourceReplayResult> {
  if (
    typeof jti !== "string" || jti.length < 8 ||
    jti.length > MAX_REPLAY_KEY_BYTES || !validResourceBinding(binding)
  ) {
    return { tag: "invalidSession" };
  }
  const key = `oauth:dpop:jti:resource:${jti}`;
  if (!validReplayKey(key)) return { tag: "invalidSession" };
  return consumeOAuthReplayInternal(env, key, {
    tag: "dpop",
    issuedAt,
  }, binding);
}

async function consumeOAuthReplayInternal(
  env: Env,
  key: string,
  claims: OAuthReplayClaims,
  binding?: OAuthResourceBinding,
): Promise<OAuthResourceReplayResult> {
  const prefix = claims.tag === "dpop"
    ? "oauth:dpop:jti:"
    : "oauth:client-assertion:jti:";
  if (
    !validReplayKey(key) || !key.startsWith(prefix)
  ) throw new Error("Invalid OAuth replay key");
  if (!validClaims(claims)) return { tag: "expired" };
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const value = claims.tag === "dpop"
    ? JSON.stringify({
      iat: claims.issuedAt,
      exp: dpopProofReplayExpiresAt(claims.issuedAt),
      attempt: nonce,
    })
    : JSON.stringify({ exp: Math.ceil(claims.expiresAt), attempt: nonce });
  const database = env.ALTERAN_DB;
  const observedAt = binding ? Math.floor(Date.now() / 1000) : 0;
  if (binding && (!Number.isSafeInteger(observedAt) || observedAt < 0)) return { tag: "invalidSession" };
  const bindingArguments = binding && [
    binding.sessionId,
    binding.accessJti,
    binding.did,
    binding.clientId,
    binding.jkt,
    binding.scope,
    observedAt,
    binding.expiresAt,
    binding.expiresAt,
    observedAt,
    ...oauthSpaceGrantFenceValues(binding.spaceGrant),
  ] as const;
  const sweepBinding = bindingArguments ?? ["", "", "", "", "", "", 0, 0, 0, 0, 0, "", "", null, null, null, ""] as const;
  const assertionExpiry = claims.tag === "assertion" ? claims.expiresAt : null;
  const insertion = claims.tag === "dpop" && bindingArguments
    ? database.prepare(INSERT_RESOURCE_DPOP).bind(
      key,
      value,
      nonce,
      claims.issuedAt,
      DPOP_PROOF_MAX_AGE_SEC,
      claims.issuedAt,
      DPOP_PROOF_FUTURE_SKEW_SEC,
      ...bindingArguments,
    )
    : claims.tag === "dpop"
    ? database.prepare(INSERT_DPOP).bind(
      key,
      value,
      nonce,
      claims.issuedAt,
      DPOP_PROOF_MAX_AGE_SEC,
      claims.issuedAt,
      DPOP_PROOF_FUTURE_SKEW_SEC,
    )
    : database.prepare(INSERT_ASSERTION).bind(
      key,
      value,
      nonce,
      claims.issuedAt,
      DPOP_PROOF_MAX_AGE_SEC,
      claims.issuedAt,
      DPOP_PROOF_FUTURE_SKEW_SEC,
      claims.expiresAt,
      claims.expiresAt,
      DPOP_PROOF_MAX_AGE_SEC,
    );
  const results = await database.batch([
    database.prepare(UPDATE_CLOCK).bind(nonce),
    database.prepare(ASSERT_CLOCK).bind(nonce),
    database.prepare(OAUTH_REPLAY_ADMISSION_CLEANUP_SQL).bind(
      nonce,
      key,
      DPOP_PROOF_MAX_AGE_SEC,
    ),
    insertion,
    database.prepare(INSERT_OUTCOME).bind(nonce, key, value),
    database.prepare(OAUTH_REPLAY_AMORTIZED_SWEEP_SQL).bind(
      key,
      value,
      claims.issuedAt,
      DPOP_PROOF_MAX_AGE_SEC,
      claims.issuedAt,
      DPOP_PROOF_FUTURE_SKEW_SEC,
      assertionExpiry,
      assertionExpiry,
      assertionExpiry,
      DPOP_PROOF_MAX_AGE_SEC,
      bindingArguments ? 1 : 0,
      ...sweepBinding,
      claims.issuedAt - DPOP_PROOF_FUTURE_SKEW_SEC,
      nonce,
    ),
    database.prepare(REFRESH_CLOCK).bind(nonce),
    database.prepare(ASSERT_CLOCK).bind(nonce),
    bindingArguments
      ? database.prepare(FINAL_RESOURCE_OUTCOME).bind(
        key,
        value,
        ...bindingArguments,
        binding?.sessionId,
        nonce,
      )
      : database.prepare(FINAL_OUTCOME).bind(key, value, nonce),
  ]);
  const inserted = results[4]?.results?.[0];
  const final = results[8]?.results?.[0];
  if (
    !inserted || !final || typeof inserted.inserted !== "number" ||
    typeof inserted.seconds !== "number" ||
    typeof inserted.marker !== "number" ||
    typeof final.seconds !== "number" || typeof final.marker !== "number" ||
    !Number.isSafeInteger(inserted.seconds) ||
    !Number.isSafeInteger(final.seconds) ||
    final.seconds < inserted.seconds
  ) throw new Error("Invalid OAuth replay transaction result");
  if (!validAt(claims, final.seconds)) return { tag: "expired" };
  if (binding && bindingArguments) {
    const completedAt = Math.floor(Date.now() / 1000);
    if (final.session_valid !== 1 || !Number.isSafeInteger(completedAt) || completedAt < 0 ||
      binding.expiresAt <= completedAt || typeof final.session_expires_at !== "number" ||
      !Number.isSafeInteger(final.session_expires_at) || final.session_expires_at <= completedAt) {
      return { tag: "invalidSession" };
    }
  }
  if (inserted.inserted === 0) return { tag: "replayed" };
  if (inserted.inserted !== 1 || inserted.marker !== 1 || final.marker !== 1) {
    throw new Error("OAuth replay marker was not retained");
  }
  return { tag: "accepted" };
}

export function validResourceBinding(binding: OAuthResourceBinding): boolean {
  if (
    !binding || typeof binding !== "object" ||
    typeof binding.expiresAt !== "number" || !Number.isFinite(binding.expiresAt)
  ) return false;
  const fields = [
    binding.sessionId,
    binding.accessJti,
    binding.did,
    binding.clientId,
    binding.jkt,
    binding.scope,
  ];
  const grant = binding.spaceGrant;
  if (grant) {
    if (typeof grant.snapshot !== "string" || grant.snapshot.length > 65_536 ||
      typeof grant.digest !== "string" || !/^[0-9a-f]{64}$/.test(grant.digest) ||
      typeof grant.accountIncarnation !== "string" || !/^[0-9a-f]{32}$/.test(grant.accountIncarnation) ||
      (grant.clientAuthMethod !== "none" && grant.clientAuthMethod !== "private_key_jwt") ||
      (grant.clientAuthKeyId !== null && typeof grant.clientAuthKeyId !== "string") ||
      (grant.clientAuthKeyBinding !== null && grant.clientAuthKeyBinding !== "jwk-thumbprint-v1")) return false;
    fields.push(grant.snapshot, grant.digest, grant.accountIncarnation, grant.clientAuthMethod);
    if (grant.clientAuthKeyId !== null) fields.push(grant.clientAuthKeyId);
    if (grant.clientAuthKeyBinding !== null) fields.push(grant.clientAuthKeyBinding);
  }
  const encoder = new TextEncoder();
  let total = 0;
  for (const value of fields) {
    if (
      typeof value !== "string" || !value ||
      value.length > MAX_RESOURCE_FIELD_BYTES
    ) return false;
    total += encoder.encode(value).byteLength;
    if (total > MAX_RESOURCE_FIELD_BYTES) return false;
  }
  return true;
}

function validReplayKey(key: string): boolean {
  return typeof key === "string" && key.length <= MAX_REPLAY_KEY_BYTES &&
    new TextEncoder().encode(key).byteLength <= MAX_REPLAY_KEY_BYTES;
}

/** Cleanup uses the same primary clock and transaction boundary as admission. */
export async function cleanupExpiredOAuthReplaySecrets(
  env: Env,
): Promise<number> {
  const database = env.ALTERAN_DB;
  const clock = await database.prepare(
    "SELECT seconds FROM oauth_replay_clock WHERE id = 1",
  )
    .first<{ seconds: number }>();
  if (!clock || !Number.isSafeInteger(clock.seconds) || clock.seconds < 0) {
    throw new Error("Invalid OAuth replay clock");
  }
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const results = await database.batch([
    database.prepare(UPDATE_CLOCK).bind(nonce),
    database.prepare(ASSERT_CLOCK_AT_LEAST).bind(nonce, clock.seconds),
    database.prepare(OAUTH_REPLAY_SWEEP_SQL).bind(
      nonce,
      clock.seconds,
      OAUTH_REPLAY_CLEANUP_LIMIT,
    ),
    database.prepare(REFRESH_CLOCK).bind(nonce),
    database.prepare(ASSERT_CLOCK).bind(nonce),
  ]);
  return results[2]?.meta.changes ?? 0;
}

function validClaims(claims: OAuthReplayClaims): boolean {
  return Number.isFinite(claims.issuedAt) &&
    (claims.tag === "dpop" || Number.isFinite(claims.expiresAt));
}

function validAt(claims: OAuthReplayClaims, seconds: number): boolean {
  if (
    seconds - claims.issuedAt > DPOP_PROOF_MAX_AGE_SEC ||
    claims.issuedAt - seconds > DPOP_PROOF_FUTURE_SKEW_SEC
  ) return false;
  return claims.tag === "dpop" ||
    (claims.expiresAt > seconds &&
      claims.expiresAt - seconds <= DPOP_PROOF_MAX_AGE_SEC);
}
