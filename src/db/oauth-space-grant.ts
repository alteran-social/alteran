import type { Env } from "../env";
import { restoreExplicitSpaceConsent, type ExplicitSpaceConsentBinding } from "../lib/spaces/explicit-read-consent";
import type { SpaceConsentGrant } from "../lib/spaces/consent-snapshot";

export type OAuthSpaceGrant = {
  readonly snapshot: string;
  readonly digest: string;
  readonly accountIncarnation: string;
  readonly clientAuthMethod: "none" | "private_key_jwt";
  readonly clientAuthKeyId: string | null;
  readonly clientAuthKeyBinding: "jwk-thumbprint-v1" | null;
  readonly grants: readonly SpaceConsentGrant[];
};

export type OAuthSpaceGrantIdentity = {
  readonly sessionId: string;
  readonly accessJti: string;
  readonly did: string;
  readonly clientId: string;
  readonly jkt: string;
  readonly scope: string;
};

type GrantRow = {
  snapshot: string | null;
  method: string | null;
  key_id: string | null;
  key_binding: string | null;
  incarnation: string | null;
};

/** Read only bounded grant data and verify it against authenticated token fields. */
export async function loadOAuthSpaceGrant(
  env: Env,
  identity: OAuthSpaceGrantIdentity,
  digest: string,
): Promise<OAuthSpaceGrant | null> {
  if (!/^[0-9a-f]{64}$/.test(digest) || identity.scope.length > 4096 ||
    identity.sessionId.length > 128 || identity.accessJti.length > 128 ||
    identity.did.length > 2048 || identity.clientId.length > 2048 || identity.jkt.length > 128) return null;
  const row = await env.ALTERAN_DB.prepare(`SELECT
      CASE WHEN typeof(g.snapshot) = 'text' AND length(CAST(g.snapshot AS BLOB)) BETWEEN 1 AND 65536
        THEN g.snapshot END AS snapshot,
      CASE WHEN s.client_auth_method IN ('none', 'private_key_jwt') THEN s.client_auth_method END AS method,
      CASE WHEN s.client_auth_key_id IS NULL THEN NULL
        WHEN typeof(s.client_auth_key_id) = 'text' AND length(s.client_auth_key_id) = 43
          AND length(CAST(s.client_auth_key_id AS BLOB)) = 43 THEN s.client_auth_key_id END AS key_id,
      CASE WHEN s.client_auth_key_binding IS NULL THEN NULL
        WHEN s.client_auth_key_binding = 'jwk-thumbprint-v1' THEN s.client_auth_key_binding END AS key_binding,
      CASE WHEN typeof(a.space_incarnation) = 'text' AND length(a.space_incarnation) = 32
        AND length(CAST(a.space_incarnation AS BLOB)) = 32 AND a.space_incarnation NOT GLOB '*[^0-9a-f]*'
        THEN a.space_incarnation END AS incarnation
    FROM oauth_space_grant g JOIN oauth_session s ON s.id = g.session_id JOIN account a ON a.did = s.did
    WHERE s.id = ? AND s.access_jti = ? AND s.did = ? AND s.client_id = ?
      AND s.dpop_jkt = ? AND s.scope = ? AND s.revoked_at IS NULL AND g.digest = ?`)
    .bind(identity.sessionId, identity.accessJti, identity.did, identity.clientId,
      identity.jkt, identity.scope, digest).first<GrantRow>();
  if (!row || typeof row.snapshot !== "string" || typeof row.incarnation !== "string" ||
    (row.method !== "none" && row.method !== "private_key_jwt")) return null;
  const binding: ExplicitSpaceConsentBinding = {
    subject: identity.did,
    accountIncarnation: row.incarnation,
    clientId: identity.clientId,
    dpopJkt: identity.jkt,
    clientAuthMethod: row.method,
    clientAuthKeyId: row.key_id,
    clientAuthKeyBinding: row.key_binding === "jwk-thumbprint-v1" ? row.key_binding : null,
  };
  const restored = await restoreExplicitSpaceConsent(row.snapshot, digest, binding, identity.scope);
  if (!restored) return null;
  return Object.freeze({
    snapshot: restored.serialized, digest, accountIncarnation: binding.accountIncarnation, clientAuthMethod: binding.clientAuthMethod,
    clientAuthKeyId: binding.clientAuthKeyId, clientAuthKeyBinding: binding.clientAuthKeyBinding,
    grants: restored.grants,
  });
}

/** Match the bytes already authenticated by a verified access or refresh token. */
export function oauthSpaceGrantFence(alias: string, requireActive = true): string {
  if (!/^[a-z_]+$/.test(alias)) throw new Error("Invalid SQL alias");
  return `(? = 0 OR (EXISTS (SELECT 1 FROM oauth_space_grant grant_row
      WHERE grant_row.session_id = ${alias}.id AND grant_row.snapshot = ? AND grant_row.digest = ?)
    AND ${alias}.client_auth_method IS ? AND ${alias}.client_auth_key_id IS ?
    AND ${alias}.client_auth_key_binding IS ?
    AND EXISTS (SELECT 1 FROM account account_row ${requireActive ? "JOIN account_state state ON state.did = account_row.did" : ""}
      WHERE account_row.did = ${alias}.did AND account_row.space_incarnation = ?
      ${requireActive ? "AND state.active = 1 AND state.status IS NULL AND state.suspended_until IS NULL" : ""})))`;
}

export function oauthSpaceGrantFenceValues(grant?: OAuthSpaceGrant | null): (string | number | null)[] {
  return grant
    ? [1, grant.snapshot, grant.digest, grant.clientAuthMethod, grant.clientAuthKeyId, grant.clientAuthKeyBinding, grant.accountIncarnation]
    : [0, "", "", null, null, null, ""];
}

/** Capture only the explicit active account incarnation for consent. */
export async function loadActiveSpaceIncarnation(env: Env, did: string): Promise<string | null> {
  if (typeof did !== "string" || !did || did.length > 2048) return null;
  const row = await env.ALTERAN_DB.prepare(`SELECT CASE WHEN typeof(a.space_incarnation) = 'text'
      AND length(a.space_incarnation) = 32 AND length(CAST(a.space_incarnation AS BLOB)) = 32
      AND a.space_incarnation NOT GLOB '*[^0-9a-f]*' THEN a.space_incarnation END AS incarnation
    FROM account a JOIN account_state state ON state.did = a.did
    WHERE a.did = ? AND state.active = 1 AND state.status IS NULL AND state.suspended_until IS NULL`)
    .bind(did).first<{ incarnation: string | null }>();
  return row?.incarnation ?? null;
}
