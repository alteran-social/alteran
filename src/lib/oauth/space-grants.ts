import type { Env } from "../../env";
import type { OAuthSessionRow } from "../../db/account";
import { loadOAuthSpaceGrant, type OAuthSpaceGrant } from "../../db/oauth-space-grant";
import { restoreExplicitSpaceConsent, type ExplicitSpaceConsentBinding } from "../spaces/explicit-read-consent";
import type { CodeRecord } from "./store";
import { hasSpaceScope } from "./space-consent";

export type OAuthSpaceGrantLookup =
  | { readonly tag: "none" }
  | { readonly tag: "invalid" }
  | { readonly tag: "valid"; readonly grant: OAuthSpaceGrant };

export async function codeSpaceGrant(record: CodeRecord): Promise<OAuthSpaceGrantLookup> {
  if (!hasSpaceScope(record.scope)) return record.spaceConsent ? { tag: "invalid" } : { tag: "none" };
  const stored = record.spaceConsent;
  if (!stored || stored.tokenScope !== record.scope) return { tag: "invalid" };
  const binding: ExplicitSpaceConsentBinding = {
    subject: record.did,
    accountIncarnation: stored.accountIncarnation,
    clientId: record.client_id,
    dpopJkt: record.dpopJkt,
    clientAuthMethod: record.clientAuthMethod,
    clientAuthKeyId: record.clientAuthKeyId ?? null,
    clientAuthKeyBinding: record.clientAuthKeyBinding ?? null,
  };
  const restored = await restoreExplicitSpaceConsent(stored.serialized, stored.digest, binding, record.scope);
  if (!restored) return { tag: "invalid" };
  return { tag: "valid", grant: Object.freeze({
    snapshot: restored.serialized, digest: restored.digest, accountIncarnation: binding.accountIncarnation,
    clientAuthMethod: binding.clientAuthMethod, clientAuthKeyId: binding.clientAuthKeyId,
    clientAuthKeyBinding: binding.clientAuthKeyBinding, grants: restored.grants,
  }) };
}

export async function sessionSpaceGrant(
  env: Env,
  session: OAuthSessionRow,
  signedDigest: unknown,
): Promise<OAuthSpaceGrantLookup> {
  if (!hasSpaceScope(session.scope)) return signedDigest === undefined ? { tag: "none" } : { tag: "invalid" };
  if (typeof signedDigest !== "string") return { tag: "invalid" };
  const grant = await loadOAuthSpaceGrant(env, {
    sessionId: session.id, accessJti: session.accessJti, did: session.did, clientId: session.clientId,
    jkt: session.dpopJkt, scope: session.scope,
  }, signedDigest);
  return grant ? { tag: "valid", grant } : { tag: "invalid" };
}
