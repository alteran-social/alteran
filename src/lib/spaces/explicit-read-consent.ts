import { formatSpaceTokenScope } from "../oauth/space-token-scope";
import {
  createSpaceConsentSnapshot,
  restoreSpaceConsentSnapshot,
  type SpaceConsentGrant,
} from "./consent-snapshot";
import { isSpaceScope, materializeExplicitSpaceReadGrant } from "./explicit-read-grant";
import { isSpaceDid } from "./space-did";
import { isLexiconUri } from "./lexicon-uri";
import { copyPlainRecord } from "./plain-values";

export type ExplicitSpaceConsentBinding = {
  readonly subject: string;
  readonly accountIncarnation: string;
  readonly clientId: string;
  readonly dpopJkt: string;
  readonly clientAuthMethod: "none" | "private_key_jwt";
  readonly clientAuthKeyId: string | null;
  readonly clientAuthKeyBinding: "jwk-thumbprint-v1" | null;
};

export type ExplicitSpaceConsent = {
  readonly serialized: string;
  readonly digest: string;
  readonly tokenScope: string;
  readonly grants: readonly SpaceConsentGrant[];
};

const MAX_SNAPSHOT_BYTES = 65_536;
const MAX_REQUESTED_SCOPE_BYTES = 16_384;
const BINDING_KEYS = [
  "subject", "accountIncarnation", "clientId", "dpopJkt", "clientAuthMethod",
  "clientAuthKeyId", "clientAuthKeyBinding",
] as const;
const SERIALIZED_KEYS = [
  "version", ...BINDING_KEYS, "requestedScope", "tokenScope",
  "consentSnapshot", "consentDigest",
] as const;

/** Seal the exact grant shown to the configured single-user account. */
export async function createExplicitSpaceConsent(
  binding: ExplicitSpaceConsentBinding,
  requestedScope: string,
): Promise<ExplicitSpaceConsent | null> {
  const captured = captureBinding(binding);
  if (
    !captured || typeof requestedScope !== "string" ||
    requestedScope.length > MAX_REQUESTED_SCOPE_BYTES ||
    !/^[\x21-\x7e]+(?: [\x21-\x7e]+)*$/.test(requestedScope)
  ) return null;
  const parts = requestedScope.split(" ");
  if (parts.length > 128 || new Set(parts).size !== parts.length) return null;
  const otherScopes: string[] = [];
  const grants: SpaceConsentGrant[] = [];
  for (const part of parts) {
    if (!isSpaceScope(part)) {
      otherScopes.push(part);
      continue;
    }
    const grant = materializeExplicitSpaceReadGrant(part, captured.subject);
    if (!grant) return null;
    grants.push(grant);
  }
  if (grants.length === 0) return null;
  const formatted = formatSpaceTokenScope({
    otherScopes,
    grants: grants.map((grant) => grant.permission),
  });
  if (formatted.tag !== "formatted") return null;
  const consent = await createSpaceConsentSnapshot({
    subject: captured.subject,
    clientId: captured.clientId,
    grants,
    declarations: [],
  });
  if (!consent) return null;
  const restored = await restoreSpaceConsentSnapshot(consent.serialized, {
    subject: captured.subject,
    clientId: captured.clientId,
    digest: consent.digest,
  });
  if (!restored) return null;
  const serialized = JSON.stringify({
    version: 1,
    ...captured,
    requestedScope,
    tokenScope: formatted.scope,
    consentSnapshot: consent.serialized,
    consentDigest: consent.digest,
  });
  if (serialized.length > MAX_SNAPSHOT_BYTES) return null;
  const bytes = new TextEncoder().encode(serialized);
  if (bytes.byteLength > MAX_SNAPSHOT_BYTES) return null;
  return Object.freeze({
    serialized,
    digest: await digestBytes(bytes),
    tokenScope: formatted.scope,
    grants: restored.grants,
  });
}

/** Restore only with identity fields captured from a trusted request or token. */
export async function restoreExplicitSpaceConsent(
  serialized: unknown,
  digest: unknown,
  binding: ExplicitSpaceConsentBinding,
  tokenScope: string,
  requestedScope?: string,
): Promise<ExplicitSpaceConsent | null> {
  if (
    typeof serialized !== "string" || serialized.length > MAX_SNAPSHOT_BYTES ||
    typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)
  ) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    return null;
  }
  const fields = copyPlainRecord(parsed, SERIALIZED_KEYS);
  if (
    !fields || fields.version !== 1 || typeof fields.requestedScope !== "string" ||
    (requestedScope !== undefined && fields.requestedScope !== requestedScope)
  ) return null;
  const expected = await createExplicitSpaceConsent(binding, fields.requestedScope);
  return expected && expected.serialized === serialized && expected.digest === digest &&
      expected.tokenScope === tokenScope
    ? expected
    : null;
}

function captureBinding(value: ExplicitSpaceConsentBinding): ExplicitSpaceConsentBinding | null {
  const fields = copyPlainRecord(value, BINDING_KEYS);
  if (
    !fields || !isSpaceDid(fields.subject) || typeof fields.accountIncarnation !== "string" ||
    !/^[0-9a-f]{32}$/.test(fields.accountIncarnation) ||
    typeof fields.clientId !== "string" || fields.clientId.length > 2048 ||
    !isLexiconUri(fields.clientId) || typeof fields.dpopJkt !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(fields.dpopJkt)
  ) return null;
  if (fields.clientAuthMethod === "none") {
    if (fields.clientAuthKeyId !== null || fields.clientAuthKeyBinding !== null) return null;
  } else if (
    fields.clientAuthMethod !== "private_key_jwt" ||
    typeof fields.clientAuthKeyId !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(fields.clientAuthKeyId) ||
    fields.clientAuthKeyBinding !== "jwk-thumbprint-v1"
  ) return null;
  return fields as ExplicitSpaceConsentBinding;
}

async function digestBytes(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
