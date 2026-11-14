import { isSpaceDid } from "./space-did";
import { isLexiconUri } from "./lexicon-uri";
import {
  copyIssuedSpacePermission,
  type IssuedSpacePermission,
  materializeSpacePermission,
  parseSpacePermission,
} from "./oauth-scopes";
import { copyPlainArray, copyPlainRecord } from "./plain-values";
import {
  copySpaceDeclarationEvidence,
  type SpaceDeclarationEvidence,
} from "./declaration-evidence";
import { SPACE_LEXICON_LIMITS } from "./lexicon-limits";

export type SpaceConsentGrant = {
  readonly requestedScope: string;
  readonly permission: IssuedSpacePermission;
};

export type SpaceConsentSnapshot = {
  readonly version: 2;
  readonly subject: string;
  readonly clientId: string;
  readonly grants: readonly SpaceConsentGrant[];
  readonly declarations: readonly SpaceDeclarationEvidence[];
};

export type SpaceConsentSnapshotSeal = {
  readonly serialized: string;
  readonly digest: string;
};

export type SpaceConsentSnapshotBinding = {
  readonly subject: string;
  readonly clientId: string;
  readonly digest: string;
};

const MAX_SERIALIZED_BYTES = 64 * 1024;
const MAX_PERMISSIONS = 128;
const MAX_CLIENT_ID_LENGTH = 2048;

/**
 * The caller supplies scopes from the trusted authorization request and
 * permissions materialized from authenticated, current declarations.
 */
export async function createSpaceConsentSnapshot(input: {
  readonly subject: string;
  readonly clientId: string;
  readonly grants: readonly SpaceConsentGrant[];
  readonly declarations: readonly SpaceDeclarationEvidence[];
}): Promise<SpaceConsentSnapshotSeal | null> {
  const captured = copyPlainRecord(input, [
    "subject",
    "clientId",
    "grants",
    "declarations",
  ]);
  if (!captured) return null;
  const snapshot = copySnapshot({ version: 2, ...captured });
  if (!snapshot) return null;
  const serialized = JSON.stringify(snapshot);
  const bytes = encodedSnapshot(serialized);
  if (!bytes) return null;
  return { serialized, digest: await digestBytes(bytes) };
}

/**
 * The expected binding must come from an authenticated token or trusted
 * one-use consent/session record, never from the serialized snapshot itself.
 */
export async function restoreSpaceConsentSnapshot(
  serialized: unknown,
  binding: SpaceConsentSnapshotBinding,
): Promise<SpaceConsentSnapshot | null> {
  const captured = copyPlainRecord(binding, ["subject", "clientId", "digest"]);
  if (
    typeof serialized !== "string" || !captured || !isValidBinding(captured)
  ) return null;
  const { subject, clientId, digest } = captured;
  const bytes = encodedSnapshot(serialized);
  if (!bytes) return null;

  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch {
    return null;
  }
  const snapshot = copySnapshot(value);
  if (
    !snapshot || JSON.stringify(snapshot) !== serialized ||
    snapshot.subject !== subject || snapshot.clientId !== clientId
  ) return null;
  if (await digestBytes(bytes) !== digest) return null;
  return freezeSnapshot(snapshot);
}

function copySnapshot(value: unknown): SpaceConsentSnapshot | null {
  const fields = copyPlainRecord(value, [
    "version",
    "subject",
    "clientId",
    "grants",
    "declarations",
  ]);
  const source = fields && copyPlainArray(fields.grants, MAX_PERMISSIONS);
  const declarationSource = fields &&
    copyPlainArray(
      fields.declarations,
      SPACE_LEXICON_LIMITS.declarationsPerRequest,
    );
  if (
    !fields || fields.version !== 2 || typeof fields.subject !== "string" ||
    !isSpaceDid(fields.subject) || !isClientId(fields.clientId) || !source ||
    !declarationSource
  ) return null;

  const declarations: SpaceDeclarationEvidence[] = [];
  const declarationsByType = new Map<string, SpaceDeclarationEvidence>();
  for (const item of declarationSource) {
    const evidence = copySpaceDeclarationEvidence(item);
    if (!evidence || declarationsByType.has(evidence.spaceType)) return null;
    declarations.push(evidence);
    declarationsByType.set(evidence.spaceType, evidence);
  }
  const grants: SpaceConsentGrant[] = [];
  const scopes = new Set<string>();
  const usedDeclarations = new Set<string>();
  for (const grant of source) {
    const copy = copyGrant(grant, fields.subject, declarationsByType);
    if (!copy) return null;
    if (scopes.has(copy.grant.requestedScope)) return null;
    scopes.add(copy.grant.requestedScope);
    if (copy.declarationType) usedDeclarations.add(copy.declarationType);
    grants.push(copy.grant);
  }
  if (usedDeclarations.size !== declarations.length) return null;
  return {
    version: 2,
    subject: fields.subject,
    clientId: fields.clientId,
    grants,
    declarations,
  };
}

function copyGrant(
  value: unknown,
  subject: string,
  declarations: ReadonlyMap<string, SpaceDeclarationEvidence>,
):
  | { readonly grant: SpaceConsentGrant; readonly declarationType?: string }
  | null {
  const fields = copyPlainRecord(value, ["requestedScope", "permission"]);
  if (
    !fields || typeof fields.requestedScope !== "string" ||
    fields.requestedScope.length > 8192
  ) return null;
  const requested = parseSpacePermission(fields.requestedScope);
  const permission = copyIssuedSpacePermission(fields.permission);
  if (!requested || !permission) return null;
  const declarationType =
    requested.collections.tag === "declaration" && requested.spaceType !== "*"
      ? requested.spaceType
      : undefined;
  const evidence = declarationType
    ? declarations.get(declarationType)
    : undefined;
  if (declarationType && !evidence) return null;
  const expected = materializeSpacePermission(
    requested,
    subject,
    evidence && {
      spaceType: evidence.spaceType,
      collections: evidence.collections,
    },
  );
  if (!expected) return null;
  const canonical = copyIssuedSpacePermission(expected);
  if (!canonical || JSON.stringify(canonical) !== JSON.stringify(permission)) {
    return null;
  }
  return {
    grant: { requestedScope: fields.requestedScope, permission },
    declarationType,
  };
}

function freezeSnapshot(snapshot: SpaceConsentSnapshot): SpaceConsentSnapshot {
  for (const grant of snapshot.grants) {
    Object.freeze(grant.permission.collections.values);
    Object.freeze(grant.permission.collections);
    Object.freeze(grant.permission.actions);
    Object.freeze(grant.permission.manage);
    Object.freeze(grant.permission);
    Object.freeze(grant);
  }
  Object.freeze(snapshot.grants);
  Object.freeze(snapshot.declarations);
  return Object.freeze(snapshot);
}

function isClientId(value: unknown): value is string {
  return typeof value === "string" && value.length <= MAX_CLIENT_ID_LENGTH &&
    isLexiconUri(value);
}

function isValidBinding(value: Record<string, unknown>): boolean {
  return typeof value.subject === "string" &&
    isSpaceDid(value.subject) &&
    isClientId(value.clientId) && typeof value.digest === "string" &&
    /^[0-9a-f]{64}$/.test(value.digest);
}

function encodedSnapshot(value: string): Uint8Array | null {
  if (value.length > MAX_SERIALIZED_BYTES) return null;
  const bytes = new TextEncoder().encode(value);
  return bytes.length <= MAX_SERIALIZED_BYTES ? bytes : null;
}

async function digestBytes(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
  return Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
}
