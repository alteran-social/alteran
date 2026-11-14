import { isValidDid } from "@atproto/syntax-spaces";
import {
  copyIssuedSpacePermission,
  type IssuedSpacePermission,
  materializeSpacePermission,
  parseSpacePermission,
} from "./oauth-scopes";
import { copyPlainArray, copyPlainRecord } from "./plain-values";

export type SpaceConsentGrant = {
  readonly requestedScope: string;
  readonly permission: IssuedSpacePermission;
};

export type SpaceConsentSnapshot = {
  readonly version: 1;
  readonly subject: string;
  readonly clientId: string;
  readonly grants: readonly SpaceConsentGrant[];
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
}): Promise<SpaceConsentSnapshotSeal | null> {
  const captured = copyPlainRecord(input, ["subject", "clientId", "grants"]);
  if (!captured) return null;
  const snapshot = copySnapshot({ version: 1, ...captured });
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
  ]);
  const source = fields && copyPlainArray(fields.grants, MAX_PERMISSIONS);
  if (
    !fields || fields.version !== 1 || typeof fields.subject !== "string" ||
    !isValidDid(fields.subject) || !isClientId(fields.clientId) || !source
  ) return null;

  const grants: SpaceConsentGrant[] = [];
  const scopes = new Set<string>();
  const declarations = new Map<string, string>();
  for (const grant of source) {
    const copy = copyGrant(grant, fields.subject);
    if (!copy) return null;
    if (scopes.has(copy.requestedScope)) return null;
    scopes.add(copy.requestedScope);
    if (copy.permission.collectionSource === "declaration") {
      const { spaceType, collections } = copy.permission;
      const serialized = JSON.stringify(collections.values);
      const previous = declarations.get(spaceType);
      if (previous !== undefined && previous !== serialized) return null;
      declarations.set(spaceType, serialized);
    }
    grants.push(copy);
  }
  return {
    version: 1,
    subject: fields.subject,
    clientId: fields.clientId,
    grants,
  };
}

function copyGrant(value: unknown, subject: string): SpaceConsentGrant | null {
  const fields = copyPlainRecord(value, ["requestedScope", "permission"]);
  if (
    !fields || typeof fields.requestedScope !== "string" ||
    fields.requestedScope.length > 8192
  ) return null;
  const requested = parseSpacePermission(fields.requestedScope);
  const permission = copyIssuedSpacePermission(fields.permission);
  if (!requested || !permission) return null;
  const expected = materializeSpacePermission(requested, subject, {
    spaceType: requested.spaceType,
    collections: permission.collections.values,
  });
  if (!expected) return null;
  const canonical = copyIssuedSpacePermission(expected);
  if (!canonical || JSON.stringify(canonical) !== JSON.stringify(permission)) {
    return null;
  }
  return { requestedScope: fields.requestedScope, permission };
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
  return Object.freeze(snapshot);
}

function isClientId(value: unknown): value is string {
  return typeof value === "string" && value.length <= MAX_CLIENT_ID_LENGTH &&
    /^[\x21-\x7e]+$/.test(value);
}

function isValidBinding(value: Record<string, unknown>): boolean {
  return typeof value.subject === "string" &&
    isValidDid(value.subject) &&
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
