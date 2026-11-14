import { isValidDid } from "@atproto/syntax-spaces";
import {
  isIssuedSpacePermission,
  type IssuedSpacePermission,
} from "./oauth-scopes";

export type SpaceConsentSnapshot = {
  readonly version: 1;
  readonly subject: string;
  readonly clientId: string;
  readonly permissions: readonly IssuedSpacePermission[];
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
const MAX_COLLECTIONS = 128;
const MAX_CLIENT_ID_LENGTH = 2048;

/** Create a snapshot from permissions materialized by the authorization server. */
export async function createSpaceConsentSnapshot(input: {
  readonly subject: string;
  readonly clientId: string;
  readonly permissions: readonly IssuedSpacePermission[];
}): Promise<SpaceConsentSnapshotSeal | null> {
  const snapshot = copySnapshot({ version: 1, ...input });
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
  if (typeof serialized !== "string" || !isValidBinding(binding)) return null;
  const { subject, clientId, digest } = binding;
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
  return snapshot;
}

function copySnapshot(value: unknown): SpaceConsentSnapshot | null {
  if (
    !hasExactKeys(value, ["version", "subject", "clientId", "permissions"]) ||
    value.version !== 1 || typeof value.subject !== "string" ||
    !isValidDid(value.subject) ||
    !isClientId(value.clientId) || !Array.isArray(value.permissions) ||
    value.permissions.length > MAX_PERMISSIONS
  ) return null;

  const permissions: IssuedSpacePermission[] = [];
  for (const permission of value.permissions) {
    const copy = copyPermission(permission);
    if (!copy) return null;
    permissions.push(copy);
  }
  return {
    version: 1,
    subject: value.subject,
    clientId: value.clientId,
    permissions,
  };
}

function copyPermission(value: unknown): IssuedSpacePermission | null {
  if (
    !hasExactKeys(value, [
      "tag",
      "spaceType",
      "authority",
      "skey",
      "collections",
      "actions",
      "manage",
    ]) ||
    !hasExactKeys(value.collections, ["tag", "values"]) ||
    !Array.isArray(value.collections.values) ||
    value.collections.values.length > MAX_COLLECTIONS ||
    !Array.isArray(value.actions) || value.actions.length > 5 ||
    !Array.isArray(value.manage) || value.manage.length > 3 ||
    !isIssuedSpacePermission(value)
  ) return null;

  return {
    tag: "issued",
    spaceType: value.spaceType,
    authority: value.authority,
    skey: value.skey,
    collections: { tag: "explicit", values: [...value.collections.values] },
    actions: [...value.actions],
    manage: [...value.manage],
  };
}

function hasExactKeys(
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value);
  return actual.length === keys.length &&
    actual.every((key) => keys.includes(key));
}

function isClientId(value: unknown): value is string {
  return typeof value === "string" && value.length <= MAX_CLIENT_ID_LENGTH &&
    /^[\x21-\x7e]+$/.test(value);
}

function isValidBinding(value: SpaceConsentSnapshotBinding): boolean {
  return !!value && typeof value.subject === "string" &&
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
