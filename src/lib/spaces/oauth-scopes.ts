import { isValidNsid, isValidRecordKey } from "@atproto/syntax-spaces";
import { copyPlainArray, copyPlainRecord } from "./plain-values";
import { isSpaceDid } from "./space-did";

export type SpaceRecordAction = "create" | "update" | "delete";
export type SpaceAction = "read" | "read_self" | SpaceRecordAction;

export type SpaceCollections =
  | { readonly tag: "declaration" }
  | { readonly tag: "explicit"; readonly values: readonly string[] };

export type SpacePermission = {
  readonly spaceType: string;
  readonly authority: string;
  readonly skey: string;
  readonly collections: SpaceCollections;
  readonly actions: readonly SpaceAction[];
  readonly manage: readonly SpaceRecordAction[];
};

export type IssuedSpacePermission = Omit<SpacePermission, "collections"> & {
  readonly tag: "issued";
  readonly collectionSource: "declaration" | "explicit";
  readonly collections: Extract<SpaceCollections, { readonly tag: "explicit" }>;
};

// Wildcards in a target represent a request covering an entire set of spaces.
export type SpacePermissionTarget = {
  readonly spaceType: string;
  readonly authority: string;
  readonly skey: string;
};

export type SpacePermissionOperation =
  | { readonly action: "read" }
  | { readonly action: "read_self" }
  | { readonly action: SpaceRecordAction; readonly collection: string }
  | { readonly manage: SpaceRecordAction };

export type SpaceTypeDeclaration = {
  readonly spaceType: string;
  readonly collections: readonly string[];
};

/** Materialize a verified declaration and the granting DID at token issuance. */
export function materializeSpacePermission(
  value: SpacePermission,
  grantingDid: string,
  declaration?: SpaceTypeDeclaration,
): IssuedSpacePermission | null {
  const fields = copyPlainRecord(value, [
    "spaceType",
    "authority",
    "skey",
    "collections",
    "actions",
    "manage",
  ]);
  const permission = fields && copyPermissionFields(fields);
  if (
    !permission || typeof grantingDid !== "string" ||
    !isSpaceDid(grantingDid) ||
    (permission.collections.tag === "explicit" &&
      permission.collections.values.length === 0)
  ) return null;
  let collections = permission.collections;
  if (collections.tag === "declaration") {
    if (permission.spaceType === "*") {
      collections = { tag: "explicit", values: [] };
    } else {
      const source = copyPlainRecord(declaration, ["spaceType", "collections"]);
      const values = source && copyPlainArray(source.collections, 128);
      if (
        !source || source.spaceType !== permission.spaceType || !values ||
        !values.every((collection) =>
          typeof collection === "string" && isValidNsid(collection)
        )
      ) {
        return null;
      }
      collections = {
        tag: "explicit",
        values: [...new Set(values as string[])],
      };
    }
  } else {
    collections = { tag: "explicit", values: [...collections.values] };
  }
  return {
    ...permission,
    tag: "issued",
    collectionSource: permission.collections.tag,
    authority: permission.authority === "self"
      ? grantingDid
      : permission.authority,
    collections,
    actions: [...permission.actions],
    manage: [...permission.manage],
  };
}

const ACTIONS: ReadonlySet<string> = new Set([
  "read",
  "read_self",
  "create",
  "update",
  "delete",
]);
const WRITE_ACTIONS: ReadonlySet<string> = new Set([
  "create",
  "update",
  "delete",
]);
const DEFAULT_ACTIONS: readonly SpaceAction[] = [
  "read",
  "create",
  "update",
  "delete",
];
const PARAMETERS: ReadonlySet<string> = new Set([
  "spaceType",
  "authority",
  "skey",
  "collection",
  "action",
  "manage",
]);

export function parseSpacePermission(scope: unknown): SpacePermission | null {
  if (
    typeof scope !== "string" || scope.length > 8192 ||
    !/^[\x21-\x7e]+$/.test(scope) ||
    /%(?![0-9a-fA-F]{2})/.test(scope)
  ) return null;

  const question = scope.indexOf("?");
  const head = question === -1 ? scope : scope.slice(0, question);
  const query = question === -1 ? "" : scope.slice(question + 1);
  const params = new URLSearchParams(query);
  for (const key of params.keys()) {
    if (!PARAMETERS.has(key)) return null;
  }

  let positional: string | undefined;
  if (head.startsWith("space:")) {
    try {
      positional = decodeURIComponent(head.slice("space:".length));
    } catch {
      return null;
    }
  } else if (head !== "space") {
    return null;
  }

  const namedTypes = params.getAll("spaceType");
  const authorities = params.getAll("authority");
  const keys = params.getAll("skey");
  if (namedTypes.length > 1 || authorities.length > 1 || keys.length > 1) {
    return null;
  }
  if (positional !== undefined && namedTypes.length) return null;

  const spaceType = positional ?? namedTypes[0];
  const authority = authorities[0] ?? "self";
  const skey = keys[0] ?? "*";
  if (
    !spaceType || !isSpaceType(spaceType) || !isAuthority(authority) ||
    !isSpaceKey(skey)
  ) {
    return null;
  }

  const collections = params.getAll("collection");
  const actions = params.getAll("action");
  const manage = params.getAll("manage");
  if (
    collections.length > 128 || actions.length > 128 || manage.length > 128 ||
    !collections.every(isCollection) || !actions.every(isSpaceAction) ||
    !manage.every(isWriteAction)
  ) return null;

  return {
    spaceType,
    authority,
    skey,
    collections: collections.length
      ? { tag: "explicit", values: [...new Set(collections)] }
      : { tag: "declaration" },
    actions: actions.length ? [...new Set(actions)] : [...DEFAULT_ACTIONS],
    manage: [...new Set(manage)],
  };
}

/**
 * Checks an OAuth grant, not a space credential. Callers must separately
 * enforce repository ownership for account-authenticated reads and writes,
 * and space authority for management operations. A `read` grant permits
 * delegation; it does not authorize an OAuth read from another account's repo.
 */
export function allowsSpacePermission(
  value: IssuedSpacePermission,
  targetValue: SpacePermissionTarget,
  operationValue: SpacePermissionOperation,
): boolean {
  const permission = copyIssuedSpacePermission(value);
  const target = copyPlainRecord(targetValue, [
    "spaceType",
    "authority",
    "skey",
  ]);
  if (
    !permission || !target ||
    typeof target.spaceType !== "string" ||
    typeof target.authority !== "string" ||
    typeof target.skey !== "string" || !isSpaceType(target.spaceType) ||
    !(target.authority === "*" || isSpaceDid(target.authority)) ||
    !isSpaceKey(target.skey)
  ) return false;

  if (
    !covers(permission.spaceType, target.spaceType) ||
    !covers(permission.authority, target.authority) ||
    !covers(permission.skey, target.skey)
  ) return false;

  const operation = copyPlainRecord(operationValue, ["manage"]) ??
    copyPlainRecord(operationValue, ["action"]) ??
    copyPlainRecord(operationValue, ["action", "collection"]);
  if (!operation) return false;
  if ("manage" in operation) {
    return typeof operation.manage === "string" &&
      isWriteAction(operation.manage) &&
      permission.manage.includes(operation.manage);
  }
  if (!("action" in operation)) return false;
  if (operation.action === "read") return permission.actions.includes("read");
  if (operation.action === "read_self") {
    return permission.actions.includes("read_self") ||
      permission.actions.includes("read");
  }
  if (
    typeof operation.action !== "string" || !isWriteAction(operation.action) ||
    !permission.actions.includes(operation.action) ||
    !("collection" in operation) || typeof operation.collection !== "string" ||
    !isValidNsid(operation.collection)
  ) return false;

  return permission.collections.values.includes("*") ||
    permission.collections.values.includes(operation.collection);
}

/** Copy and validate a grant; its origin and integrity must be checked separately. */
export function copyIssuedSpacePermission(
  value: unknown,
): IssuedSpacePermission | null {
  const fields = copyPlainRecord(value, [
    "tag",
    "collectionSource",
    "spaceType",
    "authority",
    "skey",
    "collections",
    "actions",
    "manage",
  ]);
  if (
    !fields || fields.tag !== "issued" ||
    (fields.collectionSource !== "declaration" &&
      fields.collectionSource !== "explicit")
  ) return null;
  const permission = copyPermissionFields(fields);
  if (
    !permission || permission.authority === "self" ||
    permission.collections.tag !== "explicit"
  ) return null;
  if (
    fields.collectionSource === "explicit" &&
    permission.collections.values.length === 0
  ) return null;
  if (
    fields.collectionSource === "declaration" &&
    (permission.collections.values.includes("*") ||
      (permission.spaceType === "*" &&
        permission.collections.values.length !== 0))
  ) return null;
  return {
    ...permission,
    tag: "issued",
    collectionSource: fields.collectionSource,
    collections: permission.collections,
  };
}

function copyPermissionFields(
  permission: Record<string, unknown>,
): SpacePermission | null {
  const actions = copyPlainArray(permission.actions, 5);
  const manage = copyPlainArray(permission.manage, 3);
  const collectionFields = copyPlainRecord(permission.collections, ["tag"]) ??
    copyPlainRecord(permission.collections, ["tag", "values"]);
  if (
    typeof permission.spaceType !== "string" ||
    !isSpaceType(permission.spaceType) ||
    typeof permission.authority !== "string" ||
    !isAuthority(permission.authority) ||
    typeof permission.skey !== "string" || !isSpaceKey(permission.skey) ||
    !actions ||
    !actions.every((action) =>
      typeof action === "string" && isSpaceAction(action)
    ) ||
    !manage ||
    !manage.every((action) =>
      typeof action === "string" && isWriteAction(action)
    ) ||
    !collectionFields
  ) return null;
  let collections: SpaceCollections;
  if (
    collectionFields.tag === "declaration" &&
    !Object.hasOwn(collectionFields, "values")
  ) {
    collections = { tag: "declaration" };
  } else {
    const values = copyPlainArray(collectionFields.values, 128);
    if (
      collectionFields.tag !== "explicit" || !values ||
      !values.every((value) => typeof value === "string" && isCollection(value))
    ) return null;
    collections = { tag: "explicit", values: values as string[] };
  }
  return {
    spaceType: permission.spaceType,
    authority: permission.authority,
    skey: permission.skey,
    collections,
    actions: actions as SpaceAction[],
    manage: manage as SpaceRecordAction[],
  };
}

function covers(grant: string, target: string): boolean {
  return grant === "*" || grant === target;
}

function isSpaceType(value: string): boolean {
  return value === "*" || isValidNsid(value);
}

function isAuthority(value: string): boolean {
  return value === "*" || value === "self" || isSpaceDid(value);
}

function isSpaceKey(value: string): boolean {
  return value === "*" || isValidRecordKey(value);
}

function isCollection(value: string): boolean {
  return value === "*" || isValidNsid(value);
}

function isSpaceAction(value: string): value is SpaceAction {
  return ACTIONS.has(value);
}

function isWriteAction(value: string): value is SpaceRecordAction {
  return WRITE_ACTIONS.has(value);
}
