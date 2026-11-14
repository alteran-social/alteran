import type { SpaceConsentGrant } from "./consent-snapshot";
import {
  materializeSpacePermission,
  materializeCollectionFreeReadSelf,
  parseSpacePermission,
  type SpacePermission,
} from "./oauth-scopes";

export function isSpaceScope(scope: string): boolean {
  return scope === "space" || scope.startsWith("space:") || scope.startsWith("space?");
}

/** The initial Space grant supports only an explicit read-self request. */
export function parseExplicitSpaceReadGrant(scope: unknown): SpacePermission | null {
  const permission = parseSpacePermission(scope);
  if (
    !permission ||
    (permission.collections.tag === "explicit" && permission.collections.values.length === 0) ||
    permission.actions.length !== 1 || permission.actions[0] !== "read_self" ||
    permission.manage.length !== 0 || permission.authority.includes("%")
  ) return null;
  return permission;
}

/** Resolve `self` against the captured account before showing consent. */
export function materializeExplicitSpaceReadGrant(
  scope: string,
  subject: string,
): SpaceConsentGrant | null {
  const requested = parseExplicitSpaceReadGrant(scope);
  if (!requested) return null;
  const permission = requested.collections.tag === "declaration"
    ? materializeCollectionFreeReadSelf(requested, subject)
    : materializeSpacePermission(requested, subject);
  // Escaped DID authorities cannot safely be formatted for token responses.
  if (!permission || permission.authority.includes("%")) return null;
  return { requestedScope: scope, permission };
}
