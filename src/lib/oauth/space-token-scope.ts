import { isSupportedOAuthScopeValue } from "../auth-scope";
import { copyIssuedSpacePermission } from "../spaces/oauth-scopes";
import { copyPlainArray, copyPlainRecord } from "../spaces/plain-values";

export const MAX_MATERIALIZED_SCOPE_BYTES = 4096;
const MAX_SCOPE_VALUES = 128;

export type SpaceTokenScopeResult =
  | { readonly tag: "formatted"; readonly scope: string }
  | { readonly tag: "invalid" | "unsupported" | "tooLarge" };

/**
 * Format authenticated, materialized grants for a token response. The
 * trusted grant snapshot, rather than this text, retains default provenance.
 */
export function formatSpaceTokenScope(input: {
  readonly otherScopes: readonly string[];
  readonly grants: readonly unknown[];
}): SpaceTokenScopeResult {
  const fields = copyPlainRecord(input, ["otherScopes", "grants"]);
  const otherScopes = fields &&
    copyPlainArray(fields.otherScopes, MAX_SCOPE_VALUES);
  const grants = fields && copyPlainArray(fields.grants, MAX_SCOPE_VALUES);
  if (!otherScopes || !grants) return { tag: "invalid" };
  const parts = new Set<string>();
  let bytes = 0;
  const add = (scope: string): boolean => {
    if (parts.has(scope)) return true;
    bytes += scope.length + (parts.size > 0 ? 1 : 0);
    if (bytes > MAX_MATERIALIZED_SCOPE_BYTES) return false;
    parts.add(scope);
    return true;
  };
  for (const scope of otherScopes) {
    if (
      typeof scope !== "string" ||
      scope.length > MAX_MATERIALIZED_SCOPE_BYTES ||
      scope === "space" || scope.startsWith("space:") ||
      scope.startsWith("space?") ||
      !isSupportedOAuthScopeValue(scope)
    ) return { tag: "invalid" };
    if (!add(scope)) return { tag: "tooLarge" };
  }
  if (!parts.has("atproto")) return { tag: "invalid" };
  for (const value of grants) {
    const permission = copyIssuedSpacePermission(value);
    if (!permission || permission.actions.length === 0) {
      return { tag: "invalid" };
    }
    // The alpha reference formatter can decode a DID escape on its next parse.
    if (permission.authority.includes("%")) return { tag: "unsupported" };
    const parameters = new URLSearchParams();
    parameters.set("authority", permission.authority);
    parameters.set("skey", permission.skey);
    for (const collection of permission.collections.values) {
      parameters.append("collection", collection);
    }
    for (const action of permission.actions) {
      parameters.append("action", action);
    }
    for (const operation of permission.manage) {
      parameters.append("manage", operation);
    }
    if (
      !add(
        `space:${
          encodeURIComponent(permission.spaceType)
        }?${parameters.toString()}`,
      )
    ) {
      return { tag: "tooLarge" };
    }
  }
  const scope = [...parts].join(" ");
  return { tag: "formatted", scope };
}
