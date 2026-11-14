import { isValidDid, SpaceRef } from "@atproto/syntax-spaces";
import { isLexiconUri } from "./lexicon-uri";
import { copyPlainRecord } from "./plain-values";
import { parseSpacePolicy } from "./policy";

export type SpaceMembership =
  | { readonly tag: "not-checked" | "not-member" | "unavailable" }
  | { readonly tag: "member"; readonly read: boolean; readonly write: boolean };

export type SpacePolicyAccess =
  | {
    readonly tag:
      | "allowed"
      | "denied"
      | "lookup-required"
      | "unavailable"
      | "invalid"
      | "unsupported";
  }
  | { readonly tag: "managed"; readonly managingApp: string };

export type SpaceClientAttestation =
  | { readonly tag: "absent" | "invalid" | "unavailable" }
  | { readonly tag: "verified"; readonly clientId: string };

/**
 * Account policy controls credential issuance and writer tracking. The caller
 * authenticates the repo and obtains membership from the authority's store.
 */
export function decideSpaceAccountAccess(
  policyValue: unknown,
  inputValue: {
    readonly space: string;
    readonly repo: string | null;
    readonly action: "read" | "write";
    readonly membership: SpaceMembership;
  },
): SpacePolicyAccess {
  const parsed = parseSpacePolicy(policyValue);
  if (parsed.tag !== "valid") return { tag: parsed.tag };
  const input = copyPlainRecord(inputValue, [
    "space",
    "repo",
    "action",
    "membership",
  ]);
  if (
    !input || typeof input.space !== "string" || input.space.length > 8192 ||
    (input.repo !== null && !validDid(input.repo)) ||
    (input.action !== "read" && input.action !== "write")
  ) return { tag: "invalid" };
  const membership = copyMembership(input.membership);
  if (!membership) return { tag: "invalid" };

  let authority: string;
  try {
    const reference = SpaceRef.parse(input.space);
    if (reference.toString() !== input.space || !validDid(reference.spaceDid)) {
      return { tag: "invalid" };
    }
    authority = reference.spaceDid;
  } catch {
    return { tag: "invalid" };
  }
  if (input.repo === authority) return { tag: "allowed" };
  // Writer tracking requires an authenticated repo, including for managed spaces.
  if (input.action === "write" && input.repo === null) return { tag: "denied" };
  const policy = parsed.policy;
  if (policy.$type === "com.atproto.personalspace.policy") {
    return { tag: "denied" };
  }
  if (policy.$type === "com.atproto.managedspace.policy") {
    return { tag: "managed", managingApp: policy.managingApp };
  }
  if (input.action === "read" && policy.publicRead) return { tag: "allowed" };
  if (input.repo === null) return { tag: "denied" };
  if (membership.tag === "not-checked") return { tag: "lookup-required" };
  if (membership.tag === "unavailable") return { tag: "unavailable" };
  if (membership.tag === "member") {
    return { tag: membership[input.action] ? "allowed" : "denied" };
  }
  return {
    tag: input.action === "write" && policy.publicWrite ? "allowed" : "denied",
  };
}

/** Application restrictions apply to credential issuance, not writer tracking. */
export function decideSpaceClientAccess(
  policyValue: unknown,
  attestationValue: SpaceClientAttestation,
): {
  readonly tag:
    | "allowed"
    | "denied"
    | "invalid"
    | "unavailable"
    | "unsupported";
} {
  const parsed = parseSpacePolicy(policyValue);
  if (parsed.tag !== "valid") return { tag: parsed.tag };
  const fields = copyPlainRecord(attestationValue, ["tag"]) ??
    copyPlainRecord(attestationValue, ["tag", "clientId"]);
  if (!fields) return { tag: "invalid" };
  if (fields.tag === "invalid" || fields.tag === "unavailable") {
    return { tag: fields.tag };
  }
  let clientId: string | undefined;
  if (fields.tag === "verified") {
    if (!isLexiconUri(fields.clientId)) {
      return { tag: "invalid" };
    }
    clientId = fields.clientId;
  } else if (fields.tag !== "absent" || Object.hasOwn(fields, "clientId")) {
    return { tag: "invalid" };
  }
  const policy = parsed.policy;
  if (
    policy.$type !== "com.atproto.memberspace.policy" ||
    policy.allowedApps === undefined
  ) {
    return { tag: "allowed" };
  }
  return {
    tag: clientId !== undefined && policy.allowedApps.includes(clientId)
      ? "allowed"
      : "denied",
  };
}

function validDid(value: unknown): value is string {
  return typeof value === "string" && value.length <= 2048 &&
    !/%(?![0-9A-Fa-f]{2})/.test(value) && isValidDid(value);
}

function copyMembership(value: unknown): SpaceMembership | null {
  const fields = copyPlainRecord(value, ["tag"]) ??
    copyPlainRecord(value, ["tag", "read", "write"]);
  if (!fields) return null;
  if (
    (fields.tag === "not-checked" || fields.tag === "not-member" ||
      fields.tag === "unavailable") &&
    !Object.hasOwn(fields, "read")
  ) return { tag: fields.tag };
  if (
    fields.tag === "member" && typeof fields.read === "boolean" &&
    typeof fields.write === "boolean"
  ) {
    return { tag: "member", read: fields.read, write: fields.write };
  }
  return null;
}
