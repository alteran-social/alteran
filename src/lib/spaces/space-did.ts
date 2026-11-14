import { isValidDid } from "@atproto/syntax-spaces";

/** Validate generic DID syntax without resolving or authenticating the DID. */
export function isSpaceDid(value: unknown): value is string {
  return typeof value === "string" && value.length <= 2048 &&
    !/%(?![0-9A-Fa-f]{2})/.test(value) && isValidDid(value);
}
