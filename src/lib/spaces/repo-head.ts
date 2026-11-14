import { isValidTid } from "@atproto/syntax-spaces";
import { base32 } from "multiformats/bases/base32";
import { parseCanonicalRepoCid } from "./repo-cid";

export type PublicRepoHead = {
  readonly cid: string;
  readonly revision: string;
};

export function parsePublicRepoHead(value: unknown): PublicRepoHead | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const head = value as Record<string, unknown>;
  if (
    typeof head.cid !== "string" || head.cid.length > 128 ||
    typeof head.rev !== "string" || !isValidTid(head.rev)
  ) {
    return null;
  }
  const cid = parseCanonicalRepoCid(head.cid);
  return cid ? { cid: base32.encode(cid.bytes), revision: head.rev } : null;
}
