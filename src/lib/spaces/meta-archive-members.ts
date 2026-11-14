import { isValidRecordKey } from "@atproto/syntax-spaces";
import { MAX_META_ENTRIES } from "./meta-archive-framing";
import { copyPlainArray, copyPlainRecord } from "./plain-values";
import { isSpaceDid } from "./space-did";
import type { SpaceMetaMember } from "./meta-archive";

const MEMBER_PREFIX = "com.atproto.memberspace.member/";

export type ExpectedSpaceMember = {
  readonly did: string;
  readonly read: boolean;
  readonly write: boolean;
};

/** Capture a caller-provided membership snapshot before reading archive bytes. */
export function captureExpectedSpaceMembers(value: unknown) {
  const entries = copyPlainArray(value, MAX_META_ENTRIES);
  if (!entries) throw invalid();
  const byKey = new Map<string, ExpectedSpaceMember>();
  const dids = new Set<string>();
  for (const entry of entries) {
    const fields = copyPlainRecord(entry, ["did", "read", "write"]);
    if (
      !fields || !isSpaceDid(fields.did) || typeof fields.read !== "boolean" ||
      typeof fields.write !== "boolean"
    ) throw invalid();
    const key = referenceMemberKey(fields.did);
    if (dids.has(fields.did) || byKey.has(key)) throw invalid();
    dids.add(fields.did);
    byKey.set(key, { did: fields.did, read: fields.read, write: fields.write });
  }
  return {
    match(key: string, member: SpaceMetaMember): string {
      const expected = byKey.get(key);
      if (
        !expected || expected.read !== member.read ||
        expected.write !== member.write
      ) throw invalid();
      byKey.delete(key);
      return expected.did;
    },
    finish(): void {
      if (byKey.size !== 0) throw invalid();
    },
  };
}

/** Require the reference PDS mapping to preserve this exact DID. */
export function referenceMemberKey(did: unknown): string {
  if (!isSpaceDid(did)) throw invalid();
  // This is the reference PDS mapping, not general percent decoding.
  const rkey = did.replace(/%3A/g, ":");
  const decoded = rkey.replace(/^(did:web:[^:]+):(\d+)$/, "$1%3A$2");
  const key = `${MEMBER_PREFIX}${rkey}`;
  if (!isValidRecordKey(rkey) || decoded !== did || key.length > 830) {
    throw invalid();
  }
  return key;
}

function invalid(): Error {
  return new Error("Invalid expected Space membership");
}
