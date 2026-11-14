import { isValidRecordKey, isValidTid, SpaceRef } from "@atproto/syntax-spaces";
import {
  type CborBudget,
  decodeCanonicalMap,
  encodeCanonicalMap,
  measureCanonicalMap,
} from "./meta-archive-cbor";
import {
  copyBoundedBytes,
  MAX_KEY_LENGTH,
  MAX_META_ARCHIVE_BYTES,
  MAX_META_ENTRIES,
  MAX_META_LENGTH,
  MAX_VALUE_LENGTH,
  type MetaFrame,
  readMetaFrames,
  writeMetaFrames,
} from "./meta-archive-framing";
import {
  copyPlainArray,
  copyPlainRecord,
  copyPlainRecordWithExtensions,
} from "./plain-values";
import { parseSpacePolicy, type SpacePolicy } from "./policy";
import { isSpaceDid } from "./space-did";
import {
  captureExpectedSpaceMembers,
  type ExpectedSpaceMember,
  referenceMemberKey,
} from "./meta-archive-members";

const META_TYPE = "atproto-space-meta";
const MEMBER_TYPE = "com.atproto.memberspace.member";
const MEMBER_PREFIX = `${MEMBER_TYPE}/`;
const WRITER_PREFIX = "writer/";
const MAX_ITEMS = 400_000;

export type SpaceMetaMember = {
  readonly $type: typeof MEMBER_TYPE;
  readonly read: boolean;
  readonly write: boolean;
};
export type SpaceMetaPolicyState = {
  readonly key: string;
  readonly value: SpaceMetaMember;
};
export type SpaceMetaWriter = {
  readonly did: string;
  readonly repoRev: string;
  readonly data: Uint8Array;
  readonly spaceRev: string;
};
export type SpaceMetaArchive = {
  readonly space: string;
  readonly policy: SpacePolicy;
  readonly policyState: readonly SpaceMetaPolicyState[];
  readonly writers: readonly SpaceMetaWriter[];
};
export type SpaceMetaArchiveWithMembers =
  & Omit<SpaceMetaArchive, "policyState">
  & {
    readonly policyState: readonly {
      readonly did: string;
      readonly value: SpaceMetaMember;
    }[];
  };

export class SpaceMetaArchiveError extends Error {
  constructor(readonly code: "InvalidSpaceMeta" | "UnsupportedPolicy") {
    super(
      code === "UnsupportedPolicy"
        ? "Unsupported Space policy"
        : "Invalid Space metadata archive",
    );
    this.name = "SpaceMetaArchiveError";
  }
}

/**
 * Normalize like the reference importer. Member keys with multiple DID
 * method-specific segments are excluded because its percent-decoding mapping
 * cannot distinguish those segments from an encoded colon. This is not a
 * lossless backup or authorization.
 */
export function readSpaceMetaArchive(
  input: Uint8Array,
  expectedSpace: string,
): SpaceMetaArchive {
  return readArchive(input, expectedSpace, null).archive;
}

/**
 * Match every member to a separately authenticated, complete snapshot.
 * This verifies correspondence to the supplied snapshot, not its provenance.
 */
export function readSpaceMetaArchiveWithMembers(
  input: Uint8Array,
  expectedSpace: string,
  expectedMembers: readonly ExpectedSpaceMember[],
): SpaceMetaArchiveWithMembers {
  const result = readArchive(input, expectedSpace, { expectedMembers });
  return { ...result.archive, policyState: result.members };
}

function readArchive(
  input: Uint8Array,
  expectedSpace: string,
  expected: { expectedMembers: unknown } | null,
): {
  archive: SpaceMetaArchive;
  members: SpaceMetaArchiveWithMembers["policyState"];
} {
  try {
    const matcher = expected
      ? captureExpectedSpaceMembers(expected.expectedMembers)
      : null;
    if (!validSpace(expectedSpace)) throw invalid();
    const { metadata, pairs } = readMetaFrames(input);
    const budget: CborBudget = { remaining: MAX_ITEMS };
    const header = decodeCanonicalMap(metadata, budget);
    if (
      header.$type !== META_TYPE || header.ver !== 1 ||
      header.space !== expectedSpace
    ) throw invalid();
    if (!pairs.length) throw invalid();
    const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
    if (decoder.decode(pairs[0].key) !== "policy") throw invalid();
    const policy = normalizePolicy(decodeCanonicalMap(pairs[0].value, budget));
    const policyState: SpaceMetaPolicyState[] = [];
    const members: { did: string; value: SpaceMetaMember }[] = [];
    const writers: SpaceMetaWriter[] = [];
    const membersSeen = new Set<string>();
    const writersSeen = new Set<string>();
    let section: "policyState" | "writers" = "policyState";
    let previous: Uint8Array | null = null;
    for (const pair of pairs.slice(1)) {
      const key = decoder.decode(pair.key);
      const nextSection = key.startsWith(WRITER_PREFIX)
        ? "writers"
        : "policyState";
      if (section === "writers" && nextSection !== "writers") throw invalid();
      if (section !== nextSection) {
        section = nextSection;
        previous = null;
      }
      if (previous && compareBytes(previous, pair.key) >= 0) throw invalid();
      previous = pair.key;
      const value = decodeCanonicalMap(pair.value, budget);
      if (section === "writers") {
        const writer = normalizeWriter(key.slice(WRITER_PREFIX.length), value);
        if (writersSeen.has(writer.did)) throw invalid();
        writersSeen.add(writer.did);
        writers.push(writer);
      } else {
        const entry = normalizeMember(policy, key, value);
        const did = matcher ? matcher.match(key, entry.value) : memberDid(key);
        if (membersSeen.has(did)) throw invalid();
        membersSeen.add(did);
        if (matcher) members.push({ did, value: entry.value });
        else policyState.push(entry);
      }
    }
    matcher?.finish();
    return {
      archive: { space: expectedSpace, policy, policyState, writers },
      members,
    };
  } catch (error) {
    if (error instanceof SpaceMetaArchiveError) throw error;
    throw invalid();
  }
}

/** Build a normalized profile; callers separately authorize imports or exports. */
export function writeSpaceMetaArchive(input: SpaceMetaArchive): Uint8Array {
  return writeArchive(input, null);
}

/** Serialize members only when their exact DIDs survive the reference mapping. */
export function writeSpaceMetaArchiveWithMembers(
  input: SpaceMetaArchiveWithMembers,
): Uint8Array {
  try {
    const fields = copyPlainRecord(input, [
      "space",
      "policy",
      "policyState",
      "writers",
    ]);
    const entries = fields &&
      copyPlainArray(fields.policyState, MAX_META_ENTRIES);
    if (!fields || !entries) throw invalid();
    const expectedMembers: ExpectedSpaceMember[] = [];
    const keyBudget = { remaining: MAX_META_ARCHIVE_BYTES };
    const policyState = entries.map((entry) => {
      const item = copyPlainRecord(entry, ["did", "value"]);
      const value = item &&
        copyPlainRecordWithExtensions(item.value, 64, keyBudget);
      if (
        !item || !value || typeof item.did !== "string" ||
        value.$type !== MEMBER_TYPE ||
        typeof value.read !== "boolean" || typeof value.write !== "boolean"
      ) throw invalid();
      expectedMembers.push({
        did: item.did,
        read: value.read,
        write: value.write,
      });
      return {
        key: referenceMemberKey(item.did),
        value: { $type: MEMBER_TYPE, read: value.read, write: value.write },
      };
    });
    return writeArchive({
      space: fields.space,
      policy: fields.policy,
      policyState,
      writers: fields.writers,
    }, { expectedMembers });
  } catch (error) {
    if (error instanceof SpaceMetaArchiveError) throw error;
    throw invalid();
  }
}

function writeArchive(
  input: unknown,
  expected: { expectedMembers: unknown } | null,
): Uint8Array {
  try {
    const matcher = expected
      ? captureExpectedSpaceMembers(expected.expectedMembers)
      : null;
    const fields = copyPlainRecord(input, [
      "space",
      "policy",
      "policyState",
      "writers",
    ]);
    if (!fields || !validSpace(fields.space)) throw invalid();
    const policy = normalizePolicy(fields.policy);
    const state = copyPlainArray(fields.policyState, MAX_META_ENTRIES);
    const writerValues = copyPlainArray(fields.writers, MAX_META_ENTRIES);
    if (
      !state || !writerValues ||
      1 + state.length + writerValues.length > MAX_META_ENTRIES
    ) throw invalid();
    const membersSeen = new Set<string>();
    const keyBudget = { remaining: MAX_META_ARCHIVE_BYTES };
    const policyState = state.map((entry) => {
      const entryFields = copyPlainRecord(entry, ["key", "value"]);
      if (!entryFields || typeof entryFields.key !== "string") throw invalid();
      const normalized = normalizeMember(
        policy,
        entryFields.key,
        entryFields.value,
        keyBudget,
      );
      const did = matcher
        ? matcher.match(normalized.key, normalized.value)
        : memberDid(normalized.key);
      if (membersSeen.has(did)) throw invalid();
      membersSeen.add(did);
      return normalized;
    });
    matcher?.finish();
    const writersSeen = new Set<string>();
    const writers = writerValues.map((writer) => {
      const writerFields = copyPlainRecordWithExtensions(writer, 64, keyBudget);
      if (!writerFields || typeof writerFields.did !== "string") {
        throw invalid();
      }
      const normalized = normalizeWriter(writerFields.did, writerFields);
      if (writersSeen.has(normalized.did)) throw invalid();
      writersSeen.add(normalized.did);
      return normalized;
    });
    const budget: CborBudget = { remaining: MAX_ITEMS };
    const size = { remaining: MAX_META_ARCHIVE_BYTES - 5 };
    const header = { $type: META_TYPE, ver: 1, space: fields.space };
    const headerSize = measureCanonicalMap(header, MAX_META_LENGTH);
    reserve(size, varintLength(headerSize) + headerSize);
    const metadata = encodeCanonicalMap(header, MAX_META_LENGTH, budget);
    if (metadata.length !== headerSize) throw invalid();
    const encoder = new TextEncoder();
    const policyFrame = frame(encoder, "policy", policy, budget, size);
    const stateFrames = policyState.map((entry) =>
      frame(encoder, entry.key, entry.value, budget, size)
    );
    const writerFrames = writers.map(({ did, repoRev, data, spaceRev }) =>
      frame(
        encoder,
        `${WRITER_PREFIX}${did}`,
        { repoRev, data, spaceRev },
        budget,
        size,
      )
    );
    sortUnique(stateFrames);
    sortUnique(writerFrames);
    return writeMetaFrames(metadata, [
      policyFrame,
      ...stateFrames,
      ...writerFrames,
    ]);
  } catch (error) {
    if (error instanceof SpaceMetaArchiveError) throw error;
    throw invalid();
  }
}

function normalizePolicy(value: unknown): SpacePolicy {
  const result = parseSpacePolicy(value);
  if (result.tag === "unsupported") {
    throw new SpaceMetaArchiveError("UnsupportedPolicy");
  }
  if (result.tag !== "valid") throw invalid();
  return result.policy;
}

function normalizeMember(
  policy: SpacePolicy,
  key: string,
  value: unknown,
  keyBudget?: { remaining: number },
): SpaceMetaPolicyState {
  if (policy.$type !== "com.atproto.memberspace.policy") throw invalid();
  const fields = copyPlainRecordWithExtensions(value, 64, keyBudget);
  if (
    !fields || fields.$type !== MEMBER_TYPE ||
    typeof fields.read !== "boolean" || typeof fields.write !== "boolean"
  ) {
    throw invalid();
  }
  return {
    key,
    value: { $type: MEMBER_TYPE, read: fields.read, write: fields.write },
  };
}

function memberDid(key: string): string {
  if (key.length > 830 || !key.startsWith(MEMBER_PREFIX)) throw invalid();
  const recordKey = key.slice(MEMBER_PREFIX.length);
  if (!isValidRecordKey(recordKey)) throw invalid();
  if (!/^did:[a-z0-9]+:[^:]+$/.test(recordKey) || !isSpaceDid(recordKey)) {
    throw invalid();
  }
  return recordKey;
}

function normalizeWriter(did: string, value: unknown): SpaceMetaWriter {
  if (!isSpaceDid(did)) throw invalid();
  const fields = copyPlainRecordWithExtensions(value, 64);
  if (
    !fields || typeof fields.repoRev !== "string" ||
    !isValidTid(fields.repoRev) ||
    typeof fields.spaceRev !== "string" || !isValidTid(fields.spaceRev)
  ) throw invalid();
  const data = copyBoundedBytes(fields.data, 32);
  if (data.length !== 32) throw invalid();
  return { did, repoRev: fields.repoRev, data, spaceRev: fields.spaceRev };
}

function validSpace(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 8192) return false;
  try {
    const reference = SpaceRef.parse(value);
    return reference.toString() === value && isSpaceDid(reference.spaceDid);
  } catch {
    return false;
  }
}

function frame(
  encoder: TextEncoder,
  key: string,
  value: object,
  budget: CborBudget,
  size: { remaining: number },
): MetaFrame {
  if (key.length > MAX_KEY_LENGTH) throw invalid();
  const encodedKey = encoder.encode(key);
  if (encodedKey.length > MAX_KEY_LENGTH) throw invalid();
  const map = value as Record<string, unknown>;
  const valueSize = measureCanonicalMap(map, MAX_VALUE_LENGTH);
  reserve(
    size,
    1 + varintLength(encodedKey.length) + encodedKey.length +
      varintLength(valueSize) + valueSize,
  );
  const encodedValue = encodeCanonicalMap(map, MAX_VALUE_LENGTH, budget);
  if (encodedValue.length !== valueSize) throw invalid();
  return { key: encodedKey, value: encodedValue };
}

function varintLength(value: number): number {
  let count = 1;
  while (value >= 128) {
    count++;
    value = Math.floor(value / 128);
  }
  return count;
}
function reserve(budget: { remaining: number }, size: number): void {
  budget.remaining -= size;
  if (budget.remaining < 0) throw invalid();
}
function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const count = Math.min(left.length, right.length);
  for (let index = 0; index < count; index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}
function sortUnique(frames: MetaFrame[]): void {
  frames.sort((left, right) => compareBytes(left.key, right.key));
  for (let index = 1; index < frames.length; index++) {
    if (compareBytes(frames[index - 1].key, frames[index].key) === 0) {
      throw invalid();
    }
  }
}
function invalid(): SpaceMetaArchiveError {
  return new SpaceMetaArchiveError("InvalidSpaceMeta");
}
