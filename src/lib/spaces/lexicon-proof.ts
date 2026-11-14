import { parseDidKey } from "@atproto/crypto-spaces";
import { decode, encode } from "@atproto/lex-cbor";
import { def, readCarStream, verifyCommitSig } from "@atproto/repo";
import {
  isValidDid,
  isValidNsid,
  isValidRecordKey,
  isValidTid,
} from "@atproto/syntax-spaces";
import { sha256 } from "@noble/hashes/sha2.js";
import { base32 } from "multiformats/bases/base32";
import { CID } from "multiformats/cid";
import { isCanonicalRepoCid, parseCanonicalRepoCid } from "./repo-cid";
import { validateSpaceLexiconSemantics } from "./lexicon-semantics";

const SCHEMA_COLLECTION = "com.atproto.lexicon.schema";
const MAX_CAR_BYTES = 4 * 1024 * 1024;
const MAX_BLOCK_BYTES = 1024 * 1024;
const MAX_HEADER_BYTES = 4096;
const MAX_BLOCKS = 256;
const MAX_PATH_DEPTH = 64;
const MAX_PATH_ENTRIES = 16_384;
const MAX_CBOR_DEPTH = 64;
const MAX_CBOR_ITEMS = 50_000;

export type LexiconProofInput = {
  readonly nsid: string;
  readonly publisherDid: string;
  readonly signingKey: string;
  readonly currentCommitCid: string;
  readonly proof: Uint8Array;
};

export type ProvenSpaceMain = {
  readonly spaceType: string;
  readonly publisherDid: string;
  readonly recordCid: string;
  readonly key: string;
  readonly title?: string;
  readonly collections: readonly string[];
};

export type LexiconProofResult =
  | { readonly tag: "invalid" }
  | {
    readonly tag: "unsupported";
    readonly headCid: string;
    readonly revision: string;
    readonly recordCid: string;
  }
  | {
    readonly tag: "proven";
    readonly uri: string;
    readonly headCid: string;
    readonly revision: string;
    readonly definitions: "main-only" | "additional";
    readonly main: ProvenSpaceMain;
  };

/**
 * Verify a schema record in a CAR against an independently authenticated head.
 * The caller must establish the NSID-to-DID binding, current DID signing key,
 * and freshness/authenticity of currentCommitCid. This function performs no
 * DNS, DID resolution, network access, or authorization. It validates the
 * traversed MST path; a record proof cannot attest omitted sibling subtrees.
 * A proven result validates the supported semantic subset on the exact
 * CID-bound record. Unsupported forms never return a usable declaration.
 */
export async function verifyLexiconProofAtTrustedHead(
  input: LexiconProofInput,
): Promise<LexiconProofResult> {
  if (!validInput(input)) return { tag: "invalid" };
  const { nsid, publisherDid, signingKey, currentCommitCid } = input;
  const proof = Uint8Array.from(input.proof);

  try {
    const key = parseDidKey(signingKey);
    if (key.jwtAlg !== "ES256" && key.jwtAlg !== "ES256K") {
      return { tag: "invalid" };
    }
    const expectedHead = parseCanonicalRepoCid(currentCommitCid);
    if (!expectedHead || !validCarFrames(proof)) {
      return { tag: "invalid" };
    }

    const reader = await readCarStream(proof);
    const blocks = new Map<string, Uint8Array>();
    try {
      if (reader.roots.length === 0 || !reader.roots[0].equals(expectedHead)) {
        return { tag: "invalid" };
      }
      for await (const block of reader) {
        const id = base32.encode(block.cid.bytes);
        if (block.bytes.byteLength > MAX_BLOCK_BYTES) {
          return { tag: "invalid" };
        }
        const previous = blocks.get(id);
        if (previous) {
          if (
            previous.byteLength !== block.bytes.byteLength ||
            previous.some((byte, index) => byte !== block.bytes[index])
          ) return { tag: "invalid" };
          continue;
        }
        if (blocks.size >= MAX_BLOCKS) return { tag: "invalid" };
        blocks.set(id, Uint8Array.from(block.bytes));
      }
    } finally {
      await reader.destroy();
    }

    const commitBytes = blocks.get(base32.encode(expectedHead.bytes));
    if (!commitBytes) return { tag: "invalid" };
    const rawCommit = decodeCanonical(commitBytes);
    if (!hasKeys(rawCommit, ["did", "version", "data", "rev", "prev", "sig"])) {
      return { tag: "invalid" };
    }
    const parsedCommit = def.commit.schema.safeParse(rawCommit);
    if (!parsedCommit.success) return { tag: "invalid" };
    const commit = parsedCommit.data;
    const rootCid = CID.asCID(commit.data);
    if (
      commit.did !== publisherDid || !isValidTid(commit.rev) ||
      commit.sig.byteLength !== 64 ||
      !isCanonicalRepoCid(rootCid) ||
      (commit.prev !== null && !isCanonicalRepoCid(CID.asCID(commit.prev))) ||
      !await verifyCommitSig(commit, signingKey)
    ) return { tag: "invalid" };

    const targetPath = `${SCHEMA_COLLECTION}/${nsid}`;
    const targetCid = findRecordCid(
      blocks,
      rootCid,
      targetPath,
    );
    if (!targetCid) return { tag: "invalid" };
    const recordBytes = blocks.get(base32.encode(targetCid.bytes));
    if (!recordBytes) return { tag: "invalid" };
    const record = decodeCanonical(recordBytes);
    if (
      !isObject(record) || record.$type !== SCHEMA_COLLECTION ||
      record.id !== nsid
    ) return { tag: "invalid" };
    if (
      !isObject(record.defs) || !isObject(record.defs.main) ||
      record.defs.main.type !== "space"
    ) return { tag: "invalid" };
    const semantics = validateSpaceLexiconSemantics(record);
    if (semantics.tag === "invalid") return { tag: "invalid" };
    const recordCid = base32.encode(targetCid.bytes);
    if (semantics.tag === "unsupported") {
      return Object.freeze({
        tag: "unsupported",
        headCid: base32.encode(expectedHead.bytes),
        revision: commit.rev,
        recordCid,
      });
    }
    const main = record.defs.main;
    if (
      typeof main.key !== "string" || !Array.isArray(main.collections) ||
      !main.collections.every((value: unknown) =>
        typeof value === "string" && isValidNsid(value)
      ) ||
      (main.title !== undefined && typeof main.title !== "string")
    ) return { tag: "invalid" };
    const mainDeclaration: ProvenSpaceMain = Object.freeze({
      spaceType: nsid,
      publisherDid,
      recordCid,
      key: main.key,
      ...(main.title === undefined ? {} : { title: main.title }),
      collections: Object.freeze([...main.collections]),
    });
    return Object.freeze({
      tag: "proven",
      uri: `at://${publisherDid}/${SCHEMA_COLLECTION}/${nsid}`,
      headCid: base32.encode(expectedHead.bytes),
      revision: commit.rev,
      definitions: Object.keys(record.defs).length === 1
        ? "main-only"
        : "additional",
      main: mainDeclaration,
    });
  } catch {
    return { tag: "invalid" };
  }
}

function validInput(value: LexiconProofInput): boolean {
  return isObject(value) && typeof value.nsid === "string" &&
    isValidNsid(value.nsid) &&
    isValidRecordKey(value.nsid) && typeof value.publisherDid === "string" &&
    isValidDid(value.publisherDid) &&
    typeof value.signingKey === "string" && value.signingKey.length <= 140 &&
    typeof value.currentCommitCid === "string" &&
    value.currentCommitCid.length <= 128 &&
    value.proof instanceof Uint8Array && value.proof.byteLength > 0 &&
    value.proof.byteLength <= MAX_CAR_BYTES;
}

// Preflight framing before the SDK reads varints; its reader otherwise scans an
// arbitrarily long run of continuation bytes. All lengths are bounded by 4 MiB.
function validCarFrames(bytes: Uint8Array): boolean {
  let offset = 0;
  let frames = 0;
  while (offset < bytes.length) {
    let length = 0;
    let multiplier = 1;
    let last = 0;
    let count = 0;
    do {
      if (offset >= bytes.length || count === 4) return false;
      last = bytes[offset++];
      length += (last & 127) * multiplier;
      multiplier *= 128;
      count++;
    } while (last & 128);
    if (
      (count > 1 && last === 0) || length === 0 ||
      length > bytes.length - offset
    ) return false;
    if (frames === 0) {
      if (
        length > MAX_HEADER_BYTES ||
        !boundedCbor(bytes.subarray(offset, offset + length))
      ) return false;
      decodeCanonical(bytes.subarray(offset, offset + length));
    } else if (
      length < 36 || length > MAX_BLOCK_BYTES + 36 || frames > MAX_BLOCKS
    ) return false;
    offset += length;
    frames++;
  }
  return frames >= 2;
}

/** Bound the shape before handing hostile bytes to a recursive CBOR decoder. */
function boundedCbor(bytes: Uint8Array): boolean {
  const pending = [1];
  let offset = 0;
  let items = 0;
  while (pending.length) {
    if (pending[pending.length - 1] === 0) {
      pending.pop();
      continue;
    }
    pending[pending.length - 1]--;
    if (++items > MAX_CBOR_ITEMS || offset >= bytes.length) return false;
    const initial = bytes[offset++];
    const major = initial >> 5;
    const additional = initial & 31;
    let argument = additional;
    if (additional >= 24) {
      const length = additional === 24
        ? 1
        : additional === 25
        ? 2
        : additional === 26
        ? 4
        : additional === 27
        ? 8
        : 0;
      if (length === 0 || offset + length > bytes.length) return false;
      argument = 0;
      for (let i = 0; i < length; i++) {
        argument = argument * 256 + bytes[offset++];
      }
      if (!Number.isSafeInteger(argument)) return false;
    }
    if (major === 2 || major === 3) {
      if (argument > bytes.length - offset) return false;
      offset += argument;
    } else if (major === 4 || major === 5 || major === 6) {
      const children = major === 6 ? 1 : argument * (major === 5 ? 2 : 1);
      if (
        !Number.isSafeInteger(children) || children > MAX_CBOR_ITEMS ||
        pending.length >= MAX_CBOR_DEPTH
      ) return false;
      pending.push(children);
    }
  }
  return offset === bytes.length;
}

function decodeCanonical(bytes: Uint8Array): unknown {
  if (!boundedCbor(bytes)) throw new Error("CBOR limits exceeded");
  const value = decode(bytes);
  const canonical = encode(value);
  if (
    canonical.length !== bytes.length ||
    canonical.some((byte, i) => byte !== bytes[i])
  ) {
    throw new Error("Non-canonical CBOR");
  }
  return value;
}

type Entry = {
  readonly key: string;
  readonly value: CID;
  readonly tree: CID | null;
};

function findRecordCid(
  blocks: ReadonlyMap<string, Uint8Array>,
  root: CID,
  target: string,
): CID | null {
  let nodeCid = root;
  let lower: string | null = null;
  let upper: string | null = null;
  let expectedLayer: number | null = null;
  let pathEntries = 0;
  const seen = new Set<string>();
  for (let depth = 0; depth < MAX_PATH_DEPTH; depth++) {
    const id = base32.encode(nodeCid.bytes);
    if (seen.has(id)) return null;
    seen.add(id);
    const bytes = blocks.get(id);
    if (!bytes) return null;
    const node = decodeCanonical(bytes);
    if (!hasKeys(node, ["l", "e"]) || !Array.isArray(node.e)) return null;
    pathEntries += node.e.length;
    if (pathEntries > MAX_PATH_ENTRIES) return null;
    const left = nullableCborCid(node.l);
    if (left === undefined) return null;
    const entries: Entry[] = [];
    let previous = "";
    let layer: number | null = expectedLayer;
    for (const raw of node.e) {
      if (
        !hasKeys(raw, ["p", "k", "v", "t"]) || !Number.isSafeInteger(raw.p) ||
        typeof raw.p !== "number" || raw.p < 0 || raw.p > previous.length ||
        !(raw.k instanceof Uint8Array) ||
        raw.k.length > 1024
      ) return null;
      if (raw.k.some((byte) => byte > 0x7f)) return null;
      const key = previous.slice(0, raw.p) + String.fromCharCode(...raw.k);
      if (
        !validPath(key) || (previous && previous >= key) ||
        commonPrefix(previous, key) !== raw.p ||
        (lower !== null && key <= lower) || (upper !== null && key >= upper)
      ) return null;
      const keyLayer = pathLayer(key);
      if (layer === null) layer = keyLayer;
      if (layer !== keyLayer) return null;
      const value = CID.asCID(raw.v);
      const tree = nullableCborCid(raw.t);
      if (!isCanonicalRepoCid(value) || tree === undefined) return null;
      entries.push({ key, value, tree });
      previous = key;
    }
    if (layer === null || layer < 0 || (depth === 0 && entries.length === 0)) {
      return null;
    }
    if (
      layer === 0 &&
      (left !== null || entries.some((entry) => entry.tree !== null))
    ) return null;
    const childIds = new Set<string>();
    for (const child of [left, ...entries.map((entry) => entry.tree)]) {
      if (!child) continue;
      const childId = base32.encode(child.bytes);
      if (seen.has(childId) || childIds.has(childId)) return null;
      childIds.add(childId);
    }
    let child = left;
    let nextLower: string | null = lower;
    let nextUpper: string | null = upper;
    for (const entry of entries) {
      if (target === entry.key) return entry.value;
      if (target < entry.key) {
        nextUpper = entry.key;
        break;
      }
      child = entry.tree;
      nextLower = entry.key;
    }
    if (!child || layer === 0) return null;
    nodeCid = child;
    lower = nextLower;
    upper = nextUpper;
    expectedLayer = layer - 1;
  }
  return null;
}

function validPath(path: string): boolean {
  if (path.length > 1024) return false;
  const parts = path.split("/");
  return parts.length === 2 && isValidNsid(parts[0]) &&
    isValidRecordKey(parts[1]);
}

function commonPrefix(first: string, second: string): number {
  let length = 0;
  while (length < first.length && first[length] === second[length]) length++;
  return length;
}

function pathLayer(path: string): number {
  const digest = sha256(new TextEncoder().encode(path));
  let layer = 0;
  for (const byte of digest) {
    for (let shift = 6; shift >= 0; shift -= 2) {
      if (((byte >> shift) & 3) !== 0) return layer;
      layer++;
    }
  }
  return layer;
}

function nullableCborCid(value: unknown): CID | null | undefined {
  if (value === null) return null;
  const cid = CID.asCID(value);
  return isCanonicalRepoCid(cid) ? cid : undefined;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasKeys(
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> {
  return isObject(value) && Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}
