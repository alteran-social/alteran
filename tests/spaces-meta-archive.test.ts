import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { encode } from "@atproto/lex-cbor";
import { readSpaceMetaStar, writeSpaceMetaStar } from "@atproto/space";
import {
  readSpaceMetaArchive,
  type SpaceMetaArchive,
  SpaceMetaArchiveError,
  writeSpaceMetaArchive,
} from "../src/lib/spaces/meta-archive";
import { MAX_META_ARCHIVE_BYTES } from "../src/lib/spaces/meta-archive-framing";

const SPACE = "at://did:example:alice/space/com.example.notes/archive";
const REVISION = "3kbcq3p7ad42b";
const MEMBER_TYPE = "com.atproto.memberspace.member";
const POLICY = {
  $type: "com.atproto.memberspace.policy",
  publicRead: true,
  publicWrite: false,
  publishPolicy: false,
  publishMembers: false,
} as const;
const MEMBER = { $type: MEMBER_TYPE, read: true, write: false } as const;
const WRITER = {
  did: "did:example:bob",
  repoRev: REVISION,
  data: new Uint8Array(32).fill(7),
  spaceRev: REVISION,
};
const archive: SpaceMetaArchive = {
  space: SPACE,
  policy: POLICY,
  policyState: [
    { key: `${MEMBER_TYPE}/did:example:z`, value: MEMBER },
    { key: `${MEMBER_TYPE}/did:example:a`, value: MEMBER },
  ],
  writers: [WRITER],
};
const header = () =>
  encode({ $type: "atproto-space-meta", ver: 1, space: SPACE });
const text = (value: string) => new TextEncoder().encode(value);
const map = (value: unknown) => encode(value as never);

type RawPair = readonly [string | Uint8Array, Uint8Array];
function rawArchive(meta: Uint8Array, entries: readonly RawPair[]): Uint8Array {
  const chunks: number[] = [0x2a, 0x6c, 1, 0];
  const length = (value: number) => {
    while (value >= 128) {
      chunks.push((value % 128) | 128);
      value = Math.floor(value / 128);
    }
    chunks.push(value);
  };
  length(meta.length);
  chunks.push(...meta);
  for (const [rawKey, value] of entries) {
    const key = typeof rawKey === "string" ? text(rawKey) : rawKey;
    chunks.push(1);
    length(key.length);
    for (const byte of key) chunks.push(byte);
    length(value.length);
    for (const byte of value) chunks.push(byte);
  }
  chunks.push(0);
  return Uint8Array.from(chunks);
}
async function collect(chunks: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  let size = 0;
  for await (const part of chunks) {
    parts.push(part);
    size += part.length;
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}
function rejects(bytes: Uint8Array, code = "InvalidSpaceMeta") {
  try {
    readSpaceMetaArchive(bytes, SPACE);
    throw new Error("Expected an invalid archive");
  } catch (error) {
    expect(error).toBeInstanceOf(SpaceMetaArchiveError);
    expect((error as SpaceMetaArchiveError).code).toBe(code);
  }
}

describe("Space host metadata archives", () => {
  it("round-trips through the reference SDK in both directions", async () => {
    const encoded = writeSpaceMetaArchive(archive);
    const decodedByReference = await readSpaceMetaStar([encoded]);
    expect(decodedByReference.space).toBe(SPACE);
    expect(decodedByReference.policyState.map((entry) => entry.key)).toEqual([
      `${MEMBER_TYPE}/did:example:a`,
      `${MEMBER_TYPE}/did:example:z`,
    ]);
    expect(decodedByReference.writers[0].data).toEqual(WRITER.data);
    const reference = await collect(writeSpaceMetaStar({
      ...archive,
      policyState: [...archive.policyState],
      writers: [...archive.writers],
    } as never));
    const decoded = readSpaceMetaArchive(reference, SPACE);
    expect(decoded.policy).toEqual(POLICY);
    expect(decoded.policyState.map((entry) => entry.key)).toEqual([
      `${MEMBER_TYPE}/did:example:a`,
      `${MEMBER_TYPE}/did:example:z`,
    ]);
    expect(decoded.writers[0]).toEqual(WRITER);
  });

  it("normalizes supported extensions and copies writer bytes", () => {
    const bytes = rawArchive(
      map({
        $type: "atproto-space-meta",
        ver: 1,
        space: SPACE,
        future: "ignored",
      }),
      [
        ["policy", map({ ...POLICY, future: { extra: 1 } })],
        [`${MEMBER_TYPE}/did:example:a`, map({ ...MEMBER, future: "ignored" })],
        [
          "writer/did:example:bob",
          map({ ...WRITER, did: "ignored", future: true }),
        ],
      ],
    );
    const decoded = readSpaceMetaArchive(bytes, SPACE);
    expect(decoded.policy).toEqual(POLICY);
    expect(decoded.policyState[0].value).toEqual(MEMBER);
    expect(decoded.writers[0]).toEqual(WRITER);
    bytes.fill(0);
    expect(decoded.writers[0].data).toEqual(new Uint8Array(32).fill(7));
  });

  it("binds the exact Space and rejects unknown policy or policy state", () => {
    const bytes = writeSpaceMetaArchive(archive);
    expect(() => readSpaceMetaArchive(bytes, `${SPACE}-other`)).toThrow();
    rejects(
      rawArchive(header(), [["policy", map({ $type: "com.example.unknown" })]]),
      "UnsupportedPolicy",
    );
    rejects(
      rawArchive(header(), [["policy", map(POLICY)], [
        "com.example.unknown/key",
        map(MEMBER),
      ]]),
    );
    rejects(
      rawArchive(header(), [[
        "policy",
        map({ $type: "com.atproto.personalspace.policy" }),
      ], [`${MEMBER_TYPE}/did:example:a`, map(MEMBER)]]),
    );
  });

  it("rejects missing, duplicate or out-of-order sections and entries", () => {
    const p: RawPair = ["policy", map(POLICY)];
    const a: RawPair = [`${MEMBER_TYPE}/did:example:a`, map(MEMBER)];
    const z: RawPair = [`${MEMBER_TYPE}/did:example:z`, map(MEMBER)];
    const w: RawPair = ["writer/did:example:bob", map(WRITER)];
    for (
      const entries of [[a], [p, p], [p, a, a], [p, z, a], [p, w, a], [p, w, w]]
    ) {
      rejects(rawArchive(header(), entries));
    }
    expect(() =>
      writeSpaceMetaArchive({ ...archive, writers: [WRITER, WRITER] })
    ).toThrow();
  });

  it("validates member and writer identities and writer commit fields", () => {
    const p: RawPair = ["policy", map(POLICY)];
    for (
      const entry of [
        [`${MEMBER_TYPE}/not-a-did`, map(MEMBER)],
        [`${MEMBER_TYPE}/did:example:a`, map({ read: true, write: false })],
        [`${MEMBER_TYPE}/did:example:a`, map({ ...MEMBER, write: "yes" })],
        ["writer/not-a-did", map(WRITER)],
        [
          "writer/did:example:bob",
          map({ ...WRITER, data: new Uint8Array(31) }),
        ],
        ["writer/did:example:bob", map({ ...WRITER, repoRev: "bad" })],
      ] as RawPair[]
    ) rejects(rawArchive(header(), [p, entry]));
    const localhost = `${MEMBER_TYPE}/did:web:localhost`;
    const decoded = readSpaceMetaArchive(
      rawArchive(header(), [p, [localhost, map(MEMBER)]]),
      SPACE,
    );
    expect(decoded.policyState[0].key).toBe(localhost);
    for (const ambiguous of ["did:web:localhost:2583", "did:example:a:b"]) {
      const key = `${MEMBER_TYPE}/${ambiguous}`;
      rejects(rawArchive(header(), [p, [key, map(MEMBER)]]));
      expect(() =>
        writeSpaceMetaArchive({
          ...archive,
          policyState: [{ key, value: MEMBER }],
        })
      ).toThrow();
    }
  });

  it("rejects noncanonical CBOR values, malformed UTF-8 and BOM-prefixed keys", () => {
    const noncanonicalMap = Uint8Array.of(
      0xa2,
      0x61,
      0x62,
      0xf5,
      0x61,
      0x61,
      0xf5,
    );
    rejects(rawArchive(header(), [["policy", noncanonicalMap]]));
    rejects(rawArchive(header(), [[Uint8Array.of(0xff), map(POLICY)]]));
    rejects(
      rawArchive(header(), [[
        Uint8Array.of(0xef, 0xbb, 0xbf, ...text("policy")),
        map(POLICY),
      ]]),
    );
    const unsupportedFloat = Uint8Array.of(0xa1, 0x61, 0x61, 0xf9, 0x3c, 0x00);
    rejects(rawArchive(header(), [["policy", unsupportedFloat]]));
    const canonicalHeader = header();
    const position = canonicalHeader.findIndex((byte, index) =>
      byte === 0x63 && canonicalHeader[index + 1] === 0x76 &&
      canonicalHeader[index + 2] === 0x65 &&
      canonicalHeader[index + 3] === 0x72 &&
      canonicalHeader[index + 4] === 1
    );
    expect(position).toBeGreaterThanOrEqual(0);
    const noncanonicalHeader = new Uint8Array(canonicalHeader.length + 1);
    noncanonicalHeader.set(canonicalHeader.subarray(0, position + 4));
    noncanonicalHeader.set([0x18, 1], position + 4);
    noncanonicalHeader.set(
      canonicalHeader.subarray(position + 5),
      position + 6,
    );
    rejects(rawArchive(noncanonicalHeader, [["policy", map(POLICY)]]));
    rejects(
      rawArchive(map({ $type: "atproto-space-repo", ver: 1, space: SPACE }), [[
        "policy",
        map(POLICY),
      ]]),
    );
  });

  it("rejects truncated, trailing, oversized and noncanonical STAR framing", () => {
    const good = rawArchive(header(), [["policy", map(POLICY)]]);
    rejects(good.slice(0, -1));
    const trailing = new Uint8Array(good.length + 1);
    trailing.set(good);
    rejects(trailing);
    const paddedLength = new Uint8Array(good.length + 1);
    paddedLength.set(good.subarray(0, 4));
    paddedLength[4] = good[4] | 0x80;
    paddedLength[5] = 0;
    paddedLength.set(good.subarray(5), 6);
    rejects(paddedLength);
    const wrongControl = good.slice();
    wrongControl[wrongControl.length - 1] = 2;
    rejects(wrongControl);
    rejects(new Uint8Array(MAX_META_ARCHIVE_BYTES + 1));
    const keyTooLong = "a".repeat(4097);
    rejects(
      rawArchive(header(), [["policy", map(POLICY)], [
        keyTooLong,
        map(MEMBER),
      ]]),
    );
  });

  it("bounds nested and aggregate CBOR complexity before decoding", () => {
    let nested: unknown = null;
    for (let index = 0; index < 101; index++) nested = [nested];
    rejects(
      rawArchive(header(), [["policy", map({ ...POLICY, extra: nested })]]),
    );
    const large = Array.from({ length: 100_001 }, () => null);
    rejects(
      rawArchive(header(), [["policy", map({ ...POLICY, extra: large })]]),
    );
    const array = Array.from({ length: 80_000 }, () => null);
    const many: RawPair[] = [["policy", map(POLICY)]];
    for (let index = 0; index < 6; index++) {
      many.push([
        `${MEMBER_TYPE}/did:example:${index}`,
        map({ ...MEMBER, extra: array }),
      ]);
    }
    rejects(rawArchive(header(), many));
  });

  it("rejects oversized or shared writer buffers before copying", () => {
    expect(() =>
      writeSpaceMetaArchive({
        ...archive,
        writers: [{ ...WRITER, data: new Uint8Array(2_000_000) }],
      })
    ).toThrow();
    if (typeof SharedArrayBuffer !== "undefined") {
      const data = new Uint8Array(new SharedArrayBuffer(32));
      expect(() =>
        writeSpaceMetaArchive({ ...archive, writers: [{ ...WRITER, data }] })
      ).toThrow();
      const sharedArchive = new Uint8Array(new SharedArrayBuffer(8));
      expect(() => readSpaceMetaArchive(sharedArchive, SPACE)).toThrow();
    }
  });

  it("accepts the metadata and value limits and rejects larger frames", () => {
    const sized = (target: number, build: (length: number) => Uint8Array) => {
      let length = target - 256;
      for (;;) {
        const bytes = build(length);
        if (bytes.length === target) return bytes;
        length += target - bytes.length;
      }
    };
    const exactHeader = sized(
      65_536,
      (length) =>
        map({
          $type: "atproto-space-meta",
          ver: 1,
          space: SPACE,
          extra: "x".repeat(length),
        }),
    );
    const exactValue = sized(
      1_048_576,
      (length) => map({ ...POLICY, extra: "x".repeat(length) }),
    );
    const parsed = readSpaceMetaArchive(
      rawArchive(exactHeader, [["policy", exactValue]]),
      SPACE,
    );
    expect(parsed.policy).toEqual(POLICY);
    rejects(rawArchive(exactHeader, [["policy", new Uint8Array(1_048_577)]]));
    rejects(rawArchive(new Uint8Array(65_537), [["policy", map(POLICY)]]));
  });

  it("enforces the aggregate archive limit while encoding many writers", () => {
    const longId = "a".repeat(2000);
    const writers = Array.from({ length: 8500 }, (_, index) => ({
      ...WRITER,
      did: `did:example:${longId}${index.toString().padStart(4, "0")}`,
    }));
    expect(() => writeSpaceMetaArchive({ ...archive, writers })).toThrow();
  });

  it("rejects getters, sparse lists and input with too many entries", () => {
    const policy = {
      get $type() {
        throw new Error("must not run");
      },
    };
    expect(() => writeSpaceMetaArchive({ ...archive, policy } as never))
      .toThrow();
    const sparse = new Array(1);
    expect(() => writeSpaceMetaArchive({ ...archive, writers: sparse }))
      .toThrow();
    expect(() =>
      writeSpaceMetaArchive({
        ...archive,
        writers: new Array(10_001).fill(WRITER),
      })
    ).toThrow();
  });
});
