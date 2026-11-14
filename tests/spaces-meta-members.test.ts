import { expect } from "@std/expect";
import { encode } from "@atproto/lex-cbor";
import { describe, it } from "./helpers/bdd";
import {
  readSpaceMetaArchive,
  readSpaceMetaArchiveWithMembers,
  writeSpaceMetaArchiveWithMembers,
} from "../src/lib/spaces/meta-archive";
import { writeMetaFrames } from "../src/lib/spaces/meta-archive-framing";

const SPACE = "at://did:example:alice/space/com.example.notes/archive";
const PREFIX = "com.atproto.memberspace.member/";
const POLICY = {
  $type: "com.atproto.memberspace.policy",
  publicRead: true,
  publicWrite: false,
  publishPolicy: false,
  publishMembers: false,
} as const;
const members = [
  { did: "did:example:a:b", read: true, write: false },
  { did: "did:web:localhost%3A2583", read: false, write: true },
  { did: "did:web:localhost:path", read: true, write: true },
];
const keys = [
  "did:example:a:b",
  "did:web:localhost:2583",
  "did:web:localhost:path",
];

function archive(
  options: {
    entries?: { key: string; read: boolean; write: boolean }[];
    policy?: object;
    space?: string;
  } = {},
) {
  const text = new TextEncoder();
  const entries = options.entries ??
    members.map(({ read, write }, i) => ({ key: keys[i], read, write }));
  return writeMetaFrames(
    encode({
      $type: "atproto-space-meta",
      ver: 1,
      space: options.space ?? SPACE,
    }),
    [
      { key: text.encode("policy"), value: encode(options.policy ?? POLICY) },
      ...entries.map(({ key, read, write }) => ({
        key: text.encode(`${PREFIX}${key}`),
        value: encode({ $type: "com.atproto.memberspace.member", read, write }),
      })),
    ],
  );
}

describe("Space metadata membership snapshots", () => {
  it("matches reference keys to the supplied DIDs and returns the semantic identities", () => {
    const bytes = archive();
    expect(() => readSpaceMetaArchive(bytes, SPACE)).toThrow();
    const result = readSpaceMetaArchiveWithMembers(
      bytes,
      SPACE,
      [...members].reverse(),
    );
    expect(result.policyState.map(({ did }) => did)).toEqual(
      members.map(({ did }) => did),
    );
    expect(result.policyState.map(({ value }) => [value.read, value.write]))
      .toEqual(
        members.map(({ read, write }) => [read, write]),
      );
    expect(result.policy).toEqual(POLICY);
  });

  it("exports only exactly round-trippable semantic DIDs and retains writer DIDs", () => {
    const state = members.map(({ did, read, write }) => ({
      did,
      value: {
        $type: "com.atproto.memberspace.member" as const,
        read,
        write,
      },
    }));
    const writer = {
      did: "did:example:writer:a",
      repoRev: "3kbcq3p7ad42b",
      spaceRev: "3kbcq3p7ad42b",
      data: new Uint8Array(32).fill(7),
    };
    const input = {
      space: SPACE,
      policy: POLICY,
      policyState: state,
      writers: [writer],
    };
    const bytes = writeSpaceMetaArchiveWithMembers(input);
    const result = readSpaceMetaArchiveWithMembers(bytes, SPACE, members);
    expect(result.policyState.map(({ did }) => did)).toEqual(
      members.map(({ did }) => did),
    );
    expect(result.writers).toEqual([writer]);
    const roundtrip = readSpaceMetaArchiveWithMembers(
      writeSpaceMetaArchiveWithMembers(result),
      SPACE,
      members,
    );
    expect(roundtrip).toEqual(result);
    for (const did of ["did:web:localhost:2583", "did:example:a%3Ab"]) {
      expect(() =>
        writeSpaceMetaArchiveWithMembers({
          ...input,
          policyState: [{ ...state[0], did }],
        })
      ).toThrow();
    }
    expect(() =>
      writeSpaceMetaArchiveWithMembers({
        ...input,
        policyState: [state[0], state[0]],
      })
    ).toThrow();
  });

  it("requires a complete, unique snapshot with matching access bits", () => {
    const bytes = archive();
    for (
      const expected of [
        members.slice(0, 2),
        [...members, { did: "did:example:extra", read: true, write: false }],
        [...members, members[0]],
        [{ ...members[0], read: false }, ...members.slice(1)],
        [{ ...members[0], write: true }, ...members.slice(1)],
      ]
    ) {
      expect(() => readSpaceMetaArchiveWithMembers(bytes, SPACE, expected))
        .toThrow();
    }
    const duplicate = archive({
      entries: [
        { key: keys[0], read: true, write: false },
        { key: keys[0], read: true, write: false },
      ],
    });
    expect(() =>
      readSpaceMetaArchiveWithMembers(duplicate, SPACE, [members[0]])
    ).toThrow();
    const reordered = archive({
      entries: [
        { key: keys[1], read: false, write: true },
        { key: keys[0], read: true, write: false },
      ],
    });
    expect(() =>
      readSpaceMetaArchiveWithMembers(reordered, SPACE, members.slice(0, 2))
    ).toThrow();
  });

  it("rejects aliases that the reference key mapping cannot round-trip", () => {
    const bytes = archive();
    for (
      const did of [
        "did:web:localhost:2583",
        "did:example:a%3Ab",
        "did:web:localhost%3a2583",
        "did:example:a%zzb",
        "not-a-did",
      ]
    ) {
      expect(() =>
        readSpaceMetaArchiveWithMembers(bytes, SPACE, [{
          did,
          read: true,
          write: false,
        }])
      ).toThrow();
    }
  });

  it("rejects wrong Space, policy, untrusted accessors and malformed manifests", () => {
    const bytes = archive();
    expect(() =>
      readSpaceMetaArchiveWithMembers(bytes, `${SPACE}-other`, members)
    ).toThrow();
    expect(() =>
      readSpaceMetaArchiveWithMembers(
        archive({ policy: { $type: "com.atproto.personalspace.policy" } }),
        SPACE,
        members,
      )
    ).toThrow();
    let accessed = false;
    const getter = {
      did: members[0].did,
      get read() {
        accessed = true;
        return true;
      },
      write: false,
    };
    for (
      const expected of [
        [getter],
        [{ ...members[0], read: "yes" }],
        undefined,
        null,
      ]
    ) {
      expect(() =>
        readSpaceMetaArchiveWithMembers(bytes, SPACE, expected as never)
      ).toThrow();
    }
    expect(accessed).toBe(false);
  });
});
