import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import {
  writeSpaceMetaArchive,
  writeSpaceMetaArchiveWithMembers,
} from "../src/lib/spaces/meta-archive";

const SPACE = "at://did:example:alice/space/com.example.notes/budget";
const POLICY = {
  $type: "com.atproto.memberspace.policy",
  publicRead: true,
  publicWrite: false,
  publishPolicy: false,
  publishMembers: false,
} as const;
const MEMBER = {
  $type: "com.atproto.memberspace.member",
  read: true,
  write: false,
} as const;
const REV = "3kbcq3p7ad42b";

function extensions(count: number, size: number) {
  return Object.fromEntries(
    Array.from({ length: count }, (_, i) => [`${i}${"x".repeat(size)}`, true]),
  );
}

describe("Space metadata writer work budgets", () => {
  it("bounds repeated ignored member extensions for both writers", () => {
    const value = { ...MEMBER, ...extensions(61, 1000) };
    const semantic = Array.from(
      { length: 300 },
      (_, i) => ({ did: `did:example:member${i}`, value }),
    );
    const keyed = semantic.map(({ did, value }) => ({
      key: `com.atproto.memberspace.member/${did}`,
      value,
    }));
    expect(() =>
      writeSpaceMetaArchiveWithMembers({
        space: SPACE,
        policy: POLICY,
        policyState: semantic,
        writers: [],
      })
    ).toThrow();
    expect(() =>
      writeSpaceMetaArchive({
        space: SPACE,
        policy: POLICY,
        policyState: keyed,
        writers: [],
      })
    ).toThrow();
    expect(
      writeSpaceMetaArchiveWithMembers({
        space: SPACE,
        policy: POLICY,
        policyState: semantic.slice(0, 2),
        writers: [],
      }).length,
    )
      .toBeGreaterThan(0);
  });

  it("bounds repeated ignored writer extensions", () => {
    const extra = extensions(60, 1000);
    const writers = Array.from(
      { length: 300 },
      (_, i) => ({
        did: `did:example:writer${i}`,
        repoRev: REV,
        spaceRev: REV,
        data: new Uint8Array(32),
        ...extra,
      }),
    );
    expect(() =>
      writeSpaceMetaArchive({
        space: SPACE,
        policy: POLICY,
        policyState: [],
        writers,
      })
    ).toThrow();
  });

  it("charges UTF-8 bytes, not just JavaScript string length", () => {
    const value = { ...MEMBER, ["é".repeat(2000)]: true };
    const state = Array.from(
      { length: 4500 },
      (_, i) => ({ did: `did:example:member${i}`, value }),
    );
    expect(() =>
      writeSpaceMetaArchiveWithMembers({
        space: SPACE,
        policy: POLICY,
        policyState: state,
        writers: [],
      })
    ).toThrow();
  });
});
