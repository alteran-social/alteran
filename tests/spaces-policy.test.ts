import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { parseSpacePolicy } from "../src/lib/spaces/policy";
import {
  decideSpaceAccountAccess,
  decideSpaceClientAccess,
  type SpaceMembership,
} from "../src/lib/spaces/policy-access";

const AUTHORITY = "did:plc:abcdefghijklmnopqrstuvwx";
const OTHER = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const SPACE = `at://${AUTHORITY}/space/com.example.forum/general`;
const CLIENT = "https://client.example/metadata.json";
const PERSONAL = { $type: "com.atproto.personalspace.policy" };
const MEMBER = { $type: "com.atproto.memberspace.policy" };
const MANAGED = {
  $type: "com.atproto.managedspace.policy",
  managingApp: `${AUTHORITY}#service`,
};
const UNKNOWN: SpaceMembership = { tag: "not-checked" };

function decision(
  policy: unknown,
  repo: string | null,
  action: "read" | "write",
  membership: SpaceMembership = UNKNOWN,
) {
  return decideSpaceAccountAccess(policy, {
    space: SPACE,
    repo,
    action,
    membership,
  }).tag;
}

describe("baseline Space policies", () => {
  it("normalizes member defaults and drops extension fields", () => {
    expect(parseSpacePolicy({ ...MEMBER, extra: true })).toEqual({
      tag: "valid",
      policy: {
        ...MEMBER,
        publicRead: false,
        publicWrite: false,
        publishPolicy: false,
        publishMembers: false,
      },
    });
    expect(parseSpacePolicy({ ...PERSONAL, extra: true })).toEqual({
      tag: "valid",
      policy: PERSONAL,
    });
  });

  it("rejects invalid fields and leaves unknown policies unsupported", () => {
    for (
      const policy of [
        null,
        { ...MEMBER, publicRead: "true" },
        { ...MEMBER, publicWrite: null },
        { ...MEMBER, allowedApps: ["not-a-uri"] },
        { ...MEMBER, allowedApps: [CLIENT, null] },
        { ...MEMBER, allowedApps: ["https://example.com/%ZZ"] },
        { ...MEMBER, allowedApps: Array(257).fill(CLIENT) },
        { ...MANAGED, publishPolicy: 1 },
      ]
    ) expect(parseSpacePolicy(policy).tag).toBe("invalid");
    expect(parseSpacePolicy({ $type: "com.example.future.policy" }).tag).toBe(
      "unsupported",
    );
  });

  it("requires a valid AT Protocol DID service reference for managed policies", () => {
    expect(parseSpacePolicy(MANAGED)).toEqual({
      tag: "valid",
      policy: { ...MANAGED, publishPolicy: false },
    });
    for (
      const managingApp of [
        AUTHORITY,
        "#service",
        `${AUTHORITY}#`,
        `${AUTHORITY}#bad%zz`,
        "did:example:other#service",
      ]
    ) {
      expect(parseSpacePolicy({ ...MANAGED, managingApp }).tag).toBe("invalid");
    }
  });

  it("copies and freezes allowed apps", () => {
    const allowedApps = [CLIENT];
    const result = parseSpacePolicy({ ...MEMBER, allowedApps });
    if (
      result.tag !== "valid" ||
      result.policy.$type !== "com.atproto.memberspace.policy"
    ) {
      throw new Error("Expected member policy");
    }
    allowedApps.push("https://other.example/app");
    expect(result.policy.allowedApps).toEqual([CLIENT]);
    expect(Object.isFrozen(result.policy)).toBe(true);
    expect(Object.isFrozen(result.policy.allowedApps)).toBe(true);
  });

  it("rejects getters and array-method overrides on policy input", () => {
    const changing = { ...MEMBER };
    Object.defineProperty(changing, "publicRead", {
      enumerable: true,
      get: () => true,
    });
    expect(parseSpacePolicy(changing).tag).toBe("invalid");
    const apps = [CLIENT];
    Object.defineProperty(apps, "includes", { value: () => true });
    expect(parseSpacePolicy({ ...MEMBER, allowedApps: apps }).tag).toBe(
      "invalid",
    );
  });

  it("always authorizes the authority account under each baseline policy", () => {
    for (const policy of [PERSONAL, MEMBER, MANAGED]) {
      expect(decision(policy, AUTHORITY, "read")).toBe("allowed");
      expect(decision(policy, AUTHORITY, "write")).toBe("allowed");
    }
  });

  it("denies other accounts and anonymous users under personal policy", () => {
    for (const repo of [OTHER, null]) {
      expect(decision(PERSONAL, repo, "read")).toBe("denied");
      expect(decision(PERSONAL, repo, "write")).toBe("denied");
    }
  });

  it("permits public reads even for anonymous or explicitly denied members", () => {
    const publicPolicy = { ...MEMBER, publicRead: true };
    expect(decision(publicPolicy, null, "read")).toBe("allowed");
    expect(
      decision(publicPolicy, OTHER, "read", {
        tag: "member",
        read: false,
        write: false,
      }),
    ).toBe("allowed");
  });

  it("uses the member read flag when public reading is disabled", () => {
    expect(
      decision(MEMBER, OTHER, "read", {
        tag: "member",
        read: true,
        write: false,
      }),
    ).toBe("allowed");
    expect(
      decision(MEMBER, OTHER, "read", {
        tag: "member",
        read: false,
        write: true,
      }),
    ).toBe("denied");
    expect(decision(MEMBER, OTHER, "read", { tag: "not-member" })).toBe(
      "denied",
    );
    expect(decision(MEMBER, OTHER, "read")).toBe("lookup-required");
    expect(decision(MEMBER, OTHER, "read", { tag: "unavailable" })).toBe(
      "unavailable",
    );
  });

  it("lets explicit member write denial override public write", () => {
    const publicPolicy = { ...MEMBER, publicWrite: true };
    expect(
      decision(publicPolicy, OTHER, "write", {
        tag: "member",
        read: true,
        write: false,
      }),
    ).toBe("denied");
    expect(
      decision(publicPolicy, OTHER, "write", {
        tag: "member",
        read: false,
        write: true,
      }),
    ).toBe("allowed");
    expect(decision(publicPolicy, OTHER, "write", { tag: "not-member" })).toBe(
      "allowed",
    );
    expect(decision(publicPolicy, OTHER, "write", { tag: "unavailable" })).toBe(
      "unavailable",
    );
    expect(decision(publicPolicy, null, "write")).toBe("denied");
  });

  it("requires an external decision for non-authority managed access", () => {
    expect(
      decideSpaceAccountAccess(MANAGED, {
        space: SPACE,
        repo: OTHER,
        action: "write",
        membership: UNKNOWN,
      }),
    )
      .toEqual({ tag: "managed", managingApp: MANAGED.managingApp });
    expect(decision(MANAGED, null, "read")).toBe("managed");
    expect(decision(MANAGED, null, "write")).toBe("denied");
  });

  it("enforces the separate verified-client allowlist", () => {
    const unrestricted = MEMBER;
    const restricted = { ...MEMBER, allowedApps: [CLIENT] };
    expect(decideSpaceClientAccess(unrestricted, { tag: "absent" }).tag).toBe(
      "allowed",
    );
    expect(
      decideSpaceClientAccess({ ...MEMBER, allowedApps: [] }, { tag: "absent" })
        .tag,
    ).toBe("denied");
    expect(
      decideSpaceClientAccess(restricted, { tag: "verified", clientId: CLIENT })
        .tag,
    ).toBe("allowed");
    expect(
      decideSpaceClientAccess(restricted, {
        tag: "verified",
        clientId: `${CLIENT}/other`,
      }).tag,
    ).toBe("denied");
    expect(decideSpaceClientAccess(restricted, { tag: "absent" }).tag).toBe(
      "denied",
    );
    expect(decideSpaceClientAccess(unrestricted, { tag: "invalid" }).tag).toBe(
      "invalid",
    );
    expect(decideSpaceClientAccess(unrestricted, { tag: "unavailable" }).tag)
      .toBe("unavailable");
  });

  it("rejects invalid targets, memberships and client attestations", () => {
    expect(
      decideSpaceAccountAccess(MEMBER, {
        space: "invalid",
        repo: OTHER,
        action: "read",
        membership: UNKNOWN,
      }).tag,
    ).toBe("invalid");
    expect(
      decideSpaceAccountAccess(MEMBER, {
        space: SPACE,
        repo: "invalid",
        action: "read",
        membership: UNKNOWN,
      }).tag,
    ).toBe("invalid");
    expect(
      decideSpaceAccountAccess(MEMBER, {
        space: SPACE,
        repo: OTHER,
        action: "read",
        membership: {
          tag: "member",
          read: "yes",
          write: false,
        } as unknown as SpaceMembership,
      }).tag,
    ).toBe("invalid");
    expect(
      decideSpaceClientAccess(MEMBER, {
        tag: "verified",
        clientId: "not-a-uri",
      }).tag,
    ).toBe("invalid");
    expect(
      decideSpaceClientAccess(MEMBER, {
        tag: "verified",
        clientId: "https://example.com/%ZZ",
      }).tag,
    ).toBe("invalid");
    expect(
      decideSpaceAccountAccess(PERSONAL, {
        space: "at://did:plc:%ZZ/space/com.example.forum/general",
        repo: "did:plc:%ZZ",
        action: "read",
        membership: UNKNOWN,
      }).tag,
    ).toBe("invalid");
    expect(
      decideSpaceAccountAccess(MEMBER, {
        space: `at://${AUTHORITY}/space/com.example.forum/${"x".repeat(8193)}`,
        repo: OTHER,
        action: "read",
        membership: UNKNOWN,
      }).tag,
    ).toBe("invalid");
  });
});
