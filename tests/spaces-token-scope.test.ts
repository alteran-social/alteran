import { SpacePermission as ReferenceSpacePermission } from "@atproto/oauth-scopes";
import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import {
  formatSpaceTokenScope,
  MAX_MATERIALIZED_SCOPE_BYTES,
} from "../src/lib/oauth/space-token-scope";
import {
  allowsSpacePermission,
  type IssuedSpacePermission,
  materializeCollectionFreeReadSelf,
  materializeSpacePermission,
  parseSpacePermission,
} from "../src/lib/spaces/oauth-scopes";

const DID = "did:plc:abcdefghijklmnopqrstuvwx";
const TYPE = "com.example.forum";
const THREAD = "com.example.thread";
const REPLY = "com.example.reply";

function issued(
  scope: string,
  collections: readonly string[] = [THREAD],
): IssuedSpacePermission {
  const parsed = parseSpacePermission(scope);
  if (!parsed) throw new Error("Invalid test scope");
  const permission = materializeSpacePermission(parsed, DID, {
    spaceType: parsed.spaceType,
    collections,
  });
  if (!permission) throw new Error("Could not materialize test scope");
  return permission;
}

function wire(permission: IssuedSpacePermission) {
  const result = formatSpaceTokenScope({
    otherScopes: ["atproto", "transition:generic"],
    grants: [permission],
  });
  if (result.tag !== "formatted") {
    throw new Error(`Could not format test scope: ${result.tag}`);
  }
  const token = result.scope.split(" ").find((part) =>
    part.startsWith("space:")
  );
  if (!token) throw new Error("Missing Space scope");
  const reference = ReferenceSpacePermission.fromString(token);
  if (!reference) throw new Error("Reference rejected formatted scope");
  return { scope: result.scope, reference };
}

describe("materialized Space token scopes", () => {
  it("formats collection-free read_self with the pinned reference semantics", () => {
    const requested = parseSpacePermission(`space:${TYPE}?skey=general&action=read_self`);
    if (!requested) throw new Error("Expected request");
    const permission = materializeCollectionFreeReadSelf(requested, DID);
    if (!permission) throw new Error("Expected collection-free grant");
    const { reference, scope } = wire(permission);
    expect(scope).not.toContain("collection=");
    const target = { spaceType: TYPE, authority: DID, skey: "general" } as const;
    for (const operation of [
      { action: "read_self" }, { action: "read" },
      { action: "create", collection: THREAD }, { manage: "create" },
    ] as const) {
      expect(reference.matches({ ...target, ...operation })).toBe(allowsSpacePermission(permission, target, operation));
    }
    expect(reference.matches({ ...target, action: "read_self" })).toBe(true);
    expect(reference.matches({ ...target, skey: "other", action: "read_self" })).toBe(false);
  });

  it("matches the pinned reference for reads, writes, management and targets", () => {
    const permission = issued(
      `space:${TYPE}?authority=*&skey=general&collection=${THREAD}&collection=${REPLY}&action=read&action=create&action=delete&manage=update`,
    );
    const { scope, reference } = wire(permission);
    expect(scope).toContain("atproto transition:generic ");
    expect(scope.length <= MAX_MATERIALIZED_SCOPE_BYTES).toBe(true);
    const targets = [
      { spaceType: TYPE, authority: DID, skey: "general" },
      { spaceType: TYPE, authority: DID, skey: "other" },
      { spaceType: "com.example.other", authority: DID, skey: "general" },
    ] as const;
    const operations = [
      { action: "read" },
      { action: "read_self" },
      { action: "create", collection: THREAD },
      { action: "update", collection: REPLY },
      { action: "delete", collection: REPLY },
      { action: "delete", collection: "com.example.other" },
      { manage: "create" },
      { manage: "update" },
      { manage: "delete" },
    ] as const;
    for (const target of targets) {
      for (const operation of operations) {
        expect(reference.matches({ ...target, ...operation }))
          .toBe(allowsSpacePermission(permission, target, operation));
      }
    }
  });

  it("omits an empty collection set without granting writes", () => {
    const permission = issued(`space:${TYPE}`, []);
    const { reference } = wire(permission);
    expect(reference.collection).toBeUndefined();
    const target = {
      spaceType: TYPE,
      authority: DID,
      skey: "general",
    } as const;
    expect(reference.matches({ ...target, action: "read_self" })).toBe(true);
    expect(
      reference.matches({ ...target, action: "create", collection: THREAD }),
    ).toBe(false);
    expect(
      allowsSpacePermission(permission, target, {
        action: "create",
        collection: THREAD,
      }),
    ).toBe(false);
  });

  it("resolves self authority and preserves a fixed wildcard grant", () => {
    const permission = issued(`space:*?collection=*&action=update`);
    const { reference } = wire(permission);
    expect(reference.authority).toBe(DID);
    expect(
      reference.matches({
        spaceType: TYPE,
        authority: DID,
        skey: "any",
        action: "update",
        collection: THREAD,
      }),
    ).toBe(true);
    expect(
      reference.matches({
        spaceType: TYPE,
        authority: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        skey: "any",
        action: "update",
        collection: THREAD,
      }),
    ).toBe(false);
  });

  it("does not use a reference formatter that changes escaped DID authorities", () => {
    for (
      const authority of [
        "did:example:a%3Ab",
        "did:example:a%2Fb",
        "did:example:a%25b",
      ]
    ) {
      const params = new URLSearchParams({
        authority,
        collection: THREAD,
        action: "read",
      });
      const parsed = ReferenceSpacePermission.fromString(
        `space:${TYPE}?${params}`,
      );
      if (!parsed) throw new Error("Expected reference parse");
      expect(parsed.authority).toBe(authority);
      expect(ReferenceSpacePermission.fromString(parsed.toString())?.authority)
        .not.toBe(authority);
      expect(
        formatSpaceTokenScope({
          otherScopes: ["atproto"],
          grants: [issued(`space:${TYPE}?${params}`)],
        }).tag,
      )
        .toBe("unsupported");
    }
  });

  it("rejects empty actions and raw Space scopes instead of expanding them", () => {
    const permission = issued(`space:${TYPE}?collection=${THREAD}`);
    expect(
      formatSpaceTokenScope({
        otherScopes: ["atproto"],
        grants: [{ ...permission, actions: [] }],
      }).tag,
    )
      .toBe("invalid");
    expect(
      formatSpaceTokenScope({
        otherScopes: ["atproto", `space:${TYPE}`],
        grants: [],
      }).tag,
    )
      .toBe("invalid");
    expect(
      formatSpaceTokenScope({
        otherScopes: ["transition:generic"],
        grants: [permission],
      }).tag,
    )
      .toBe("invalid");
  });

  it("rejects an oversized materialized scope without returning a partial token", () => {
    const collections = Array.from(
      { length: 30 },
      (_, index) =>
        `com.${"a".repeat(60)}.${"b".repeat(60)}.${
          "c".repeat(60)
        }.type${index}`,
    );
    const query = new URLSearchParams();
    for (const collection of collections) {
      query.append("collection", collection);
    }
    const permission = issued(`space:${TYPE}?${query}`);
    const result = formatSpaceTokenScope({
      otherScopes: ["atproto"],
      grants: [permission],
    });
    expect(result.tag).toBe("tooLarge");
    expect(Object.hasOwn(result, "scope")).toBe(false);
  });
});
