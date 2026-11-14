import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import {
  allowsSpacePermission,
  type IssuedSpacePermission,
  materializeSpacePermission,
  parseSpacePermission,
  type SpacePermission,
  type SpacePermissionTarget,
  type SpaceTypeDeclaration,
} from "../src/lib/spaces/oauth-scopes";

const USER = "did:plc:alice";
const OTHER = "did:plc:bob";
const TYPE = "com.example.forum";
const THREAD = "com.example.thread";
const REPLY = "com.example.reply";
const TARGET = { spaceType: TYPE, authority: USER, skey: "general" };

function permission(scope: string): SpacePermission {
  const parsed = parseSpacePermission(scope);
  if (!parsed) throw new Error(`Invalid test scope: ${scope}`);
  return parsed;
}

function issued(scope: string): IssuedSpacePermission {
  const parsed = permission(scope);
  const result = materializeSpacePermission(parsed, USER, {
    spaceType: parsed.spaceType,
    collections: [],
  });
  if (!result) throw new Error(`Cannot materialize test scope: ${scope}`);
  return result;
}

describe("Spaces OAuth permissions", () => {
  it("uses the specified defaults for an abbreviated grant", () => {
    expect(parseSpacePermission(`space:${TYPE}`)).toEqual({
      spaceType: TYPE,
      authority: "self",
      skey: "*",
      collections: { tag: "declaration" },
      actions: ["read", "create", "update", "delete"],
      manage: [],
    });
  });

  it("accepts positional and named space types with equivalent permissions", () => {
    const positional = permission(`space:${TYPE}?authority=*&action=read`);
    const named = permission(`space?spaceType=${TYPE}&authority=*&action=read`);
    expect(named).toEqual(positional);
  });

  it("accepts repeated multi-value parameters and decodes their values", () => {
    const parsed = permission(
      `space:${TYPE}?authority=did%3Aplc%3Aalice&skey=one%3Atwo` +
        `&collection=${THREAD}&collection=${REPLY}&collection=${THREAD}` +
        "&action=create&action=delete&action=create&manage=update&manage=delete",
    );
    expect(parsed.authority).toBe(USER);
    expect(parsed.skey).toBe("one:two");
    expect(parsed.collections).toEqual({
      tag: "explicit",
      values: [THREAD, REPLY],
    });
    expect(parsed.actions).toEqual(["create", "delete"]);
    expect(parsed.manage).toEqual(["update", "delete"]);
  });

  it("rejects malformed, conflicting, unknown and repeated single-value parameters", () => {
    for (
      const invalid of [
        "space",
        "space:",
        `space:${TYPE}?spaceType=${TYPE}`,
        `space?spaceType=${TYPE}&spaceType=${TYPE}`,
        `space:${TYPE}?authority=self&authority=*`,
        `space:${TYPE}?skey=one&skey=two`,
        `space:${TYPE}?unknown=value`,
        `space:${TYPE}?collection=`,
        `space:${TYPE}?action=`,
        `space:${TYPE}?manage=read`,
        `space:${TYPE}?authority=did%3Aplc%3A%ZZ`,
        `space:${TYPE}?skey=%`,
        `space:${TYPE}?action=read%20create`,
        `space:${TYPE} action=read`,
        "space:short",
        `space:${TYPE}?authority=not-a-did`,
        `space:${TYPE}?collection=bad_collection`,
        `space:${TYPE}?skey=..`,
        `space:${TYPE}?skey=a%2Fb`,
        `space:${TYPE}?skey=${"x".repeat(513)}`,
        `repo:${TYPE}`,
      ]
    ) {
      expect(parseSpacePermission(invalid)).toBeNull();
    }
  });

  it("accepts valid record keys at the length limit", () => {
    expect(permission(`space:${TYPE}?skey=${"x".repeat(512)}`).skey)
      .toHaveLength(512);
  });

  it("rejects invalid UTF-8 in decoded type, authority and key values", () => {
    for (const invalid of ["%FF", "%C0%AF", "%E2%82"]) {
      expect(parseSpacePermission(`space?spaceType=com.example.${invalid}`))
        .toBeNull();
      expect(
        parseSpacePermission(`space:${TYPE}?authority=did%3Aplc%3A${invalid}`),
      ).toBeNull();
      expect(parseSpacePermission(`space:${TYPE}?skey=${invalid}`)).toBeNull();
    }
    expect(parseSpacePermission(null)).toBeNull();
  });

  it("decodes a percent-encoded DID value exactly once", () => {
    const grant = permission(
      `space:${TYPE}?authority=did%3Aweb%3Aexample.com%253A8443`,
    );
    expect(grant.authority).toBe("did:web:example.com%3A8443");
  });

  it("resolves self to the granting DID and rejects other authorities", () => {
    const parsed = permission(`space:${TYPE}?action=read`);
    expect(
      allowsSpacePermission(
        parsed as unknown as IssuedSpacePermission,
        TARGET,
        { action: "read" },
      ),
    ).toBe(false);
    expect(
      materializeSpacePermission(parsed, "invalid", {
        spaceType: TYPE,
        collections: [],
      }),
    ).toBeNull();
    const grant = issued(`space:${TYPE}?action=read`);
    expect(allowsSpacePermission(grant, TARGET, { action: "read" })).toBe(true);
    expect(
      allowsSpacePermission(grant, { ...TARGET, authority: OTHER }, {
        action: "read",
      }),
    ).toBe(false);
    expect(
      allowsSpacePermission(grant, { ...TARGET, authority: "self" }, {
        action: "read",
      }),
    ).toBe(false);
  });

  it("fails closed for malformed runtime targets and declarations", () => {
    const grant = permission(`space:${TYPE}`);
    const resolved = issued(`space:${TYPE}`);
    expect(
      allowsSpacePermission(
        resolved,
        null as unknown as SpacePermissionTarget,
        { action: "read" },
      ),
    ).toBe(false);
    expect(
      allowsSpacePermission(
        resolved,
        { ...TARGET, skey: null } as unknown as SpacePermissionTarget,
        { action: "read" },
      ),
    ).toBe(false);
    expect(
      allowsSpacePermission({ ...resolved, authority: "self" }, TARGET, {
        action: "read",
      }),
    ).toBe(false);
    expect(materializeSpacePermission(grant, USER, {
      spaceType: TYPE,
      collections: [THREAD, null],
    } as unknown as SpaceTypeDeclaration)).toBeNull();
  });

  it("rejects malformed stored grants before checking their permissions", () => {
    const grant = issued(
      `space:${TYPE}?action=create&collection=${THREAD}&manage=update`,
    );
    const malformed: unknown[] = [
      { ...grant, actions: "create" },
      { ...grant, actions: "bread" },
      { ...grant, actions: ["read", "invalid"] },
      { ...grant, manage: "update" },
      { ...grant, manage: ["update", "read"] },
      { ...grant, collections: { tag: "explicit", values: "*" } },
      { ...grant, collections: { tag: "explicit", values: [THREAD, null] } },
      { ...grant, collections: { tag: "declaration" } },
      { ...grant, authority: "self" },
      { ...grant, authority: "invalid" },
      { ...grant, spaceType: "invalid" },
      { ...grant, skey: ".." },
      { ...grant, actions: Array(1) },
    ];
    for (const value of malformed) {
      const stored = value as IssuedSpacePermission;
      expect(allowsSpacePermission(stored, TARGET, { action: "read" })).toBe(
        false,
      );
      expect(
        allowsSpacePermission(stored, TARGET, {
          action: "create",
          collection: THREAD,
        }),
      ).toBe(false);
      expect(allowsSpacePermission(stored, TARGET, { manage: "update" })).toBe(
        false,
      );
    }
  });

  it("rejects overridden array methods and accessors in permissions", () => {
    const grant = issued(`space:${TYPE}?action=read_self&collection=${THREAD}`);
    const actions = [...grant.actions];
    Object.defineProperty(actions, "includes", { value: () => true });
    expect(allowsSpacePermission({ ...grant, actions }, TARGET, {
      action: "delete",
      collection: THREAD,
    })).toBe(false);
    const changing = { ...grant };
    Object.defineProperty(changing, "actions", {
      enumerable: true,
      get: () => ["delete"],
    });
    expect(allowsSpacePermission(changing, TARGET, {
      action: "delete",
      collection: THREAD,
    })).toBe(false);
    const accessorValues = [...grant.collections.values];
    Object.defineProperty(accessorValues, "0", {
      enumerable: true,
      get: () => "*",
    });
    expect(allowsSpacePermission(
      {
        ...grant,
        collections: { tag: "explicit", values: accessorValues },
      },
      TARGET,
      { action: "delete", collection: THREAD },
    )).toBe(false);
  });

  it("rejects accessor-backed declarations, targets and operations", () => {
    const raw = permission(`space:${TYPE}`);
    const declaration = { spaceType: TYPE, collections: [THREAD] };
    Object.defineProperty(declaration, "collections", {
      enumerable: true,
      get: () => [THREAD],
    });
    expect(materializeSpacePermission(raw, USER, declaration)).toBeNull();
    const target = { ...TARGET };
    Object.defineProperty(target, "authority", {
      enumerable: true,
      get: () => USER,
    });
    expect(
      allowsSpacePermission(issued(`space:${TYPE}`), target, {
        action: "read",
      }),
    )
      .toBe(false);
    const operation = { action: "read" as const };
    Object.defineProperty(operation, "action", {
      enumerable: true,
      get: () => "read",
    });
    expect(allowsSpacePermission(issued(`space:${TYPE}`), TARGET, operation))
      .toBe(false);
  });

  it("fails closed for revoked proxies", () => {
    const proxy = Proxy.revocable({}, {});
    proxy.revoke();
    expect(allowsSpacePermission(
      proxy.proxy as IssuedSpacePermission,
      TARGET,
      { action: "read" },
    )).toBe(false);
    expect(materializeSpacePermission(
      proxy.proxy as SpacePermission,
      USER,
    )).toBeNull();
  });

  it("rejects malformed percent escapes in granting and authority DIDs", () => {
    expect(parseSpacePermission(
      `space:${TYPE}?authority=did%3Aexample%3A%25ZZ&collection=${THREAD}`,
    )).toBeNull();
    expect(
      materializeSpacePermission(
        permission(`space:${TYPE}`),
        "did:example:%ZZ",
        {
          spaceType: TYPE,
          collections: [THREAD],
        },
      ),
    ).toBeNull();
    expect(allowsSpacePermission(issued(`space:${TYPE}`), {
      ...TARGET,
      authority: "did:example:%ZZ",
    }, { action: "read" })).toBe(false);
  });

  it("treats read_self as narrower than whole-space read regardless of collections", () => {
    const own = issued(`space:${TYPE}?action=read_self&collection=${THREAD}`);
    const all = issued(`space:${TYPE}?action=read`);
    expect(allowsSpacePermission(own, TARGET, { action: "read_self" })).toBe(
      true,
    );
    expect(allowsSpacePermission(own, TARGET, { action: "read" })).toBe(false);
    expect(allowsSpacePermission(all, TARGET, { action: "read_self" })).toBe(
      true,
    );
    expect(allowsSpacePermission(all, TARGET, { action: "read" })).toBe(true);
  });

  it("requires matching space, record action and explicit collection for writes", () => {
    const grant = issued(
      `space:${TYPE}?authority=${USER}&skey=general&collection=${THREAD}&action=create`,
    );
    const create = { action: "create", collection: THREAD } as const;
    expect(allowsSpacePermission(grant, TARGET, create)).toBe(true);
    expect(
      allowsSpacePermission(grant, {
        ...TARGET,
        spaceType: "com.example.other",
      }, create),
    ).toBe(false);
    expect(
      allowsSpacePermission(grant, { ...TARGET, authority: OTHER }, create),
    ).toBe(false);
    expect(allowsSpacePermission(grant, { ...TARGET, skey: "other" }, create))
      .toBe(false);
    expect(
      allowsSpacePermission(grant, TARGET, {
        action: "update",
        collection: THREAD,
      }),
    ).toBe(false);
    expect(
      allowsSpacePermission(grant, TARGET, {
        action: "create",
        collection: REPLY,
      }),
    ).toBe(false);
    expect(
      allowsSpacePermission(grant, TARGET, {
        action: "create",
        collection: "bad",
      }),
    ).toBe(false);
  });

  it("requires a matching declaration before an omitted collection permits writes", () => {
    const grant = permission(`space:${TYPE}`);
    const create = { action: "create", collection: THREAD } as const;
    expect(
      allowsSpacePermission(
        grant as unknown as IssuedSpacePermission,
        TARGET,
        create,
      ),
    ).toBe(false);
    const resolved = materializeSpacePermission(grant, USER, {
      spaceType: TYPE,
      collections: [THREAD],
    });
    expect(resolved).not.toBeNull();
    if (!resolved) throw new Error("Expected materialized scope");
    expect(resolved.authority).toBe(USER);
    expect(allowsSpacePermission(resolved, TARGET, create)).toBe(true);
    expect(materializeSpacePermission(grant, USER, {
      spaceType: "com.example.other",
      collections: [THREAD],
    })).toBeNull();
    expect(materializeSpacePermission(grant, USER, {
      spaceType: TYPE,
      collections: [THREAD, "*"],
    })).toBeNull();
    expect(materializeSpacePermission({
      ...grant,
      collections: { tag: "explicit", values: [] },
    }, USER)).toBeNull();
  });

  it("does not infer write targets from a declaration for a wildcard type", () => {
    const grant = permission("space:*?authority=*");
    const create = { action: "create", collection: THREAD } as const;
    const resolved = materializeSpacePermission(grant, USER);
    if (!resolved) throw new Error("Expected materialized scope");
    expect(allowsSpacePermission(resolved, TARGET, create)).toBe(false);
    const explicit = issued("space:*?authority=*&collection=*");
    expect(allowsSpacePermission(explicit, TARGET, create)).toBe(true);
  });

  it("freezes declaration collections for an issued permission", () => {
    const grant = permission(`space:${TYPE}`);
    const collections = [THREAD];
    const issued = materializeSpacePermission(grant, USER, {
      spaceType: TYPE,
      collections,
    });
    if (!issued) throw new Error("Expected materialized scope");
    collections.push(REPLY);
    expect(
      allowsSpacePermission(issued, TARGET, {
        action: "create",
        collection: REPLY,
      }),
    ).toBe(false);
    const refreshed = materializeSpacePermission(grant, USER, {
      spaceType: TYPE,
      collections,
    });
    if (!refreshed) throw new Error("Expected refreshed scope");
    expect(
      allowsSpacePermission(refreshed, TARGET, {
        action: "create",
        collection: REPLY,
      }),
    ).toBe(true);
  });

  it("checks management permissions independently from record actions", () => {
    const grant = issued(`space:${TYPE}?action=read&manage=update`);
    expect(allowsSpacePermission(grant, TARGET, { manage: "update" })).toBe(
      true,
    );
    expect(allowsSpacePermission(grant, TARGET, { manage: "delete" })).toBe(
      false,
    );
    expect(
      allowsSpacePermission(grant, TARGET, {
        action: "create",
        collection: THREAD,
      }),
    ).toBe(false);
    expect(
      allowsSpacePermission(issued(`space:${TYPE}`), TARGET, {
        manage: "update",
      }),
    ).toBe(false);
  });

  it("requires grants to cover wildcard list selectors in full", () => {
    const narrowed = issued(
      `space:${TYPE}?authority=*&skey=general&action=read_self`,
    );
    const broad = issued("space:*?authority=*&action=read_self");
    const all = { spaceType: "*", authority: "*", skey: "*" };
    expect(allowsSpacePermission(narrowed, all, { action: "read_self" })).toBe(
      false,
    );
    expect(allowsSpacePermission(broad, all, { action: "read_self" })).toBe(
      true,
    );
    expect(
      allowsSpacePermission(broad, { ...TARGET, skey: ".." }, {
        action: "read_self",
      }),
    ).toBe(false);
  });
});
