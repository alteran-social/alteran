import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import {
  materializeExplicitSpaceReadGrant,
  parseExplicitSpaceReadGrant,
} from "../src/lib/spaces/explicit-read-grant";
import { allowsSpacePermission, copyIssuedSpacePermission } from "../src/lib/spaces/oauth-scopes";

const subject = "did:plc:alice";
const scope = "space:com.example.forum?collection=com.example.post&action=read_self";

describe("explicit Space read grants", () => {
  it("retains the request and resolves self for the displayed grant", () => {
    const grant = materializeExplicitSpaceReadGrant(scope, subject);
    expect(grant?.requestedScope).toBe(scope);
    expect(grant?.permission.authority).toBe(subject);
    expect(grant?.permission.collections.values).toEqual(["com.example.post"]);
    expect(grant?.permission.actions).toEqual(["read_self"]);
  });

  it("does not silently narrow default, mixed-action or management requests", () => {
    for (const value of [
      "space:com.example.forum",
      "space:com.example.forum?collection=com.example.post",
      "space:com.example.forum?collection=com.example.post&action=read",
      `${scope}&action=create`,
      `${scope}&manage=update`,
      "space:com.example.forum?collection=&action=read_self",
      "repo:com.example.post",
    ]) expect(parseExplicitSpaceReadGrant(value)).toBeNull();
  });

  it("permits explicit read_self without a declaration or collection", () => {
    const requested = "space:com.example.forum?authority=self&skey=general&action=read_self";
    const grant = materializeExplicitSpaceReadGrant(requested, subject);
    if (!grant) throw new Error("Expected collection-free grant");
    expect(grant.permission.collectionSource).toBe("none");
    expect(grant.permission.collections.values).toEqual([]);
    expect(grant.permission.authority).toBe(subject);
    const target = { spaceType: "com.example.forum", authority: subject, skey: "general" };
    expect(allowsSpacePermission(grant.permission, target, { action: "read_self" })).toBe(true);
    expect(allowsSpacePermission(grant.permission, target, { action: "read" })).toBe(false);
    expect(allowsSpacePermission(grant.permission, target, { action: "create", collection: "com.example.post" })).toBe(false);
    expect(allowsSpacePermission(grant.permission, target, { manage: "create" })).toBe(false);
    expect(allowsSpacePermission(grant.permission, { ...target, skey: "other" }, { action: "read_self" })).toBe(false);
    expect(allowsSpacePermission(grant.permission, { ...target, authority: "did:plc:bob" }, { action: "read_self" })).toBe(false);
    for (const changes of [
      { actions: ["read"] }, { actions: ["read_self", "create"] }, { manage: ["create"] },
      { collections: { tag: "explicit", values: ["com.example.post"] } },
    ]) expect(copyIssuedSpacePermission({ ...grant.permission, ...changes })).toBeNull();
  });

  it("matches the whole owned repository for wildcard targets", () => {
    const grant = materializeExplicitSpaceReadGrant(
      "space:*?authority=*&skey=*&collection=com.example.post&action=read_self",
      subject,
    );
    if (!grant) throw new Error("Expected explicit read grant");
    expect(allowsSpacePermission(grant.permission, {
      spaceType: "com.example.another",
      authority: "did:plc:bob",
      skey: "general",
    }, { action: "read_self" })).toBe(true);
    expect(allowsSpacePermission(grant.permission, {
      spaceType: "com.example.another",
      authority: "did:plc:bob",
      skey: "general",
    }, { action: "create", collection: "com.example.post" })).toBe(false);
  });

  it("rejects authority values that cannot round-trip through the reference", () => {
    const escaped = "space:com.example.forum?authority=did%3Aweb%3Aexample.com%253A8443&collection=com.example.post&action=read_self";
    expect(parseExplicitSpaceReadGrant(escaped)).toBeNull();
    expect(materializeExplicitSpaceReadGrant(scope, "did:web:example.com%3A8443"))
      .toBeNull();
  });
});
