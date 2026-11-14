import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { describeSpaceConsent } from "../src/lib/spaces/consent-display";
import {
  materializeSpacePermission,
  parseSpacePermission,
} from "../src/lib/spaces/oauth-scopes";

const DID = "did:plc:alice";
const TYPE = "com.example.forum";
const COLLECTION = "com.example.note";

function grant(scope: string, collections: readonly string[] = [COLLECTION]) {
  const requested = parseSpacePermission(scope);
  if (!requested) throw new Error("Invalid test scope");
  const issued = materializeSpacePermission(requested, DID, {
    spaceType: requested.spaceType,
    collections,
  });
  if (!issued) throw new Error("Invalid test grant");
  return issued;
}

describe("Space consent descriptions", () => {
  it("distinguishes own-repo access, delegation, writes and management", () => {
    const result = describeSpaceConsent(grant(
      `space:${TYPE}?skey=private&collection=${COLLECTION}&action=read&action=create&action=delete&manage=update`,
    ));
    expect(result).toEqual({
      target: `space type ${TYPE}, authority ${DID}, space key private`,
      permissions: [
        "Read your own repository in matching spaces",
        "Read settings, policies, member lists, writer identities and sync state for matching spaces you govern",
        "Request credentials to read other repositories in matching spaces",
        `Create and delete records in ${COLLECTION} in your own repository`,
        "Change settings and policies, manage members, remove writers and perform policy-specific updates in matching spaces you govern",
      ],
      broad: false,
    });
  });

  it("makes wildcard targets and collections explicit", () => {
    const result = describeSpaceConsent(
      grant("space:*?authority=*&collection=*&action=update"),
    );
    expect(result).toEqual({
      target: "all space types, any authority, any space key",
      permissions: ["Update records in any collection in your own repository"],
      broad: true,
    });
  });

  it("does not claim write access when the issued collection set is empty", () => {
    const result = describeSpaceConsent(grant(`space:${TYPE}`, []));
    expect(result?.permissions).toEqual([
      "Read your own repository in matching spaces",
      "Read settings, policies, member lists, writer identities and sync state for matching spaces you govern",
      "Request credentials to read other repositories in matching spaces",
      "Future authorization may include additional collections declared for this space type",
    ]);
  });

  it("discloses declaration-derived collections that may expand on refresh", () => {
    const declared = describeSpaceConsent(
      grant(`space:${TYPE}?skey=one&action=create`),
    );
    const fixed = describeSpaceConsent(
      grant(`space:${TYPE}?skey=one&action=create&collection=${COLLECTION}`),
    );
    expect(declared?.permissions).toEqual([
      `Create records in ${COLLECTION} in your own repository`,
      "Future authorization may include additional collections declared for this space type",
    ]);
    expect(fixed?.permissions).toEqual([
      `Create records in ${COLLECTION} in your own repository`,
    ]);
    expect(declared?.broad).toBe(true);
    expect(fixed?.broad).toBe(false);
  });

  it("does not count a collection wildcard as broad for read-only permissions", () => {
    const result = describeSpaceConsent(
      grant(`space:${TYPE}?skey=one&collection=*&action=read_self`),
    );
    expect(result?.permissions).toEqual([
      "Read your own repository in matching spaces",
      "Read settings, policies, member lists, writer identities and sync state for matching spaces you govern",
    ]);
    expect(result?.broad).toBe(false);
  });

  it("describes each authority management operation", () => {
    const result = describeSpaceConsent(grant(
      `space:${TYPE}?skey=one&action=read_self&manage=create&manage=update&manage=delete`,
    ));
    expect(result?.permissions).toEqual([
      "Read your own repository in matching spaces",
      "Read settings, policies, member lists, writer identities and sync state for matching spaces you govern",
      "Create matching spaces that you govern and perform policy-specific creation operations",
      "Change settings and policies, manage members, remove writers and perform policy-specific updates in matching spaces you govern",
      "Delete matching spaces that you govern and perform policy-specific deletion operations",
    ]);
  });

  it("rejects unresolved or malformed grants", () => {
    expect(describeSpaceConsent(parseSpacePermission(`space:${TYPE}`)))
      .toBeNull();
    expect(
      describeSpaceConsent({ ...grant(`space:${TYPE}`), actions: "bread" }),
    ).toBeNull();
  });
});
