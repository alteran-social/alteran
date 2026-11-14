import { expect } from "@std/expect";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, it } from "./helpers/bdd";
import {
  createSpaceConsentSnapshot,
  restoreSpaceConsentSnapshot,
  type SpaceConsentGrant,
} from "../src/lib/spaces/consent-snapshot";
import {
  type IssuedSpacePermission,
  materializeSpacePermission,
  parseSpacePermission,
} from "../src/lib/spaces/oauth-scopes";

const SUBJECT = "did:plc:alice";
const CLIENT = "https://client.example/client-metadata.json";
const TYPE = "com.example.forum";
const THREAD = "com.example.thread";
const REPLY = "com.example.reply";

function grant(
  collections: readonly string[],
  scope = `space:${TYPE}`,
): SpaceConsentGrant {
  const requested = parseSpacePermission(scope);
  if (!requested) throw new Error("Expected valid request");
  const permission = materializeSpacePermission(requested, SUBJECT, {
    spaceType: requested.spaceType,
    collections,
  });
  if (!permission) throw new Error("Expected issued permission");
  return { requestedScope: scope, permission };
}

async function snapshot(
  grants: readonly SpaceConsentGrant[] = [grant([THREAD])],
) {
  const seal = await createSpaceConsentSnapshot({
    subject: SUBJECT,
    clientId: CLIENT,
    grants,
  });
  if (!seal) throw new Error("Expected snapshot");
  return {
    seal,
    binding: { subject: SUBJECT, clientId: CLIENT, digest: seal.digest },
  };
}

function digest(value: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(value)));
}

describe("space consent snapshots", () => {
  it("round-trips requested scopes and materialized permissions", async () => {
    const grants = [
      grant([THREAD, REPLY]),
      grant([], "space:com.example.other?skey=other"),
    ];
    const { seal, binding } = await snapshot(grants);
    const restored = await restoreSpaceConsentSnapshot(
      seal.serialized,
      binding,
    );
    expect(restored).toEqual({
      version: 1,
      subject: SUBJECT,
      clientId: CLIENT,
      grants,
    });
    expect(restored?.grants[1].permission.collections.values).toEqual([]);
    expect(restored?.grants[0].permission.collectionSource).toBe("declaration");
    expect(seal.digest).toBe(digest(seal.serialized));
  });

  it("captures independent copies before asynchronous hashing", async () => {
    const collectionValues = [THREAD];
    const item = grant(collectionValues);
    const grants = [item];
    const pending = createSpaceConsentSnapshot({
      subject: SUBJECT,
      clientId: CLIENT,
      grants,
    });
    collectionValues.push(REPLY);
    (item.permission.collections.values as string[]).push(REPLY);
    (item.permission.actions as string[]).length = 0;
    grants.push(grant([REPLY]));
    const seal = await pending;
    if (!seal) throw new Error("Expected snapshot");
    const restored = await restoreSpaceConsentSnapshot(seal.serialized, {
      subject: SUBJECT,
      clientId: CLIENT,
      digest: seal.digest,
    });
    expect(restored?.grants).toEqual([grant([THREAD])]);
  });

  it("binds restoration to the original subject, client, and digest", async () => {
    const { seal, binding } = await snapshot();
    for (
      const badBinding of [
        { ...binding, subject: "did:plc:bob" },
        { ...binding, clientId: "https://other.example/client.json" },
        { ...binding, digest: "0".repeat(64) },
        { ...binding, digest: binding.digest.toUpperCase() },
      ]
    ) {
      expect(await restoreSpaceConsentSnapshot(seal.serialized, badBinding))
        .toBeNull();
    }
  });

  it("rejects changes to an authenticated snapshot", async () => {
    const { seal, binding } = await snapshot();
    expect(
      await restoreSpaceConsentSnapshot(
        seal.serialized.replace(THREAD, REPLY),
        binding,
      ),
    )
      .toBeNull();
    expect(await restoreSpaceConsentSnapshot(`${seal.serialized} `, binding))
      .toBeNull();
  });

  it("captures the authenticated binding before awaiting the digest", async () => {
    const { seal, binding } = await snapshot();
    const mutable = { ...binding, digest: "0".repeat(64) };
    const pending = restoreSpaceConsentSnapshot(seal.serialized, mutable);
    mutable.digest = seal.digest;
    expect(await pending).toBeNull();
  });

  it("rejects changing and throwing getters instead of sealing their values", async () => {
    const item = grant([THREAD]);
    let calls = 0;
    const changing = { ...item };
    Object.defineProperty(changing, "requestedScope", {
      enumerable: true,
      get() {
        calls++;
        return calls === 1 ? `space:${TYPE}` : `space:${TYPE}?collection=*`;
      },
    });
    expect(
      await createSpaceConsentSnapshot({
        subject: SUBJECT,
        clientId: CLIENT,
        grants: [changing],
      }),
    )
      .toBeNull();
    expect(calls).toBe(0);
    const throwing = { ...item.permission };
    Object.defineProperty(throwing, "actions", {
      enumerable: true,
      get() {
        throw new Error("getter called");
      },
    });
    expect(
      await createSpaceConsentSnapshot({
        subject: SUBJECT,
        clientId: CLIENT,
        grants: [{ ...item, permission: throwing }],
      }),
    ).toBeNull();
    const array = [item];
    Object.defineProperty(array, "0", { enumerable: true, get: () => item });
    expect(
      await createSpaceConsentSnapshot({
        subject: SUBJECT,
        clientId: CLIENT,
        grants: array,
      }),
    )
      .toBeNull();
    const { seal, binding } = await snapshot();
    Object.defineProperty(binding, "digest", {
      enumerable: true,
      get: () => seal.digest,
    });
    expect(await restoreSpaceConsentSnapshot(seal.serialized, binding))
      .toBeNull();
  });

  it("returns a deeply frozen copy for use across asynchronous work", async () => {
    const { seal, binding } = await snapshot();
    const restored = await restoreSpaceConsentSnapshot(
      seal.serialized,
      binding,
    );
    if (!restored) throw new Error("Expected snapshot");
    const permission = restored.grants[0].permission;
    for (
      const value of [
        restored,
        restored.grants,
        restored.grants[0],
        permission,
        permission.collections,
        permission.collections.values,
        permission.actions,
        permission.manage,
      ]
    ) {
      expect(Object.isFrozen(value)).toBe(true);
    }
  });

  it("rejects malformed stored data even when the supplied digest matches", async () => {
    const { seal, binding } = await snapshot();
    const original = JSON.parse(seal.serialized);
    const entry = original.grants[0];
    const permission = entry.permission;
    const withPermission = (replacement: unknown) => ({
      ...original,
      grants: [{ ...entry, permission: replacement }],
    });
    const malformed = [
      null,
      { ...original, version: 2 },
      { ...original, extra: true },
      { ...original, subject: "not-a-did" },
      withPermission({ ...permission, actions: "read" }),
      withPermission({
        ...permission,
        collections: { tag: "explicit", values: "*" },
      }),
      withPermission({ ...permission, authority: "self" }),
      withPermission({ ...permission, tag: "declaration" }),
      withPermission({ ...permission, collectionSource: "other" }),
      withPermission({
        ...permission,
        collections: { tag: "explicit", values: ["*"] },
      }),
      withPermission({
        ...permission,
        collectionSource: "explicit",
        collections: { tag: "explicit", values: [] },
      }),
      { ...original, grants: [entry, entry] },
    ];
    for (const value of malformed) {
      const serialized = JSON.stringify(value);
      expect(
        await restoreSpaceConsentSnapshot(serialized, {
          ...binding,
          digest: digest(serialized),
        }),
      )
        .toBeNull();
    }
    expect(await restoreSpaceConsentSnapshot("{not-json", binding)).toBeNull();
  });

  it("rejects an issued grant paired with a different original scope", async () => {
    const { seal, binding } = await snapshot();
    const original = JSON.parse(seal.serialized);
    const entry = original.grants[0];
    for (
      const badEntry of [
        { ...entry, requestedScope: `space:${TYPE}?collection=${THREAD}` },
        { ...entry, requestedScope: `space:${TYPE}?action=read_self` },
        { ...entry, requestedScope: `space:${TYPE}?authority=did%3Aplc%3Abob` },
        {
          ...entry,
          permission: { ...entry.permission, collectionSource: "explicit" },
        },
        {
          ...entry,
          permission: { ...entry.permission, actions: ["read", "delete"] },
        },
      ]
    ) {
      const serialized = JSON.stringify({ ...original, grants: [badEntry] });
      expect(
        await restoreSpaceConsentSnapshot(serialized, {
          ...binding,
          digest: digest(serialized),
        }),
      )
        .toBeNull();
    }
  });

  it("requires one declaration snapshot per space type", async () => {
    const first = grant([THREAD]);
    const equivalent = grant([REPLY], `space?spaceType=${TYPE}`);
    expect(
      await createSpaceConsentSnapshot({
        subject: SUBJECT,
        clientId: CLIENT,
        grants: [first, equivalent],
      }),
    ).toBeNull();
    expect(
      await createSpaceConsentSnapshot({
        subject: SUBJECT,
        clientId: CLIENT,
        grants: [first, grant([THREAD], `space?spaceType=${TYPE}`)],
      }),
    ).not.toBeNull();
  });

  it("rejects oversized or invalid inputs without truncating a grant", async () => {
    const normal = grant([THREAD]);
    const excessive = {
      ...normal,
      permission: {
        ...normal.permission,
        collections: {
          tag: "explicit" as const,
          values: Array(129).fill(THREAD),
        },
      },
    };
    for (
      const input of [
        {
          subject: SUBJECT,
          clientId: CLIENT,
          grants: Array.from({ length: 129 }, () => normal),
        },
        { subject: SUBJECT, clientId: CLIENT, grants: [excessive] },
        { subject: SUBJECT, clientId: "x".repeat(2049), grants: [] },
        { subject: "invalid", clientId: CLIENT, grants: [] },
      ]
    ) expect(await createSpaceConsentSnapshot(input)).toBeNull();
    const { binding } = await snapshot();
    expect(await restoreSpaceConsentSnapshot("x".repeat(65537), binding))
      .toBeNull();
  });

  it("does not materialize raw or malformed grants while creating a snapshot", async () => {
    const raw = parseSpacePermission(`space:${TYPE}`);
    const malformed = { ...grant([THREAD]).permission, actions: "bread" };
    for (const permission of [raw, malformed]) {
      expect(
        await createSpaceConsentSnapshot({
          subject: SUBJECT,
          clientId: CLIENT,
          grants: [{
            requestedScope: `space:${TYPE}`,
            permission: permission as unknown as IssuedSpacePermission,
          }],
        }),
      ).toBeNull();
    }
  });
});
