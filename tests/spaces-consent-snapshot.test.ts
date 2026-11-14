import { expect } from "@std/expect";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, it } from "./helpers/bdd";
import {
  createSpaceConsentSnapshot,
  restoreSpaceConsentSnapshot,
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

function permission(collections: readonly string[]): IssuedSpacePermission {
  const requested = parseSpacePermission(`space:${TYPE}`);
  if (!requested) throw new Error("Expected valid request");
  const issued = materializeSpacePermission(requested, SUBJECT, {
    spaceType: TYPE,
    collections,
  });
  if (!issued) throw new Error("Expected issued permission");
  return issued;
}

async function snapshot(
  permissions: readonly IssuedSpacePermission[] = [permission([THREAD])],
) {
  const seal = await createSpaceConsentSnapshot({
    subject: SUBJECT,
    clientId: CLIENT,
    permissions,
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
  it("round-trips materialized permissions and preserves empty collections", async () => {
    const { seal, binding } = await snapshot([
      permission([THREAD, REPLY]),
      permission([]),
    ]);
    const restored = await restoreSpaceConsentSnapshot(
      seal.serialized,
      binding,
    );
    expect(restored).toEqual({
      version: 1,
      subject: SUBJECT,
      clientId: CLIENT,
      permissions: [permission([THREAD, REPLY]), permission([])],
    });
    expect(restored?.permissions[1].collections.values).toEqual([]);
    expect(seal.digest).toBe(digest(seal.serialized));
  });

  it("captures independent copies before asynchronous hashing", async () => {
    const collectionValues = [THREAD];
    const issued = permission(collectionValues);
    const permissions = [issued];
    const pending = createSpaceConsentSnapshot({
      subject: SUBJECT,
      clientId: CLIENT,
      permissions,
    });
    collectionValues.push(REPLY);
    (issued.collections.values as string[]).push(REPLY);
    (issued.actions as string[]).length = 0;
    permissions.push(permission([REPLY]));
    const seal = await pending;
    if (!seal) throw new Error("Expected snapshot");
    const restored = await restoreSpaceConsentSnapshot(seal.serialized, {
      subject: SUBJECT,
      clientId: CLIENT,
      digest: seal.digest,
    });
    expect(restored?.permissions).toEqual([permission([THREAD])]);
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

  it("rejects a changed grant even if the subject and client still match", async () => {
    const { seal, binding } = await snapshot();
    const altered = seal.serialized.replace(THREAD, REPLY);
    expect(await restoreSpaceConsentSnapshot(altered, binding)).toBeNull();
    expect(await restoreSpaceConsentSnapshot(`${seal.serialized} `, binding))
      .toBeNull();
  });

  it("uses the authenticated binding captured at the beginning of restoration", async () => {
    const { seal, binding } = await snapshot();
    const mutable = { ...binding, digest: "0".repeat(64) };
    const pending = restoreSpaceConsentSnapshot(seal.serialized, mutable);
    mutable.digest = seal.digest;
    expect(await pending).toBeNull();
  });

  it("rejects malformed stored data even when the supplied digest matches", async () => {
    const { seal, binding } = await snapshot();
    const original = JSON.parse(seal.serialized);
    const malformed = [
      null,
      { ...original, version: 2 },
      { ...original, extra: true },
      { ...original, subject: "not-a-did" },
      {
        ...original,
        permissions: [{ ...original.permissions[0], actions: "read" }],
      },
      {
        ...original,
        permissions: [{
          ...original.permissions[0],
          collections: { tag: "explicit", values: "*" },
        }],
      },
      {
        ...original,
        permissions: [{ ...original.permissions[0], authority: "self" }],
      },
      {
        ...original,
        permissions: [{ ...original.permissions[0], tag: "declaration" }],
      },
    ];
    for (const value of malformed) {
      const serialized = JSON.stringify(value);
      expect(
        await restoreSpaceConsentSnapshot(serialized, {
          ...binding,
          digest: digest(serialized),
        }),
      ).toBeNull();
    }
    expect(await restoreSpaceConsentSnapshot("{not-json", binding)).toBeNull();
  });

  it("rejects oversized or invalid snapshot inputs without truncating a grant", async () => {
    const normal = permission([THREAD]);
    expect(
      await createSpaceConsentSnapshot({
        subject: SUBJECT,
        clientId: CLIENT,
        permissions: Array.from({ length: 129 }, () => normal),
      }),
    ).toBeNull();
    const excessive = {
      ...normal,
      collections: {
        tag: "explicit" as const,
        values: Array(129).fill(THREAD),
      },
    };
    expect(
      await createSpaceConsentSnapshot({
        subject: SUBJECT,
        clientId: CLIENT,
        permissions: [excessive],
      }),
    ).toBeNull();
    expect(
      await createSpaceConsentSnapshot({
        subject: SUBJECT,
        clientId: "x".repeat(2049),
        permissions: [],
      }),
    ).toBeNull();
    expect(
      await createSpaceConsentSnapshot({
        subject: "invalid",
        clientId: CLIENT,
        permissions: [],
      }),
    ).toBeNull();
    const { binding } = await snapshot();
    expect(await restoreSpaceConsentSnapshot("x".repeat(65537), binding))
      .toBeNull();
  });

  it("does not materialize raw or malformed grants while creating a snapshot", async () => {
    const raw = parseSpacePermission(`space:${TYPE}`);
    expect(
      await createSpaceConsentSnapshot({
        subject: SUBJECT,
        clientId: CLIENT,
        permissions: [raw as unknown as IssuedSpacePermission],
      }),
    ).toBeNull();
    const malformed = {
      ...permission([THREAD]),
      actions: "bread",
    } as unknown as IssuedSpacePermission;
    expect(
      await createSpaceConsentSnapshot({
        subject: SUBJECT,
        clientId: CLIENT,
        permissions: [malformed],
      }),
    ).toBeNull();
  });
});
