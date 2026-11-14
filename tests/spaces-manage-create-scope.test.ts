import { SpacePermission as ReferenceSpacePermission } from "@atproto/oauth-scopes";
import { describe, it } from "@std/testing/bdd";
import { expect } from "@std/expect";
import { formatSpaceTokenScope } from "../src/lib/oauth/space-token-scope";
import { resolveRequestedScope } from "../src/lib/oauth/requested-scope";
import { describeSpaceConsent } from "../src/lib/spaces/consent-display";
import {
  createSpaceConsentSnapshot,
  restoreSpaceConsentSnapshot,
} from "../src/lib/spaces/consent-snapshot";
import {
  createExplicitSpaceConsent,
  type ExplicitSpaceConsentBinding,
  restoreExplicitSpaceConsent,
} from "../src/lib/spaces/explicit-read-consent";
import {
  allowsSpacePermission,
  copyIssuedSpacePermission,
  materializeCollectionFreeReadSelf,
  materializeCollectionFreeReadSelfManageCreate,
  parseSpacePermission,
} from "../src/lib/spaces/oauth-scopes";

const SUBJECT = "did:plc:abcdefghijklmnopqrstuvwx";
const OTHER = "did:plc:bcdefghijklmnopqrstuvwxy";
const CLIENT = "https://client.example/client-metadata.json";
const TYPE = "com.example.forum";
const COLLECTION = "com.example.post";
const SCOPE = `space:${TYPE}?skey=general&action=read_self&manage=create`;
const OLD_SCOPE = `space:${TYPE}?action=read_self`;
const OLD_SERIALIZED = [
  '{"version":2,"subject":"did:plc:abcdefghijklmnopqrstuvwx",',
  '"clientId":"https://client.example/client-metadata.json","grants":[{',
  '"requestedScope":"space:com.example.forum?action=read_self","permission":{',
  '"spaceType":"com.example.forum","authority":"did:plc:abcdefghijklmnopqrstuvwx",',
  '"skey":"*","collections":{"tag":"explicit","values":[]},',
  '"actions":["read_self"],"manage":[],"tag":"issued","collectionSource":"none"}}],',
  '"declarations":[]}',
].join("");
const BINDING: ExplicitSpaceConsentBinding = {
  subject: SUBJECT,
  accountIncarnation: "e".repeat(32),
  clientId: CLIENT,
  dpopJkt: "a".repeat(43),
  clientAuthMethod: "none",
  clientAuthKeyId: null,
  clientAuthKeyBinding: null,
};

type MutableSnapshot = {
  subject: string;
  clientId: string;
  grants: {
    requestedScope: string;
    permission: {
      tag: string;
      collectionSource: string;
      spaceType: string;
      authority: string;
      skey: string;
      collections: { values: string[] };
      actions: string[];
      manage: string[];
    };
  }[];
};

function grant(scope = SCOPE) {
  const permission = materializeCollectionFreeReadSelfManageCreate(
    scope,
    SUBJECT,
  );
  if (!permission) throw new Error("Expected a create-management grant");
  return { requestedScope: scope, permission };
}

function wireScope(permission: unknown): string {
  const result = formatSpaceTokenScope({
    otherScopes: ["atproto"],
    grants: [permission],
  });
  if (result.tag !== "formatted") throw new Error("Could not format scope");
  const scope = result.scope.split(" ").find((part) =>
    part.startsWith("space:")
  );
  if (!scope) throw new Error("Missing Space scope");
  return scope;
}

async function seal(grants: readonly unknown[]) {
  return await createSpaceConsentSnapshot({
    subject: SUBJECT,
    clientId: CLIENT,
    grants: grants as ReturnType<typeof grant>[],
    declarations: [],
  });
}

async function digest(serialized: string): Promise<string> {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(serialized),
  );
  return [...new Uint8Array(bytes)].map((byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

describe("collection-free create-management grant", () => {
  it("accepts the pinned reference scope and resolves authority immutably", () => {
    const referenceRequest = ReferenceSpacePermission.scopeNeededFor({
      spaceType: TYPE,
      authority: SUBJECT,
      skey: "general",
      manage: "create",
    });
    const permission = materializeCollectionFreeReadSelfManageCreate(
      referenceRequest,
      SUBJECT,
    );
    if (!permission) throw new Error("Expected reference creation scope");
    expect(permission.collectionSource).toBe("none_manage_create");
    expect(permission.collections.values).toEqual([]);
    expect(permission.actions).toEqual(["read_self"]);
    expect(permission.manage).toEqual(["create"]);
    expect(Object.isFrozen(permission)).toBe(true);
    expect(Object.isFrozen(permission.collections.values)).toBe(true);
    expect(Object.isFrozen(permission.actions)).toBe(true);
    expect(Object.isFrozen(permission.manage)).toBe(true);
    expect(grant().permission.authority).toBe(SUBJECT);
    expect(materializeCollectionFreeReadSelfManageCreate(SCOPE, "not-a-did"))
      .toBeNull();
    expect(
      materializeCollectionFreeReadSelfManageCreate(
        SCOPE,
        "did:web:example.com%3A8443",
      ),
    ).toBeNull();
  });

  it("requires exactly one explicit read_self and create management parameter", () => {
    for (
      const scope of [
        `space:${TYPE}?manage=create`,
        `space:${TYPE}?action=read_self`,
        `space:${TYPE}?action=read&manage=create`,
        `space:${TYPE}?action=create&manage=create`,
        `space:${TYPE}?action=read_self&action=read_self&manage=create`,
        `space:${TYPE}?action=read_self&a%63tion=read_self&manage=create`,
        `space:${TYPE}?action=read_self&action=create&manage=create`,
        `space:${TYPE}?action=read_self&manage=create&manage=create`,
        `space:${TYPE}?action=read_self&manage=create&manage=delete`,
        `space:${TYPE}?action=read_self&manage=update`,
        `space:${TYPE}?action=read_self&manage=delete`,
        `space:${TYPE}?action=read_self&manage=create&collection=${COLLECTION}`,
        `space:${TYPE}?action=read_self&manage=create&collection=`,
        `space:${TYPE}?action=read_self&manage=create&extra=value`,
        `space:${TYPE}?authority=did%3Aweb%3Alocalhost%253A1234&action=read_self&manage=create`,
        `space:${TYPE}?action=read_self&manage=create&authority=self&authority=self`,
        `space:${TYPE}?action=read_self&manage=create&padding=${
          "a".repeat(8192)
        }`,
        `${SCOPE}&${"a".repeat(2_000_000)}`,
      ]
    ) {
      expect(materializeCollectionFreeReadSelfManageCreate(scope, SUBJECT))
        .toBeNull();
    }
  });

  it("matches the reference for fixed and wildcard targets without granting record writes", () => {
    const scopes = [
      SCOPE,
      `space:${TYPE}?authority=*&skey=general&action=read_self&manage=create`,
      "space:*?authority=*&skey=*&action=read_self&manage=create",
    ];
    const targets = [
      { spaceType: TYPE, authority: SUBJECT, skey: "general" },
      { spaceType: TYPE, authority: OTHER, skey: "general" },
      { spaceType: TYPE, authority: SUBJECT, skey: "other" },
      { spaceType: "com.example.other", authority: SUBJECT, skey: "general" },
    ] as const;
    const operations = [
      { action: "read_self" },
      { action: "read" },
      { action: "create", collection: COLLECTION },
      { action: "update", collection: COLLECTION },
      { action: "delete", collection: COLLECTION },
      { manage: "create" },
      { manage: "update" },
      { manage: "delete" },
    ] as const;
    for (const scope of scopes) {
      const permission = grant(scope).permission;
      const wire = wireScope(permission);
      expect(wire).not.toContain("collection=");
      const reference = ReferenceSpacePermission.fromString(wire);
      if (!reference) throw new Error("Reference rejected formatted scope");
      for (const target of targets) {
        for (const operation of operations) {
          expect(reference.matches({ ...target, ...operation }))
            .toBe(allowsSpacePermission(permission, target, operation));
        }
      }
      const target = targets[0];
      expect(allowsSpacePermission(permission, target, { action: "read_self" }))
        .toBe(true);
      expect(allowsSpacePermission(permission, target, { manage: "create" }))
        .toBe(true);
      for (const action of ["create", "update", "delete"] as const) {
        expect(
          allowsSpacePermission(permission, target, {
            action,
            collection: COLLECTION,
          }),
        ).toBe(false);
      }
      expect(allowsSpacePermission(permission, target, { action: "read" }))
        .toBe(false);
    }
    const disclosure = describeSpaceConsent(grant().permission);
    expect(
      disclosure?.permissions.some((value) =>
        value.includes("all collections")
      ),
    ).toBe(true);
    expect(
      disclosure?.permissions.some((value) =>
        value.includes("Create matching spaces")
      ),
    ).toBe(true);
    expect(
      disclosure?.permissions.some((value) => value.includes("Create records")),
    ).toBe(false);
  });

  it("rejects forged provenance and permission bits before formatting", () => {
    const permission = grant().permission;
    for (
      const forged of [
        {
          ...permission,
          collections: { tag: "explicit", values: [COLLECTION] },
        },
        { ...permission, actions: ["read_self", "create"] },
        { ...permission, actions: ["read"] },
        { ...permission, manage: [] },
        { ...permission, manage: ["create", "update"] },
        { ...permission, collectionSource: "none" },
        { ...permission, collectionSource: "explicit" },
        { ...permission, authority: "did:web:example.com%3A8443" },
      ]
    ) {
      expect(copyIssuedSpacePermission(forged)).toBeNull();
      expect(
        formatSpaceTokenScope({ otherScopes: ["atproto"], grants: [forged] })
          .tag,
      ).toBe("invalid");
    }
  });

  it("reconstructs the new provenance from the original request and freezes it", async () => {
    const entry = grant();
    const saved = await seal([entry]);
    if (!saved) throw new Error("Expected snapshot");
    const restored = await restoreSpaceConsentSnapshot(saved.serialized, {
      subject: SUBJECT,
      clientId: CLIENT,
      digest: saved.digest,
    });
    expect(restored?.grants).toEqual([entry]);
    expect(Object.isFrozen(restored?.grants[0].permission)).toBe(true);
    expect(Object.isFrozen(restored?.grants[0].permission.manage)).toBe(true);
    expect(await seal([entry, entry])).toBeNull();

    const editable = structuredClone(entry);
    const pending = seal([editable]);
    (editable.permission.manage as string[]).push("delete");
    expect((await pending)?.serialized).toBe(saved.serialized);
  });

  it("rejects tampering even when a forged snapshot has a matching digest", async () => {
    const saved = await seal([grant()]);
    if (!saved) throw new Error("Expected snapshot");
    const mutations: readonly ((snapshot: MutableSnapshot) => void)[] = [
      (snapshot) => snapshot.subject = OTHER,
      (snapshot) => snapshot.clientId = "https://other.example/metadata.json",
      (snapshot) => snapshot.grants[0].requestedScope = OLD_SCOPE,
      (snapshot) => snapshot.grants[0].requestedScope += "&action=read_self",
      (snapshot) =>
        snapshot.grants[0].permission.spaceType = "com.example.other",
      (snapshot) => snapshot.grants[0].permission.authority = OTHER,
      (snapshot) => snapshot.grants[0].permission.skey = "other",
      (snapshot) => snapshot.grants[0].permission.actions.push("create"),
      (snapshot) => snapshot.grants[0].permission.manage.push("update"),
      (snapshot) =>
        snapshot.grants[0].permission.collections.values.push(COLLECTION),
      (snapshot) => snapshot.grants[0].permission.collectionSource = "none",
      (snapshot) =>
        snapshot.grants[0].permission.collectionSource = "declaration",
      (snapshot) => snapshot.grants[0].permission.tag = "other",
      (snapshot) => snapshot.grants.push(structuredClone(snapshot.grants[0])),
    ];
    for (const mutate of mutations) {
      const value = JSON.parse(saved.serialized) as MutableSnapshot;
      mutate(value);
      const serialized = JSON.stringify(value);
      expect(
        await restoreSpaceConsentSnapshot(serialized, {
          subject: SUBJECT,
          clientId: CLIENT,
          digest: await digest(serialized),
        }),
      ).toBeNull();
    }
    expect(
      await restoreSpaceConsentSnapshot(saved.serialized, {
        subject: SUBJECT,
        clientId: CLIENT,
        digest: "0".repeat(64),
      }),
    ).toBeNull();
  });

  it("preserves the saved read-only snapshot and composes the two provenances", async () => {
    const requested = parseSpacePermission(OLD_SCOPE);
    if (!requested) throw new Error("Expected old scope");
    const permission = materializeCollectionFreeReadSelf(requested, SUBJECT);
    if (!permission) throw new Error("Expected old permission");
    const read = { requestedScope: OLD_SCOPE, permission };
    const previous = await seal([read]);
    if (!previous) throw new Error("Expected old snapshot");
    expect(previous.serialized).toBe(OLD_SERIALIZED);
    expect(previous.digest).toBe(
      "2bc358a877d6dbb1973c8b76a1fa54fe093177e8c45ec63ebfa1a894156af6c1",
    );
    const mixed = await seal([read, grant()]);
    if (!mixed) throw new Error("Expected mixed snapshot");
    const restored = await restoreSpaceConsentSnapshot(mixed.serialized, {
      subject: SUBJECT,
      clientId: CLIENT,
      digest: mixed.digest,
    });
    expect(restored?.grants.map((entry) => entry.permission.collectionSource))
      .toEqual(["none", "none_manage_create"]);
  });

  it("does not enable public consent issuance or restoration", async () => {
    const requested = `atproto ${SCOPE}`;
    expect(resolveRequestedScope(requested, requested)).toEqual({
      tag: "granted",
      scope: "atproto",
    });
    expect(await createExplicitSpaceConsent(BINDING, requested))
      .toBeNull();
    const old = await createExplicitSpaceConsent(
      BINDING,
      `atproto ${OLD_SCOPE}`,
    );
    const created = await seal([grant()]);
    if (!old || !created) throw new Error("Expected independent snapshots");
    const serialized = JSON.stringify({
      ...JSON.parse(old.serialized),
      requestedScope: `atproto ${SCOPE}`,
      tokenScope: `atproto ${wireScope(grant().permission)}`,
      consentSnapshot: created.serialized,
      consentDigest: created.digest,
    });
    expect(
      await restoreExplicitSpaceConsent(
        serialized,
        await digest(serialized),
        BINDING,
        `atproto ${wireScope(grant().permission)}`,
      ),
    ).toBeNull();
  });
});
