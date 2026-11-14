import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import {
  createExplicitSpaceConsent,
  restoreExplicitSpaceConsent,
  type ExplicitSpaceConsentBinding,
} from "../src/lib/spaces/explicit-read-consent";

const binding: ExplicitSpaceConsentBinding = {
  subject: "did:plc:alice",
  accountIncarnation: "e".repeat(32),
  clientId: "https://client.example/metadata.json",
  dpopJkt: "a".repeat(43),
  clientAuthMethod: "none",
  clientAuthKeyId: null,
  clientAuthKeyBinding: null,
};
const requested = "atproto space:com.example.forum?collection=com.example.post&action=read_self";

describe("explicit Space consent binding", () => {
  it("seals the original request, materialized scope and authenticated identity", async () => {
    const consent = await createExplicitSpaceConsent(binding, requested);
    if (!consent) throw new Error("Expected consent snapshot");
    const saved = JSON.parse(consent.serialized);
    expect(saved.requestedScope).toBe(requested);
    expect(saved.subject).toBe(binding.subject);
    expect(saved.clientId).toBe(binding.clientId);
    expect(saved.dpopJkt).toBe(binding.dpopJkt);
    expect(consent.tokenScope).toContain("authority=did%3Aplc%3Aalice");
    const restored = await restoreExplicitSpaceConsent(
      consent.serialized, consent.digest, binding, consent.tokenScope,
    );
    expect(restored?.grants[0].requestedScope).toBe(requested.split(" ")[1]);
    expect(restored?.grants[0].permission.actions).toEqual(["read_self"]);
  });

  it("rejects a changed subject, client, DPoP key, scope, digest or bytes", async () => {
    const consent = await createExplicitSpaceConsent(binding, requested);
    if (!consent) throw new Error("Expected consent snapshot");
    for (const different of [
      { ...binding, subject: "did:plc:bob" },
      { ...binding, accountIncarnation: "f".repeat(32) },
      { ...binding, clientId: "https://other.example/metadata.json" },
      { ...binding, dpopJkt: "b".repeat(43) },
      { ...binding, clientAuthMethod: "private_key_jwt" as const,
        clientAuthKeyId: "c".repeat(43), clientAuthKeyBinding: "jwk-thumbprint-v1" as const },
    ]) {
      expect(await restoreExplicitSpaceConsent(
        consent.serialized, consent.digest, different, consent.tokenScope,
      )).toBeNull();
    }
    expect(await restoreExplicitSpaceConsent(
      consent.serialized, "0".repeat(64), binding, consent.tokenScope,
    )).toBeNull();
    expect(await restoreExplicitSpaceConsent(
      consent.serialized, consent.digest, binding, "atproto",
    )).toBeNull();
    expect(await restoreExplicitSpaceConsent(
      `${consent.serialized} `, consent.digest, binding, consent.tokenScope,
    )).toBeNull();
  });

  it("returns the frozen grant captured in the sealed snapshot", async () => {
    const consent = await createExplicitSpaceConsent(binding, requested);
    if (!consent) throw new Error("Expected consent snapshot");
    expect(Object.isFrozen(consent)).toBe(true);
    expect(Object.isFrozen(consent.grants)).toBe(true);
    expect(Object.isFrozen(consent.grants[0].permission)).toBe(true);
    expect(Object.isFrozen(consent.grants[0].permission.actions)).toBe(true);
    expect(Object.isFrozen(consent.grants[0].permission.collections.values)).toBe(true);
    try {
      (consent.grants[0].permission.actions as string[]).push("create");
    } catch {
      // Strict mode rejects writes to the sealed view.
    }
    const restored = await restoreExplicitSpaceConsent(
      consent.serialized, consent.digest, binding, consent.tokenScope, requested,
    );
    expect(restored?.grants[0].permission.actions).toEqual(["read_self"]);
  });

  it("rejects default, mixed, duplicated, undeclared and oversized values", async () => {
    for (const value of [
      `${requested}&action=create`,
      `${requested}&manage=update`,
      `${requested} ${requested.split(" ")[1]}`,
      `atproto unsupported ${requested.split(" ")[1]}`,
      `atproto ${"x".repeat(17_000)}`,
    ]) expect(await createExplicitSpaceConsent(binding, value)).toBeNull();
  });

  it("seals and restores collection-free read_self without declaration evidence", async () => {
    const scope = "atproto space:com.example.forum?action=read_self";
    const consent = await createExplicitSpaceConsent(binding, scope);
    if (!consent) throw new Error("Expected consent snapshot");
    expect(consent.grants[0].permission.collectionSource).toBe("none");
    expect(consent.grants[0].permission.collections.values).toEqual([]);
    expect(consent.tokenScope).toContain("action=read_self");
    expect(consent.tokenScope).not.toContain("collection=");
    expect((await restoreExplicitSpaceConsent(consent.serialized, consent.digest, binding, consent.tokenScope))?.grants)
      .toEqual(consent.grants);
  });

  it("continues to restore the saved explicit-collection snapshot exactly", async () => {
    const saved = (await Deno.readTextFile(new URL("./fixtures/spaces-explicit-consent-v1.json", import.meta.url))).trimEnd();
    const digest = "de08deb47cdb2637ffc48e484cd779cf2cd85dc6d670c38e34a2ba9fac361d08";
    const consent = await createExplicitSpaceConsent(binding, requested);
    if (!consent) throw new Error("Expected consent snapshot");
    expect(consent.serialized).toBe(saved);
    expect(consent.digest).toBe(digest);
    expect(await restoreExplicitSpaceConsent(saved, digest, binding, consent.tokenScope)).not.toBeNull();
  });

  it("requires key provenance for confidential clients", async () => {
    const confidential: ExplicitSpaceConsentBinding = {
      ...binding, clientAuthMethod: "private_key_jwt",
      clientAuthKeyId: "c".repeat(43), clientAuthKeyBinding: "jwk-thumbprint-v1",
    };
    const consent = await createExplicitSpaceConsent(confidential, requested);
    expect(consent).not.toBeNull();
    expect(await createExplicitSpaceConsent({
      ...confidential, clientAuthKeyBinding: null,
    }, requested)).toBeNull();
    expect(await createExplicitSpaceConsent({
      ...binding, clientAuthKeyId: "c".repeat(43),
    }, requested)).toBeNull();
  });
});
