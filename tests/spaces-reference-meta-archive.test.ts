import { isValidDid } from "@atproto/syntax-spaces";
import { expect } from "@std/expect";
import {
  readSpaceMetaArchive,
  writeSpaceMetaArchive,
} from "../src/lib/spaces/meta-archive";

const configPath = Deno.env.get("ALTERAN_REFERENCE_INTEROP_CONFIG");

Deno.test({
  name: "reference PDS imports and exports Space host metadata",
  ignore: !configPath,
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    if (!configPath) throw new Error("Missing reference configuration");
    const config: unknown = JSON.parse(await Deno.readTextFile(configPath));
    if (!config || typeof config !== "object") {
      throw new Error("Invalid reference configuration");
    }
    const fields = config as Record<string, unknown>;
    const origin = loopbackOrigin(fields.pds);
    if (
      !isValidDid(fields.did) || typeof fields.accessJwt !== "string" ||
      !fields.accessJwt
    ) {
      throw new Error("Invalid disposable reference account");
    }
    const authorization = `Bearer ${fields.accessJwt}`;
    const space =
      `at://${fields.did}/space/com.example.notes/meta-${crypto.randomUUID()}`;
    const memberKey = "com.atproto.memberspace.member/did:example:member";
    const revision = "3kbcq3p7ad42b";
    const input = {
      space,
      policy: {
        $type: "com.atproto.memberspace.policy" as const,
        publicRead: true,
        publicWrite: false,
        publishPolicy: false,
        publishMembers: false,
      },
      policyState: [{
        key: memberKey,
        value: {
          $type: "com.atproto.memberspace.member" as const,
          read: true,
          write: false,
        },
      }],
      writers: [{
        did: fields.did,
        repoRev: revision,
        data: new Uint8Array(32).fill(7),
        spaceRev: revision,
      }],
    };
    let attempted = false;
    try {
      attempted = true;
      const encoded = writeSpaceMetaArchive(input);
      const body = new ArrayBuffer(encoded.byteLength);
      new Uint8Array(body).set(encoded);
      const imported = await fetch(
        `${origin}/xrpc/com.atproto.space.importSpaceMeta`,
        {
          method: "POST",
          headers: {
            authorization,
            "content-type": "application/vnd.dasl.star",
          },
          body,
          redirect: "manual",
          signal: AbortSignal.timeout(10_000),
        },
      );
      if (!imported.ok) {
        throw new Error(
          `Reference metadata import returned HTTP ${imported.status}`,
        );
      }
      const params = new URLSearchParams({ space });
      const exported = await fetch(
        `${origin}/xrpc/com.atproto.space.exportSpaceMeta?${params}`,
        {
          headers: { authorization },
          redirect: "manual",
          signal: AbortSignal.timeout(10_000),
        },
      );
      if (!exported.ok) {
        throw new Error(
          `Reference metadata export returned HTTP ${exported.status}`,
        );
      }
      const result = readSpaceMetaArchive(
        new Uint8Array(await exported.arrayBuffer()),
        space,
      );
      expect(result.policy).toEqual(input.policy);
      expect(result.policyState).toEqual(input.policyState);
      expect(result.writers).toEqual(input.writers);
    } finally {
      if (attempted) {
        const cleanup = await fetch(
          `${origin}/xrpc/com.atproto.space.deleteSpace`,
          {
            method: "POST",
            headers: { authorization, "content-type": "application/json" },
            body: JSON.stringify({ space }),
            redirect: "manual",
            signal: AbortSignal.timeout(10_000),
          },
        );
        if (!cleanup.ok) {
          const error = await cleanup.json().catch(() => ({})) as {
            error?: unknown;
          };
          if (error.error !== "SpaceNotFound") {
            throw new Error(
              `Reference cleanup returned HTTP ${cleanup.status}`,
            );
          }
        }
      }
    }
  },
});

function loopbackOrigin(value: unknown): string {
  if (typeof value !== "string") throw new Error("A loopback URL is required");
  const url = new URL(value);
  if (
    url.protocol !== "http:" ||
    !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
    url.username || url.password || url.pathname !== "/" || url.search ||
    url.hash
  ) {
    throw new Error("Only a loopback reference PDS origin is allowed");
  }
  return url.origin;
}
