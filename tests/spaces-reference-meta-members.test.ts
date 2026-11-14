import { isValidDid } from "@atproto/syntax-spaces";
import { expect } from "@std/expect";
import { readMetaFrames } from "../src/lib/spaces/meta-archive-framing";
import {
  readSpaceMetaArchive,
  readSpaceMetaArchiveWithMembers,
  writeSpaceMetaArchiveWithMembers,
} from "../src/lib/spaces/meta-archive";

const configPath = Deno.env.get("ALTERAN_REFERENCE_INTEROP_CONFIG");

Deno.test({
  name:
    "reference PDS round-trips members with an independent membership snapshot",
  ignore: !configPath,
  sanitizeOps: false,
  sanitizeResources: false,
  fn: withRedactedReferenceErrors(async () => {
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
    const expected = [
      { did: "did:example:a:b", read: true, write: false },
      { did: "did:web:localhost%3A2583", read: true, write: false },
      { did: "did:web:localhost:path", read: true, write: false },
    ];
    const keys = [
      "com.atproto.memberspace.member/did:example:a:b",
      "com.atproto.memberspace.member/did:web:localhost:2583",
      "com.atproto.memberspace.member/did:web:localhost:path",
    ];
    const policy = {
      $type: "com.atproto.memberspace.policy",
      publicRead: true,
      publicWrite: false,
      publishPolicy: false,
      publishMembers: false,
    } as const;
    const member = {
      $type: "com.atproto.memberspace.member",
      read: true,
      write: false,
    } as const;
    const encoded = writeSpaceMetaArchiveWithMembers({
      space,
      policy,
      policyState: expected.map(({ did }) => ({ did, value: member })),
      writers: [],
    });
    const body = new ArrayBuffer(encoded.byteLength);
    new Uint8Array(body).set(encoded);
    let attempted = false;
    try {
      attempted = true;
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
        throw new Error(`Reference import failed: ${imported.status}`);
      }
      const manifest: typeof expected = [];
      let cursor: string | undefined;
      for (let page = 0; page < 10; page++) {
        const params = new URLSearchParams({ space, limit: "2" });
        if (cursor) params.set("cursor", cursor);
        const listed = await fetch(
          `${origin}/xrpc/com.atproto.memberspace.listMembers?${params}`,
          {
            headers: { authorization },
            redirect: "manual",
            signal: AbortSignal.timeout(10_000),
          },
        );
        if (!listed.ok) {
          throw new Error(`Reference list failed: ${listed.status}`);
        }
        const result = await listed.json() as {
          cursor?: string;
          members: typeof expected;
        };
        manifest.push(...result.members);
        if (result.members.length === 0) break;
        if (!result.cursor || result.cursor === cursor) {
          throw new Error("Invalid member cursor");
        }
        cursor = result.cursor;
        if (page === 9) throw new Error("Member pagination limit exceeded");
      }
      expect(manifest).toEqual(expected);
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
        throw new Error(`Reference export failed: ${exported.status}`);
      }
      const exportedBytes = new Uint8Array(await exported.arrayBuffer());
      const frames = readMetaFrames(exportedBytes);
      expect(
        frames.pairs.slice(1).map(({ key }) => new TextDecoder().decode(key)),
      ).toEqual(keys);
      expect(() => readSpaceMetaArchive(exportedBytes, space)).toThrow();
      const result = readSpaceMetaArchiveWithMembers(
        exportedBytes,
        space,
        manifest,
      );
      expect(result.policyState.map(({ did }) => did)).toEqual(
        expected.map(({ did }) => did),
      );
      expect(() =>
        readSpaceMetaArchiveWithMembers(exportedBytes, space, manifest.slice(1))
      ).toThrow();
    } finally {
      if (attempted) {
        const deleted = await fetch(
          `${origin}/xrpc/com.atproto.space.deleteSpace`,
          {
            method: "POST",
            headers: { authorization, "content-type": "application/json" },
            body: JSON.stringify({ space }),
            redirect: "manual",
            signal: AbortSignal.timeout(10_000),
          },
        );
        if (
          !deleted.ok &&
          (await deleted.json() as { error?: string }).error !== "SpaceNotFound"
        ) {
          throw new Error(`Reference cleanup failed: ${deleted.status}`);
        }
      }
    }
  }),
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

function withRedactedReferenceErrors<T>(
  action: () => T | Promise<T>,
): () => Promise<T> {
  return async () => {
    try {
      return await action();
    } catch {
      throw new Error("Reference interoperability test failed");
    }
  };
}

Deno.test("reference failures do not expose sensitive values", async () => {
  const sentinel = "harmless-token-sentinel";
  const failures: Array<() => unknown | Promise<unknown>> = [
    () => JSON.parse(`{"accessJwt":${sentinel}}`),
    () => new URL(`http://[${sentinel}`),
    () => new Headers({ authorization: `Bearer ${sentinel}\0` }),
    () => expect(sentinel).toEqual("unexpected"),
    () =>
      new Response(
        new ReadableStream({
          pull(controller) {
            controller.error(new Error(sentinel));
          },
        }),
      ).text(),
    () =>
      new Response(
        new ReadableStream({
          cancel() {
            throw new Error(sentinel);
          },
        }),
      ).body?.cancel(),
  ];
  for (const fail of failures) {
    let error: unknown;
    try {
      await withRedactedReferenceErrors(fail)();
    } catch (caught) {
      error = caught;
    }
    if (
      !(error instanceof Error) ||
      error.message !== "Reference interoperability test failed" ||
      !error.stack || error.stack.includes(sentinel)
    ) throw new Error("Reference test error redaction failed");
  }
});
