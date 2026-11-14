import { P256Keypair } from "@atproto/crypto-spaces";
import { isValidDid } from "@atproto/syntax-spaces";
import { expect } from "@std/expect";
import {
  decideSpaceAccountAccess,
  decideSpaceClientAccess,
} from "../src/lib/spaces/policy-access";

const configPath = Deno.env.get("ALTERAN_REFERENCE_INTEROP_CONFIG");

Deno.test({
  name: "reference PDS: memberspace anonymous and client policy decisions",
  ignore: !configPath,
  fn: withRedactedReferenceErrors(async () => {
    if (!configPath) throw new Error("Reference configuration is required");
    const config: unknown = JSON.parse(await Deno.readTextFile(configPath));
    if (!config || typeof config !== "object") {
      throw new Error("Invalid reference configuration");
    }
    const fields = config as Record<string, unknown>;
    if (
      typeof fields.pds !== "string" || typeof fields.accessJwt !== "string" ||
      !fields.accessJwt || !isValidDid(fields.did)
    ) throw new Error("Invalid reference account");
    const origin = new URL(fields.pds);
    if (
      origin.protocol !== "http:" ||
      !["127.0.0.1", "localhost", "[::1]"].includes(origin.hostname) ||
      origin.username || origin.password || origin.pathname !== "/" ||
      origin.search || origin.hash
    ) {
      throw new Error("Reference test requires a loopback HTTP origin");
    }
    const authorization = `Bearer ${fields.accessJwt}`;
    const skey = `policy-${crypto.randomUUID()}`;
    const space = `at://${fields.did}/space/com.example.forum/${skey}`;
    const credentialKey = (await P256Keypair.create()).did();
    const request = (method: string, body: unknown, authenticated = false) =>
      fetch(
        `${origin.origin}/xrpc/${method}`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            ...(authenticated ? { authorization } : {}),
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(10_000),
          redirect: "manual",
        },
      );
    const update = async (policy: unknown) => {
      const response = await request("com.atproto.space.updateSpace", {
        space,
        policy,
      }, true);
      if (!response.ok) {
        throw new Error(
          `Reference policy update failed: HTTP ${response.status}`,
        );
      }
      await response.body?.cancel();
    };
    const authorize = () =>
      request("com.atproto.space.authorizeSpaceSync", { space, credentialKey });
    const membership = { tag: "not-checked" } as const;
    await withReferenceSpace(
      async () => {
        const initialPolicy = { $type: "com.atproto.memberspace.policy" };
        const creation = await request("com.atproto.space.createSpace", {
          spaceType: "com.example.forum",
          skey,
          policy: initialPolicy,
        }, true);
        if (!creation.ok) {
          throw new Error(
            `Reference Space creation failed: HTTP ${creation.status}`,
          );
        }
        await creation.body?.cancel();

        const initial = await authorize();
        expect(initial.status).toBe(400);
        expect((await initial.json() as { error: string }).error).toBe(
          "SpaceNotFound",
        );
        expect(
          decideSpaceAccountAccess(initialPolicy, {
            space,
            repo: null,
            action: "read",
            membership,
          }).tag,
        )
          .toBe("denied");

        const publicPolicy = { ...initialPolicy, publicRead: true };
        await update(publicPolicy);
        const permitted = await authorize();
        expect(permitted.status).toBe(200);
        await permitted.body?.cancel();
        expect(
          decideSpaceAccountAccess(publicPolicy, {
            space,
            repo: null,
            action: "read",
            membership,
          }).tag,
        )
          .toBe("allowed");

        const restricted = { ...publicPolicy, allowedApps: [] };
        await update(restricted);
        const rejected = await authorize();
        expect(rejected.status).toBe(400);
        expect((await rejected.json() as { error: string }).error).toBe(
          "AppNotAuthorized",
        );
        expect(decideSpaceClientAccess(restricted, { tag: "absent" }).tag).toBe(
          "denied",
        );
      },
      () =>
        cleanupReferenceSpace(() =>
          request("com.atproto.space.deleteSpace", { space }, true)
        ),
    );
  }),
});

async function withReferenceSpace<T>(
  action: () => Promise<T>,
  cleanup: () => Promise<void>,
): Promise<T> {
  try {
    return await action();
  } finally {
    await cleanup();
  }
}

async function cleanupReferenceSpace(
  send: () => Promise<Response>,
): Promise<void> {
  try {
    const response = await send();
    if (response.ok) {
      await response.body?.cancel();
      return;
    }
    const result: unknown = await response.json();
    if (
      response.status !== 400 || !result || typeof result !== "object" ||
      (result as { error?: unknown }).error !== "SpaceNotFound"
    ) throw new Error();
  } catch {
    throw new Error("Reference Space cleanup failed");
  }
}

Deno.test("reference cleanup runs after an uncertain create", async () => {
  for (const committed of [false, true]) {
    let exists = false;
    let cleanupCalls = 0;
    const lostResponse = new Error("lost create response");
    try {
      await withReferenceSpace(async () => {
        exists = committed;
        throw lostResponse;
      }, () =>
        cleanupReferenceSpace(() => {
          cleanupCalls++;
          if (exists) {
            exists = false;
            return Promise.resolve(new Response(null, { status: 200 }));
          }
          return Promise.resolve(
            new Response(
              JSON.stringify({ error: "SpaceNotFound" }),
              { status: 400 },
            ),
          );
        }));
      throw new Error("Create failure was not propagated");
    } catch (error) {
      if (error !== lostResponse) {
        throw new Error("Unexpected lifecycle result");
      }
    }
    if (exists || cleanupCalls !== 1) {
      throw new Error("Reference cleanup did not complete");
    }
  }
  let failed = false;
  try {
    await cleanupReferenceSpace(() =>
      Promise.resolve(
        new Response(
          JSON.stringify({ error: "harmless-private-sentinel" }),
          { status: 400 },
        ),
      )
    );
  } catch (error) {
    failed = error instanceof Error &&
      error.message === "Reference Space cleanup failed" &&
      !!error.stack && !error.stack.includes("harmless-private-sentinel");
  }
  if (!failed) throw new Error("Invalid cleanup response was accepted");
});

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
