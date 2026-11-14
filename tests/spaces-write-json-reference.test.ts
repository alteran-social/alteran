import { expect } from "@std/expect";
import { isValidDid } from "@atproto/syntax-spaces";
import { parseSpaceWriteJson } from "../src/lib/spaces/write-json";

const configPath = Deno.env.get("ALTERAN_REFERENCE_INTEROP_CONFIG");
const encoder = new TextEncoder();

Deno.test({
  name: "ordinary exact JSON numbers agree with the disposable reference PDS",
  ignore: !configPath,
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    if (!configPath) throw new Error("Missing reference configuration");
    const config = await readConfig(configPath);
    const origin = loopbackOrigin(config.pds);
    if (
      !isValidDid(config.did) || typeof config.accessJwt !== "string" ||
      !config.accessJwt
    ) {
      throw new Error("Invalid disposable reference account");
    }
    const spaceType = "com.example.notes";
    const collection = "com.example.note";
    const skey = `parser-${crypto.randomUUID()}`;
    const space = `at://${config.did}/space/${spaceType}/${skey}`;
    const headers = {
      authorization: `Bearer ${config.accessJwt}`,
      "content-type": "application/json",
    };
    const send = async (path: string, init: RequestInit = {}) => {
      try {
        return await fetch(`${origin}/xrpc/${path}`, {
          ...init,
          headers,
          redirect: "manual",
          signal: AbortSignal.timeout(10_000),
        });
      } catch {
        throw new Error("Reference request failed");
      }
    };
    const post = (path: string, body: string) =>
      send(path, { method: "POST", body });
    let attempted = false;
    try {
      attempted = true;
      const created = await post(
        "com.atproto.space.createSpace",
        JSON.stringify({
          spaceType,
          skey,
          policy: { $type: "com.atproto.personalspace.policy" },
        }),
      );
      if (!created.ok) {
        throw new Error(`Reference create failed: HTTP ${created.status}`);
      }
      await created.body?.cancel();
      const cases = [["1.000", 1], ["-100e-2", -1], ["4.2e+1", 42], [
        "9.007199254740991e15",
        9007199254740991,
      ]] as const;
      for (let index = 0; index < cases.length; index++) {
        const [literal, expected] = cases[index];
        const rkey = `n${index}`;
        const body =
          `{"space":${JSON.stringify(space)},"repo":${
            JSON.stringify(config.did)
          },` +
          `"collection":${JSON.stringify(collection)},"rkey":${
            JSON.stringify(rkey)
          },"validate":false,` +
          `"record":{"$type":${JSON.stringify(collection)},"n":${literal}}}`;
        const parsed = parseSpaceWriteJson(encoder.encode(body));
        if (parsed.tag !== "valid") {
          throw new Error("Local parser rejected reference input");
        }
        const local = parsed.value as {
          readonly record: { readonly n: unknown };
        };
        expect(local.record.n).toBe(expected);
        const written = await post("com.atproto.space.createRecord", body);
        if (!written.ok) {
          throw new Error(`Reference write failed: HTTP ${written.status}`);
        }
        await written.body?.cancel();
        const query = new URLSearchParams({
          space,
          repo: config.did,
          collection,
          rkey,
        });
        const read = await send(`com.atproto.space.getRecord?${query}`);
        if (!read.ok) {
          throw new Error(`Reference read failed: HTTP ${read.status}`);
        }
        const value: unknown = await read.json().catch(() => {
          throw new Error("Invalid reference response");
        });
        const record = value as { readonly value?: { readonly n?: unknown } };
        expect(record.value?.n).toBe(expected);
      }
    } finally {
      if (attempted) {
        const removed = await post(
          "com.atproto.space.deleteSpace",
          JSON.stringify({ space }),
        );
        if (!removed.ok) {
          const response: unknown = await removed.json().catch(() => null);
          if (
            !response || typeof response !== "object" ||
            !("error" in response) ||
            response.error !== "SpaceNotFound"
          ) throw new Error(`Reference cleanup failed: HTTP ${removed.status}`);
        } else await removed.body?.cancel();
      }
    }
  },
});

async function readConfig(path: string): Promise<Record<string, unknown>> {
  try {
    const value: unknown = JSON.parse(await Deno.readTextFile(path));
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
  } catch { /* Return a fixed error below. */ }
  throw new Error("Invalid reference configuration");
}

function loopbackOrigin(value: unknown): string {
  if (typeof value === "string") {
    try {
      const url = new URL(value);
      if (
        url.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) &&
        !url.username && !url.password && url.pathname === "/" && !url.search &&
        !url.hash
      ) return url.origin;
    } catch { /* Return a fixed error below. */ }
  }
  throw new Error("Only a loopback reference PDS origin is allowed");
}
