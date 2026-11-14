import { expect } from "@std/expect";
import { Miniflare } from "miniflare";
import { join } from "node:path";

Deno.test({
  name: "bounded Space write JSON in the configured Worker runtime",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const source = import.meta.dirname;
    if (!source) throw new Error("Missing test directory");
    const root = join(source, "..");
    const directory = await Deno.makeTempDir({
      prefix: "alteran-space-json-worker-",
    });
    const bundle = join(directory, "worker.mjs");
    try {
      const build = await new Deno.Command(Deno.execPath(), {
        cwd: root,
        args: [
          "run",
          "-A",
          "--frozen",
          "npm:esbuild@0.25.12",
          "tests/fixtures/space-write-json-worker.ts",
          "--bundle",
          "--format=esm",
          "--platform=browser",
          `--outfile=${bundle}`,
        ],
        stdout: "null",
        stderr: "null",
      }).output();
      if (!build.success) {
        throw new Error("Space write JSON Worker bundle failed");
      }
      const worker = new Miniflare({
        modules: true,
        modulesRoot: directory,
        scriptPath: bundle,
        compatibilityDate: "2025-09-27",
        compatibilityFlags: ["nodejs_compat"],
      });
      try {
        const request = (body: string) =>
          worker.dispatchFetch("https://pds.example/", {
            method: "POST",
            body,
          });
        const response = await request('{"n":9223372036854775807,"child":[]}');
        expect(await response.json()).toEqual({
          tag: "valid",
          type: "bigint",
          value: "9223372036854775807",
          frozen: true,
        });
        expect(
          await (await request('{"n":9007199254740991.1,"child":[]}')).json(),
        ).toEqual({ tag: "invalid" });
        expect(await (await request('{"n":1,"\\u006e":2}')).json()).toEqual({
          tag: "invalid",
        });
        const small = '{"n":1,"child":[]}';
        const limit = 1_000_000;
        const atLimit = small + " ".repeat(limit - small.length);
        expect(await (await request(atLimit)).json()).toEqual({
          tag: "valid",
          type: "number",
          value: "1",
          frozen: true,
        });
        expect(await (await request(atLimit + " ")).json()).toEqual({
          tag: "invalid",
        });
        const items = '{"n":1,"child":[' + Array(32_763).fill("0").join(",") +
          "]}";
        expect(await (await request(items)).json()).toEqual({
          tag: "valid",
          type: "number",
          value: "1",
          frozen: true,
        });
      } finally {
        await worker.dispose();
      }
    } finally {
      await Deno.remove(directory, { recursive: true });
    }
  },
});
