import { expect } from "@std/expect";
import { it } from "@std/testing/bdd";
import { SignJWT } from "jose";
import { Miniflare } from "miniflare";
import { join } from "node:path";
import { deployProduction } from "../scripts/deploy.ts";
import { readWranglerCompatibility } from "./helpers/wrangler-compatibility.ts";

it({
  name: "built Worker rejects obsolete JWTs and retains current sessions",
  ignore: Deno.env.get("RUN_APP_TESTS") !== "true",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const root = join(import.meta.dirname!, "..");
    const environment = Object.fromEntries(
      Object.entries(Deno.env.toObject()).filter(([key]) =>
        !key.startsWith("CLOUDFLARE_") && !key.startsWith("WRANGLER_") &&
        !key.startsWith("CF_")
      ),
    );
    let builds = 0;
    const result = await deployProduction(
      root,
      environment,
      async (command) => {
        if (command.stage !== "build") {
          throw new Error("Unexpected deployment stage");
        }
        builds++;
        const build = await new Deno.Command(Deno.execPath(), {
          cwd: command.cwd,
          env: { ...command.environment },
          clearEnv: true,
          args: ["task", "build"],
          stdout: "null",
          stderr: "null",
        }).output();
        if (!build.success) {
          throw new Error(
            `Astro test build failed with exit code ${build.code}`,
          );
        }
        await exerciseWorker(command.cwd);
        return false;
      },
    );
    expect(result).toBe(false);
    expect(builds).toBe(1);
  },
});

async function exerciseWorker(root: string): Promise<void> {
  const key = crypto.randomUUID() + crypto.randomUUID();
  const token = await new SignJWT({ t: "access", scope: "com.atproto.access" })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" }).setSubject(
      "did:example:test",
    )
    .setExpirationTime("1h").sign(new TextEncoder().encode(key));
  const compatibility = await readWranglerCompatibility(root);
  const modules: { type: "ESModule"; path: string }[] = [{
    type: "ESModule",
    path: join(root, "dist/server/entry.mjs"),
  }];
  for (const directory of ["", "chunks"]) {
    for await (
      const file of Deno.readDir(join(root, "dist/server", directory))
    ) {
      if (
        file.isFile && file.name.endsWith(".mjs") && file.name !== "entry.mjs"
      ) {
        modules.push({
          type: "ESModule",
          path: join(root, "dist/server", directory, file.name),
        });
      }
    }
  }
  for (const configured of [false, true]) {
    const bindings = {
      PDS_DID: "did:example:test",
      PDS_HANDLE: "test.example",
      PDS_HOSTNAME: "test.example",
      USER_PASSWORD: "local-fixture-password",
      SESSION_JWT_SECRET: crypto.randomUUID() + crypto.randomUUID(),
      PDS_RELAY_NOTIFY: "false",
      ...(configured ? { REFRESH_TOKEN: key } : {}),
    };
    const worker = new Miniflare({
      modules,
      modulesRoot: join(root, "dist/server"),
      ...compatibility,
      d1Databases: { ALTERAN_DB: ":memory:" },
      r2Buckets: ["ALTERAN_BLOBS"],
      bindings,
    });
    try {
      const database = await worker.getD1Database("ALTERAN_DB");
      const migrations: string[] = [];
      for await (const file of Deno.readDir(join(root, "migrations"))) {
        if (file.name.endsWith(".sql")) migrations.push(file.name);
      }
      for (const name of migrations.sort()) {
        const statements =
          (await Deno.readTextFile(join(root, "migrations", name))).split(
            "--> statement-breakpoint",
          );
        for (const statement of statements) {
          if (statement.trim()) {
            await database.prepare(statement.replaceAll("\n", " ")).run();
          }
        }
      }
      const path = "https://pds.example/xrpc/com.atproto.server.getSession";
      const response = await worker.dispatchFetch(path, {
        headers: { authorization: `Bearer ${token}` },
      });
      expect(response.status).toBe(401);
      const login = await worker.dispatchFetch(
        "https://pds.example/xrpc/com.atproto.server.createSession",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            identifier: "test.example",
            password: "local-fixture-password",
          }),
        },
      );
      expect(login.status).toBe(200);
      const session: unknown = await login.json();
      if (
        !session || typeof session !== "object" || !("accessJwt" in session) ||
        !("refreshJwt" in session) ||
        typeof session.accessJwt !== "string" ||
        typeof session.refreshJwt !== "string"
      ) {
        throw new Error("Missing session tokens");
      }
      const current = await worker.dispatchFetch(path, {
        headers: { authorization: `Bearer ${session.accessJwt}` },
      });
      expect(current.status).toBe(200);
      const refreshed = await worker.dispatchFetch(
        "https://pds.example/xrpc/com.atproto.server.refreshSession",
        {
          method: "POST",
          headers: { authorization: `Bearer ${session.refreshJwt}` },
        },
      );
      expect(refreshed.status).toBe(200);
    } finally {
      await worker.dispose();
    }
  }
}
