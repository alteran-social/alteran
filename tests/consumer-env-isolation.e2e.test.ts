import { expect } from "@std/expect";
import { it } from "@std/testing/bdd";
import { Miniflare } from "miniflare";
import { SignJWT } from "jose";
import { join } from "node:path";

it({
  name: "external Astro consumer keeps request environments isolated",
  ignore: Deno.env.get("RUN_APP_TESTS") !== "true",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const root = await Deno.realPath(join(import.meta.dirname!, ".."));
    const project = await Deno.makeTempDir({ prefix: "alteran-consumer-" });
    await Deno.chmod(project, 0o700);
    try {
      await createConsumer(root, project);
      const environment = Object.fromEntries(
        Object.entries(Deno.env.toObject()).filter(([key]) =>
          !/PASSWORD|TOKEN|SECRET|AUTH|^PDS_|^CLOUDFLARE_|^WRANGLER_|^CF_/i
            .test(key)
        ),
      );
      Object.assign(environment, {
        CI: "true",
        ASTRO_TELEMETRY_DISABLED: "1",
        WRANGLER_LOG: "error",
        WRANGLER_SEND_METRICS: "false",
        WRANGLER_LOG_PATH: join(project, "wrangler-logs"),
      });
      const build = await new Deno.Command(Deno.execPath(), {
        cwd: project,
        env: environment,
        clearEnv: true,
        args: ["task", "build"],
        stdout: "null",
        stderr: "null",
      }).output();
      if (!build.success) {
        throw new Error(
          `Consumer Astro build failed with exit code ${build.code}`,
        );
      }
      await exerciseConsumer(project, root);
    } finally {
      await Deno.remove(project, { recursive: true });
    }
  },
});

async function createConsumer(root: string, project: string): Promise<void> {
  await Deno.mkdir(join(project, "src/pages"), { recursive: true });
  await Deno.symlink(
    await Deno.realPath(join(root, "node_modules")),
    join(project, "node_modules"),
    { type: "dir" },
  );
  await Deno.copyFile(join(root, "deno.lock"), join(project, "deno.lock"));
  await Deno.writeTextFile(
    join(project, "deno.json"),
    JSON.stringify({
      nodeModulesDir: "manual",
      tasks: { build: "deno run --cached-only -A npm:astro build" },
    }),
  );
  await Deno.writeTextFile(
    join(project, "package.json"),
    JSON.stringify({
      name: "alteran-consumer-fixture",
      private: true,
      type: "module",
    }),
  );
  await Deno.writeTextFile(
    join(project, "wrangler.jsonc"),
    JSON.stringify({
      name: "alteran-consumer-fixture",
      main: "src/_worker.ts",
      compatibility_date: "2025-09-27",
      compatibility_flags: ["nodejs_compat", "enable_request_signal"],
      d1_databases: [{
        binding: "ALTERAN_DB",
        database_name: "consumer",
        database_id: "local-dev",
      }],
      r2_buckets: [{ binding: "ALTERAN_BLOBS", bucket_name: "consumer-blobs" }],
      durable_objects: {
        bindings: [{ name: "ALTERAN_SEQUENCER", class_name: "Sequencer" }],
      },
      migrations: [{ tag: "v1", new_classes: ["Sequencer"] }],
    }),
  );
  const integration = new URL(`file://${join(root, "index.js")}`).href;
  const worker = new URL(`file://${join(root, "src/_worker.ts")}`).href;
  await Deno.writeTextFile(
    join(project, "astro.config.mjs"),
    `
    import { defineConfig, envField } from 'astro/config';
    import cloudflare from '@astrojs/cloudflare';
    import alteran from ${JSON.stringify(integration)};
    export default defineConfig({ output: 'server', adapter: cloudflare({ mode: 'advanced', imageService: 'custom' }),
      integrations: [alteran()], env: { schema: { HOST_APP_SECRET: envField.string({ context: 'server', access: 'secret' }) } } });
  `,
  );
  await Deno.writeTextFile(
    join(project, "src/_worker.ts"),
    `export { default, Sequencer } from ${JSON.stringify(worker)};\n`,
  );
  await Deno.writeTextFile(
    join(project, "src/pages/index.astro"),
    "<h1>Consumer fixture</h1>\n",
  );
  const fixture = await Deno.readTextFile(
    join(root, "tests/fixtures/consumer-env-isolation.js"),
  );
  await Deno.writeTextFile(
    join(project, "src/pages/isolation.js"),
    fixture.replaceAll("__ALTERAN_ROOT__", root),
  );
  await Deno.writeTextFile(
    join(project, "src/pages/scoped.js"),
    `
    export const prerender = false;
    export async function GET({ locals }) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      return Response.json({ label: locals.env.TEST_LABEL });
    }
  `,
  );
}

async function exerciseConsumer(project: string, root: string): Promise<void> {
  const modules: { type: "ESModule"; path: string }[] = [{
    type: "ESModule",
    path: join(project, "dist/server/entry.mjs"),
  }];
  for (const directory of ["", "chunks"]) {
    for await (
      const file of Deno.readDir(join(project, "dist/server", directory))
    ) {
      if (
        file.isFile && file.name.endsWith(".mjs") && file.name !== "entry.mjs"
      ) {
        modules.push({
          type: "ESModule",
          path: join(project, "dist/server", directory, file.name),
        });
      }
    }
  }
  const password = crypto.randomUUID();
  const worker = new Miniflare({
    modules,
    modulesRoot: join(project, "dist/server"),
    compatibilityDate: "2025-09-27",
    compatibilityFlags: ["nodejs_compat", "enable_request_signal"],
    d1Databases: {
      ALTERAN_DB: "host-db",
      DB_A: "first-db",
      DB_B: "second-db",
      DB_C: "third-db",
    },
    r2Buckets: ["ALTERAN_BLOBS"],
    bindings: {
      PDS_DID: "did:example:consumer",
      PDS_HANDLE: "consumer.example",
      PDS_HOSTNAME: "consumer.example",
      USER_PASSWORD: password,
      SESSION_JWT_SECRET: crypto.randomUUID() + crypto.randomUUID(),
      HOST_APP_SECRET: crypto.randomUUID(),
      PDS_RELAY_NOTIFY: "false",
    },
  });
  try {
    const names: string[] = [];
    for await (const file of Deno.readDir(join(root, "migrations"))) {
      if (file.name.endsWith(".sql")) names.push(file.name);
    }
    for (const binding of ["ALTERAN_DB", "DB_A", "DB_B", "DB_C"]) {
      const database = await worker.getD1Database(binding);
      for (const name of names.sort()) {
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
    }
    expect((await worker.dispatchFetch("https://pds.example/")).status).toBe(
      200,
    );
    const isolation = await worker.dispatchFetch(
      "https://pds.example/isolation",
    );
    expect(isolation.status).toBe(200);
    const checks: unknown = await isolation.json();
    if (!checks || typeof checks !== "object" || Array.isArray(checks)) {
      throw new Error("Invalid consumer isolation result");
    }
    for (
      const key of [
        "hostSecretBefore",
        "hostSecretAfter",
        "passwordIsolated",
        "modernIsolated",
        "audienceIsolated",
        "identityIsolated",
        "loginRejected",
        "consentRejected",
        "emptyAccount",
        "existingRejects",
        "existingAccepts",
        "secretStoreWorks",
        "secretStoreFailureClosed",
        "credentialGetterClosed",
        "missingContextClosed",
        "explicitLocalsWork",
      ]
    ) {
      if ((checks as Record<string, unknown>)[key] !== true) {
        throw new Error(`Consumer isolation check failed: ${key}`);
      }
    }
    const login = await worker.dispatchFetch(
      "https://pds.example/xrpc/com.atproto.server.createSession",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identifier: "consumer.example", password }),
      },
    );
    expect(login.status).toBe(200);
    const session: unknown = await login.json();
    if (
      !session || typeof session !== "object" || !("accessJwt" in session) ||
      typeof session.accessJwt !== "string"
    ) {
      throw new Error("Missing consumer session");
    }
    const current = await worker.dispatchFetch(
      "https://pds.example/xrpc/com.atproto.server.getSession",
      {
        headers: { authorization: `Bearer ${session.accessJwt}` },
      },
    );
    expect(current.status).toBe(200);
  } finally {
    await worker.dispose();
  }
  await exerciseComposedConsumer(project, root, modules);
}

async function exerciseComposedConsumer(
  project: string,
  root: string,
  modules: { type: "ESModule"; path: string }[],
): Promise<void> {
  const wrapper = join(project, "dist/server/test-entry.mjs");
  await Deno.copyFile(
    join(root, "tests/fixtures/consumer-env-wrapper.js"),
    wrapper,
  );
  const password = crypto.randomUUID();
  const legacySecret = crypto.randomUUID() + crypto.randomUUID();
  const worker = new Miniflare({
    modules: [{ type: "ESModule", path: wrapper }, ...modules],
    modulesRoot: join(project, "dist/server"),
    compatibilityDate: "2025-09-27",
    compatibilityFlags: ["nodejs_compat", "enable_request_signal"],
    d1Databases: { ALTERAN_DB: "host-db", DB_A: "first-db", DB_B: "second-db" },
    r2Buckets: ["ALTERAN_BLOBS"],
    bindings: {
      PDS_DID: "did:example:consumer",
      PDS_HANDLE: "consumer.example",
      USER_PASSWORD: crypto.randomUUID(),
      SESSION_JWT_SECRET: crypto.randomUUID(),
      HOST_APP_SECRET: crypto.randomUUID(),
      FIXTURE_PASSWORD: password,
      FIXTURE_SESSION: crypto.randomUUID() + crypto.randomUUID(),
      FIXTURE_LEGACY: legacySecret,
      PDS_RELAY_NOTIFY: "false",
    },
  });
  try {
    const names: string[] = [];
    for await (const file of Deno.readDir(join(root, "migrations"))) {
      if (file.name.endsWith(".sql")) names.push(file.name);
    }
    for (const binding of ["DB_A", "DB_B"]) {
      const database = await worker.getD1Database(binding);
      for (const name of names.sort()) {
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
    }
    const [first, second] = await Promise.all(
      ["first", "second"].map((label) =>
        worker.dispatchFetch("https://pds.example/scoped", {
          headers: { "x-fixture-env": label },
        })
      ),
    );
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(await first.json()).toEqual({ label: "first" });
    expect(await second.json()).toEqual({ label: "second" });
    const metadataUrl =
      "https://pds.example/.well-known/oauth-authorization-server";
    const metadata = await worker.dispatchFetch(metadataUrl, {
      headers: { "x-fixture-env": "hostname-string" },
    });
    expect(metadata.status).toBe(200);
    expect((await metadata.json() as { issuer: string }).issuer).toBe(
      "https://canonical.example",
    );
    for (const selection of ["hostname-inherited", "hostname-hidden"]) {
      const response = await worker.dispatchFetch(metadataUrl, {
        headers: { "x-fixture-env": selection },
      });
      expect(response.status).toBe(200);
      expect((await response.json() as { issuer: string }).issuer).toBe(
        "https://canonical.example",
      );
    }
    const unsupportedHostname = await worker.dispatchFetch(metadataUrl, {
      headers: { "x-fixture-env": "hostname-store" },
    });
    expect(unsupportedHostname.status).toBe(500);
    const hostnameFailure = await unsupportedHostname.text();
    expect(hostnameFailure.includes("Secret binding could not be resolved"))
      .toBe(true);
    expect(hostnameFailure.includes("hostname-store-marker")).toBe(false);
    const loginUrl =
      "https://pds.example/xrpc/com.atproto.server.createSession";
    const login = (label: string) =>
      worker.dispatchFetch(loginUrl, {
        method: "POST",
        headers: { "x-fixture-env": label, "content-type": "application/json" },
        body: JSON.stringify({ identifier: "test.example", password }),
      });
    const firstLogin = await login("first");
    expect(firstLogin.status).toBe(200);
    expect((await login("second")).status).toBe(401);
    const session: unknown = await firstLogin.json();
    if (
      !session || typeof session !== "object" || !("accessJwt" in session) ||
      typeof session.accessJwt !== "string"
    ) {
      throw new Error("Missing composed consumer session");
    }
    const accessUrl = "https://pds.example/xrpc/com.atproto.server.getSession";
    const access = (label: string) =>
      worker.dispatchFetch(accessUrl, {
        headers: {
          "x-fixture-env": label,
          authorization: `Bearer ${session.accessJwt}`,
        },
      });
    expect((await access("first")).status).toBe(200);
    expect((await access("second")).status).toBe(401);
    const legacyToken = await new SignJWT({
      t: "access",
      scope: "com.atproto.access",
    })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" }).setSubject(
        "did:example:scoped",
      )
      .setExpirationTime("1h").sign(new TextEncoder().encode(legacySecret));
    const legacyAccess = (label: string) =>
      worker.dispatchFetch(accessUrl, {
        headers: {
          "x-fixture-env": label,
          authorization: `Bearer ${legacyToken}`,
        },
      });
    expect((await legacyAccess("first")).status).toBe(401);
    expect((await legacyAccess("second")).status).toBe(401);
    const count = await (await worker.getD1Database("DB_B")).prepare(
      "SELECT COUNT(*) AS count FROM account",
    )
      .first<{ count: number }>();
    expect(count?.count).toBe(0);
  } finally {
    await worker.dispose();
  }
}
