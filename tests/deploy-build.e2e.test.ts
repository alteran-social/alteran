import { expect } from "@std/expect";
import { it } from "@std/testing/bdd";
import { applyEdits, modify } from "npm:jsonc-parser@3.3.1";
import { join } from "node:path";
import { type DeploymentCommand, deployProduction } from "../scripts/deploy.ts";

it({
  name:
    "production preflight rejects stale builds and validates a fresh redirected dry run",
  ignore: Deno.env.get("RUN_APP_TESTS") !== "true",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const root = join(import.meta.dirname!, "..");
    const rejectedStages: string[] = [];
    const rejected = await deployProduction(
      root,
      withoutConflictingEnvironment(Deno.env.toObject()),
      async (command) => {
        rejectedStages.push(command.stage);
        if (command.stage === "build") {
          await syntheticConfig(command.cwd, false);
        }
        if (command.stage === "deploy") {
          throw new Error("Unexpected deployment stage");
        }
        return await run(command, command.args);
      },
    );
    expect(rejected).toBe(false);
    expect(rejectedStages).toEqual(["build", "preflight"]);
    let deployCalls = 0;
    const ok = await deployProduction(
      root,
      withoutConflictingEnvironment(Deno.env.toObject()),
      async (command) => {
        if (command.stage === "build") {
          const environmentPath = join(command.cwd, ".env.production");
          const conflictingEnvironment =
            "CLOUDFLARE_ENV=staging\nCLOUDFLARE_VITE_WRANGLER_CONFIG_PATH=/tmp/not-the-config\n" +
            "WRANGLER_CI_OVERRIDE_NAME=wrong-worker\nCLOUDFLARE_ACCOUNT_ID=cccccccccccccccccccccccccccccccc\n" +
            "CLOUDFLARE_API_BASE_URL=https://invalid.example\nWRANGLER_API_ENVIRONMENT=staging\n";
          await Deno.writeTextFile(environmentPath, conflictingEnvironment);
          await syntheticConfig(command.cwd, false);
          expect(await run(command, ["task", "build"])).toBe(true);
          expect(
            await run(command, ["run", "-A", "scripts/deploy-preflight.ts"]),
          ).toBe(false);
          await Deno.remove(environmentPath);
          await syntheticConfig(command.cwd, true);
          expect(
            await run(command, ["task", "build"], { CLOUDFLARE_ENV: null }),
          ).toBe(true);
          expect((await generated(command.cwd)).targetEnvironment)
            .toBeUndefined();
          expect(
            await run(command, ["run", "-A", "scripts/deploy-preflight.ts"]),
          ).toBe(false);
          await dryRun(command, "alteran", {
            CLOUDFLARE_ENV: null,
            WRANGLER_CI_OVERRIDE_NAME: "alteran",
            CLOUDFLARE_ACCOUNT_ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          });
          expect(
            await run(command, ["task", "build"], {
              CLOUDFLARE_ENV: "staging",
            }),
          ).toBe(true);
          expect((await generated(command.cwd)).targetEnvironment).toBe(
            "staging",
          );
          expect(
            await run(command, ["run", "-A", "scripts/deploy-preflight.ts"]),
          ).toBe(false);
          await dryRun(command, "alteran-staging", {
            CLOUDFLARE_ENV: "staging",
            WRANGLER_CI_OVERRIDE_NAME: "alteran-staging",
            CLOUDFLARE_ACCOUNT_ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          });
          await Deno.writeTextFile(environmentPath, conflictingEnvironment);
          return await run(command, ["task", "build"]);
        }
        if (command.stage === "preflight") {
          expect(
            await run(command, command.args, {
              CLOUDFLARE_ACCOUNT_ID: "cccccccccccccccccccccccccccccccc",
            }),
          ).toBe(false);
          const redirectPath = join(
            command.cwd,
            ".wrangler/deploy/config.json",
          );
          const redirect = await Deno.readTextFile(redirectPath);
          await Deno.writeTextFile(
            redirectPath,
            JSON.stringify({ configPath: "../../dist/not-the-build.json" }),
          );
          expect(await run(command, command.args)).toBe(false);
          await Deno.writeTextFile(redirectPath, redirect);
          const generatedPath = join(command.cwd, "dist/server/wrangler.json");
          const generated = await Deno.readTextFile(generatedPath);
          const modified = JSON.parse(generated) as Record<string, unknown>;
          modified.kv_namespaces = [{ binding: "SESSION" }];
          await Deno.writeTextFile(generatedPath, JSON.stringify(modified));
          expect(await run(command, command.args)).toBe(false);
          for (
            const [key, value] of [
              ["browser", { binding: "BROWSER" }],
              ["ai", { binding: "AI" }],
              ["images", { binding: "IMAGES" }],
              ["stream", { binding: "STREAM" }],
              ["unsafe", { bindings: [{ name: "MAIL", type: "send_email" }] }],
              ["unsafe", { metadata: { bindings: [] } }],
              ["future_binding", { binding: "FUTURE" }],
              ["vars", { ENVIRONMENT: "production", PDS_DID: "did:plc:other" }],
              ["d1_databases", [{
                binding: "ALTERAN_DB",
                database_id: "22222222-2222-4222-8222-222222222222",
              }]],
              ["services", [{ binding: "OTHER", service: "other-worker" }]],
              ["durable_objects", {
                bindings: [{
                  name: "ALTERAN_SEQUENCER",
                  class_name: "Sequencer",
                  script_name: "unrelated-worker",
                }],
              }],
              ["durable_objects", {
                bindings: [{
                  name: "ALTERAN_SEQUENCER",
                  class_name: "Sequencer",
                  environment: "staging",
                }],
              }],
            ] as const
          ) {
            const unexpected = JSON.parse(generated) as Record<string, unknown>;
            unexpected[key] = value;
            await Deno.writeTextFile(generatedPath, JSON.stringify(unexpected));
            expect(await run(command, command.args)).toBe(false);
          }
          await Deno.writeTextFile(generatedPath, generated);
          const sourcePath = join(command.cwd, "wrangler.jsonc");
          const source = await Deno.readTextFile(sourcePath);
          await Deno.writeTextFile(
            sourcePath,
            applyEdits(
              source,
              modify(
                source,
                ["env", "production", "d1_databases", 0, "database_id"],
                "22222222-2222-4222-8222-222222222222",
                {},
              ),
            ),
          );
          expect(await run(command, command.args)).toBe(false);
          await Deno.writeTextFile(sourcePath, source);
          const unsupportedMigration = JSON.parse(generated) as Record<
            string,
            unknown
          >;
          unsupportedMigration.migrations = [{
            tag: "v1",
            new_classes: ["Sequencer"],
          }, { tag: "v2", modified_classes: ["Sequencer"] }];
          await Deno.writeTextFile(
            generatedPath,
            JSON.stringify(unsupportedMigration),
          );
          await Deno.writeTextFile(
            sourcePath,
            applyEdits(
              source,
              modify(source, ["env", "production", "migrations", 1], {
                tag: "v2",
                modified_classes: ["Sequencer"],
              }, {}),
            ),
          );
          expect(await run(command, command.args)).toBe(false);
          await Deno.writeTextFile(generatedPath, generated);
          await Deno.writeTextFile(sourcePath, source);
          return await run(command, command.args);
        }
        deployCalls++;
        expect(command.environment.CLOUDFLARE_ENV).toBe("production");
        expect(command.environment.CLOUDFLARE_ACCOUNT_ID).toBe(
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        expect(command.environment.WRANGLER_CI_OVERRIDE_NAME).toBe(
          "alteran-production",
        );
        expect(command.environment.WRANGLER_API_ENVIRONMENT).toBe("production");
        expect(command.environment.CLOUDFLARE_API_BASE_URL).toBe(
          "https://api.cloudflare.com/client/v4",
        );
        await dryRun(command, "alteran-production");
        return true;
      },
    );
    expect(ok).toBe(true);
    expect(deployCalls).toBe(1);
  },
});

async function syntheticConfig(
  root: string,
  configured: boolean,
): Promise<void> {
  const path = join(root, "wrangler.jsonc");
  let text = await Deno.readTextFile(path);
  const write = (key: (string | number)[], value: unknown) => {
    text = applyEdits(
      text,
      modify(text, key, value, {
        formattingOptions: { insertSpaces: true, tabSize: 2 },
      }),
    );
  };
  write(["account_id"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  write(["kv_namespaces"], [{
    binding: "SESSION",
    id: "dddddddddddddddddddddddddddddddd",
  }]);
  write(
    ["d1_databases", 0, "database_id"],
    "33333333-3333-4333-8333-333333333333",
  );
  write(["env", "staging", "account_id"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  write(["env", "staging", "kv_namespaces"], [{
    binding: "SESSION",
    id: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  }]);
  write(
    ["env", "staging", "d1_databases", 0, "database_id"],
    "44444444-4444-4444-8444-444444444444",
  );
  write(
    ["env", "production", "account_id"],
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  );
  write(["env", "production", "kv_namespaces"], [{
    binding: "SESSION",
    id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  }]);
  write(
    ["env", "production", "d1_databases", 0, "database_id"],
    configured
      ? "11111111-1111-4111-8111-111111111111"
      : "YOUR_PRODUCTION_D1_ID",
  );
  write(["migrations", 1], { tag: "v2" });
  write(["env", "staging", "migrations", 1], { tag: "v2" });
  write(["env", "production", "migrations", 1], { tag: "v2" });
  await Deno.writeTextFile(path, text);
}

async function run(
  command: DeploymentCommand,
  args: readonly string[],
  overrides: Record<string, string | null> = {},
) {
  const result = await new Deno.Command(Deno.execPath(), {
    cwd: command.cwd,
    env: environment(command, overrides),
    clearEnv: true,
    args: [...args],
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (!result.success && args[0] === "task" && args[1] === "build") {
    const selected = overrides.CLOUDFLARE_ENV === null
      ? "default"
      : overrides.CLOUDFLARE_ENV === "staging"
      ? "staging"
      : "production";
    throw new Error(
      `Astro ${selected} test build failed with exit code ${result.code}`,
    );
  }
  return result.success;
}

async function dryRun(
  command: DeploymentCommand,
  databaseName: string,
  overrides: Record<string, string | null> = {},
) {
  const result = await new Deno.Command(Deno.execPath(), {
    cwd: command.cwd,
    env: environment(command, { ...overrides, WRANGLER_LOG: "log" }),
    clearEnv: true,
    args: [
      "run",
      "-A",
      "npm:wrangler",
      "deploy",
      "--strict",
      "--no-x-provision",
      "--no-x-auto-create",
      "--dry-run",
      "--outdir",
      join(command.cwd, ".dry-run"),
    ],
    stdout: "piped",
    stderr: "piped",
  }).output();
  const output = new TextDecoder().decode(result.stdout) +
    new TextDecoder().decode(result.stderr);
  const binding = new RegExp(
    `env\\.ALTERAN_DB\\s+\\(${databaseName}\\)\\s+D1 Database(?:\\s|$)`,
  );
  if (!result.success || !binding.test(output)) {
    throw new Error(
      `Wrangler dry run failed or reported the wrong binding (exit code ${result.code})`,
    );
  }
}

function environment(
  command: DeploymentCommand,
  overrides: Record<string, string | null>,
): Record<string, string> {
  const result = { ...command.environment };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === null) delete result[key];
    else result[key] = value;
  }
  return result;
}

async function generated(root: string): Promise<Record<string, unknown>> {
  return JSON.parse(
    await Deno.readTextFile(join(root, "dist/server/wrangler.json")),
  ) as Record<string, unknown>;
}

function withoutConflictingEnvironment(environment: Record<string, string>) {
  const copy = { ...environment };
  for (
    const key of [
      "CLOUDFLARE_ENV",
      "CLOUDFLARE_ACCOUNT_ID",
      "CLOUDFLARE_API_TOKEN",
      "CLOUDFLARE_API_KEY",
      "CLOUDFLARE_EMAIL",
      "CLOUDFLARE_VITE_WRANGLER_CONFIG_PATH",
      "CLOUDFLARE_API_BASE_URL",
      "CF_API_BASE_URL",
      "CLOUDFLARE_COMPLIANCE_REGION",
      "WRANGLER_API_ENVIRONMENT",
      "WRANGLER_CI_OVERRIDE_NAME",
    ]
  ) {
    delete copy[key];
  }
  return copy;
}
