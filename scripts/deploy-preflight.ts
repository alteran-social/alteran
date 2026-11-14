import { resolve } from "node:path";
import { unstable_readConfig } from "npm:wrangler";
import { validateDeploymentConfig } from "./deploy-config-validation.ts";
import {
  generatedTargetsMatchSource,
  invalidGeneratedFields,
} from "./deploy-generated-validation.ts";
import { publicPreflightMessage } from "./deploy-diagnostics.ts";

async function preflight(): Promise<void> {
  const root = await Deno.realPath(Deno.cwd());
  const sourcePath = resolve(root, "wrangler.jsonc");
  const generatedPath = resolve(root, "dist/server/wrangler.json");
  const redirectPath = resolve(root, ".wrangler/deploy/config.json");
  if (
    await Deno.realPath(sourcePath) !== sourcePath ||
    await Deno.realPath(generatedPath) !== generatedPath ||
    await Deno.realPath(redirectPath) !== redirectPath
  ) throw new Error("Unexpected deployment configuration path");
  const redirect = await readJson(redirectPath);
  if (
    typeof redirect.configPath !== "string" ||
    await Deno.realPath(
        resolve(root, ".wrangler/deploy", redirect.configPath),
      ) !== generatedPath
  ) {
    throw new Error("Unexpected deployment redirect");
  }
  const raw = await readJson(generatedPath);
  if (raw.targetEnvironment !== "production" || Object.hasOwn(raw, "env")) {
    throw new Error("Production build selection does not match");
  }
  if (invalidGeneratedFields(raw)) {
    throw new Error("Unsupported production resource binding");
  }
  const source = unstable_readConfig(
    { config: sourcePath, env: "production" },
    { hideWarnings: true },
  );
  const generated = unstable_readConfig({}, {
    useRedirectIfAvailable: true,
    hideWarnings: true,
  });
  if (!generatedTargetsMatchSource(raw, source)) {
    throw new Error("Generated configuration does not match production");
  }
  if (
    source.configPath !== sourcePath ||
    generated.configPath !== generatedPath ||
    generated.userConfigPath !== sourcePath ||
    generated.main !== resolve(root, "dist/server/entry.mjs") ||
    await Deno.realPath(generated.main) !== generated.main ||
    await Deno.realPath(resolve(root, "dist/client")) !==
      resolve(root, "dist/client")
  ) {
    throw new Error("Unexpected deployment artifact");
  }
  const result = validateDeploymentConfig(
    source,
    generated,
    Deno.env.get("CLOUDFLARE_ACCOUNT_ID"),
  );
  if (result.tag !== "valid") throw new Error(result.reason);
}

async function readJson(path: string): Promise<Record<string, unknown>> {
  const info = await Deno.stat(path);
  if (!info.isFile || info.size > 2 * 1024 * 1024) {
    throw new Error("Invalid deployment configuration");
  }
  const value: unknown = JSON.parse(await Deno.readTextFile(path));
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Invalid deployment configuration");
  }
  return value as Record<string, unknown>;
}

try {
  await preflight();
} catch (error) {
  console.error(
    publicPreflightMessage(error instanceof Error ? error.message : undefined),
  );
  Deno.exit(1);
}
