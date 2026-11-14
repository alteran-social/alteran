import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { publicPreflightMessage } from "./deploy-diagnostics.ts";

type Stage = "build" | "preflight" | "deploy";
export type DeploymentCommand = {
  readonly stage: Stage;
  readonly cwd: string;
  readonly environment: Readonly<Record<string, string>>;
  readonly args: readonly string[];
};
type Executor = (command: DeploymentCommand) => Promise<boolean>;

const OMIT_ROOT = new Set([
  ".git",
  ".wrangler",
  ".astro",
  ".direnv",
  ".devenv",
  "dist",
  "node_modules",
  ".codex",
  ".agents",
  ".aws",
  "atproto",
  "social-app",
]);
const TARGET_OVERRIDES = [
  "CLOUDFLARE_VITE_WRANGLER_CONFIG_PATH",
  "CLOUDFLARE_API_BASE_URL",
  "CF_API_BASE_URL",
  "CLOUDFLARE_COMPLIANCE_REGION",
  "WRANGLER_API_ENVIRONMENT",
  "WRANGLER_CI_OVERRIDE_NAME",
];

/** Build and deploy the same private, validated production artifact. */
export async function deployProduction(
  projectRoot: string,
  inputEnvironment: Readonly<Record<string, string>>,
  execute: Executor,
): Promise<boolean> {
  if (
    (inputEnvironment.CLOUDFLARE_ENV &&
      inputEnvironment.CLOUDFLARE_ENV !== "production") ||
    TARGET_OVERRIDES.some((key) => inputEnvironment[key])
  ) {
    throw new Error("Remove conflicting Cloudflare deployment overrides");
  }
  const source = await Deno.realPath(projectRoot);
  const snapshot = await Deno.makeTempDir({
    prefix: "alteran-production-build-",
  });
  await Deno.chmod(snapshot, 0o700);
  try {
    if (!outside(source, await Deno.realPath(snapshot))) {
      throw new Error("Temporary build directory is inside the project");
    }
    await copyProject(source, snapshot, source, true);
    const dependencies = await Deno.realPath(join(source, "node_modules"));
    await Deno.symlink(dependencies, join(snapshot, "node_modules"), {
      type: "dir",
    });
    const environment = Object.freeze({
      ...inputEnvironment,
      CLOUDFLARE_ENV: "production",
      CLOUDFLARE_VITE_WRANGLER_CONFIG_PATH: join(snapshot, "wrangler.jsonc"),
      CLOUDFLARE_INCLUDE_PROCESS_ENV: "false",
      ASTRO_TELEMETRY_DISABLED: "1",
      CI: "true",
      WRANGLER_SEND_METRICS: "false",
      WRANGLER_SEND_ERROR_REPORTS: "false",
      WRANGLER_LOG: "error",
      WRANGLER_LOG_SANITIZE: "true",
      WRANGLER_API_ENVIRONMENT: "production",
      CLOUDFLARE_API_BASE_URL: "https://api.cloudflare.com/client/v4",
      CLOUDFLARE_COMPLIANCE_REGION: "public",
      WRANGLER_LOG_PATH: join(snapshot, ".wrangler-deployment.log"),
    });
    const command = (stage: Stage, args: readonly string[]) =>
      execute({ stage, cwd: snapshot, environment, args });
    if (!await command("build", ["task", "build"])) return false;
    if (
      !await command("preflight", ["run", "-A", "scripts/deploy-preflight.ts"])
    ) return false;
    const identity = await deploymentIdentity(
      snapshot,
      inputEnvironment.CLOUDFLARE_ACCOUNT_ID,
    );
    const deployEnvironment = Object.freeze({
      ...environment,
      CLOUDFLARE_ACCOUNT_ID: identity.accountId,
      WRANGLER_CI_OVERRIDE_NAME: identity.workerName,
      WRANGLER_API_ENVIRONMENT: "production",
      CLOUDFLARE_API_BASE_URL: "https://api.cloudflare.com/client/v4",
      CLOUDFLARE_COMPLIANCE_REGION: "public",
    });
    return await execute({
      stage: "deploy",
      cwd: snapshot,
      environment: deployEnvironment,
      args: [
        "run",
        "-A",
        "npm:wrangler",
        "deploy",
        "--strict",
        "--no-x-provision",
        "--no-x-auto-create",
      ],
    });
  } finally {
    await removeSnapshot(snapshot);
  }
}

async function deploymentIdentity(
  snapshot: string,
  ambientAccount: string | undefined,
) {
  const value: unknown = JSON.parse(
    await Deno.readTextFile(join(snapshot, "dist/server/wrangler.json")),
  );
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Invalid deployment identity");
  }
  const config = value as Record<string, unknown>;
  const accountId = typeof config.account_id === "string"
    ? config.account_id
    : ambientAccount;
  if (
    typeof accountId !== "string" || !/^[a-f0-9]{32}$/i.test(accountId) ||
    typeof config.name !== "string" || !config.name
  ) throw new Error("Invalid deployment identity");
  return { accountId, workerName: config.name };
}

async function copyProject(
  source: string,
  destination: string,
  root: string,
  topLevel: boolean,
): Promise<void> {
  for await (const entry of Deno.readDir(source)) {
    if (topLevel && OMIT_ROOT.has(entry.name)) continue;
    const input = join(source, entry.name),
      output = join(destination, entry.name);
    const info = await Deno.lstat(input);
    if (info.isSymlink) {
      const target = await Deno.readLink(input);
      const resolved = await Deno.realPath(input);
      const sourceRelative = relative(root, resolved).split(
        Deno.build.os === "windows" ? "\\" : "/",
      )[0];
      if (
        isAbsolute(target) || outside(root, resolved) ||
        (OMIT_ROOT.has(sourceRelative) && sourceRelative !== "node_modules") ||
        outside(
          destinationRoot(root, destination, source),
          resolve(dirname(output), target),
        )
      ) {
        throw new Error(
          "Project contains a symlink outside the build snapshot",
        );
      }
      await Deno.symlink(target, output, {
        type: (await Deno.stat(input)).isDirectory ? "dir" : "file",
      });
    } else if (info.isDirectory) {
      await Deno.mkdir(output, { mode: 0o700 });
      await copyProject(input, output, root, false);
      if (info.mode !== null) await Deno.chmod(output, info.mode & 0o777);
    } else if (info.isFile) {
      await Deno.copyFile(input, output);
      if (info.mode !== null) await Deno.chmod(output, info.mode & 0o777);
    } else {
      throw new Error("Project contains an unsupported file");
    }
  }
}

async function removeSnapshot(path: string): Promise<void> {
  await Deno.chmod(path, 0o700);
  for await (const entry of Deno.readDir(path)) {
    if (entry.isDirectory && !entry.isSymlink) {
      await removeSnapshot(join(path, entry.name));
    }
  }
  await Deno.remove(path, { recursive: true });
}

function destinationRoot(
  root: string,
  destination: string,
  source: string,
): string {
  return resolve(destination, relative(source, root));
}

function outside(root: string, value: string): boolean {
  const path = relative(root, value);
  return path === ".." ||
    path.startsWith(`..${Deno.build.os === "windows" ? "\\" : "/"}`) ||
    isAbsolute(path);
}

if (import.meta.main) {
  if (Deno.args.length !== 0) {
    console.error(
      "The production deploy task does not accept targeting overrides",
    );
    Deno.exit(1);
  }
  let deploymentStarted = false;
  try {
    const success = await deployProduction(
      Deno.cwd(),
      Deno.env.toObject(),
      async ({ cwd, environment, args, stage }) => {
        if (stage === "deploy") deploymentStarted = true;
        const command = new Deno.Command(Deno.execPath(), {
          cwd,
          env: { ...environment },
          args: [...args],
          stdin: "null",
          stdout: "null",
          stderr: stage === "preflight" ? "piped" : "null",
        });
        const result = await command.output();
        if (!result.success) {
          if (stage === "preflight") {
            console.error(
              publicPreflightMessage(new TextDecoder().decode(result.stderr)),
            );
          } else if (stage === "deploy") {
            console.error(
              "Production deployment command failed; the remote outcome may be unknown",
            );
          } else {console.error(
              "Production build failed; review the build configuration",
            );}
        }
        return result.success;
      },
    );
    if (!success) Deno.exit(1);
    console.log("Production deployment submitted");
  } catch {
    console.error(
      deploymentStarted
        ? "Production deployment could not be verified; the remote outcome may be unknown"
        : "Production deployment could not be prepared",
    );
    Deno.exit(1);
  }
}
