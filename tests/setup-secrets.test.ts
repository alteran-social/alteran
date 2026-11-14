import { describe, it } from "@std/testing/bdd";
import { join } from "node:path";

const root = join(import.meta.dirname!, "..");

async function run(cwd: string, ...args: string[]) {
  return await new Deno.Command(Deno.execPath(), {
    cwd,
    args: [
      "run",
      "-A",
      "--config",
      join(root, "deno.json"),
      join(root, "scripts/setup-secrets.ts"),
      ...args,
    ],
    stdout: "piped",
    stderr: "piped",
  }).output();
}

function requireCondition(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

describe("credential setup guidance", () => {
  it("uses named targets and current session credentials without exposing generated values in test output", async () => {
    const cwd = await Deno.makeTempDir();
    try {
      for (const environment of ["dev", "staging", "production"]) {
        const result = await run(cwd, "--env", environment);
        requireCondition(result.success, "Credential setup failed");
        const output = new TextDecoder().decode(result.stdout);
        const commands = output.split("\n").filter((line) =>
          line.includes("secret put")
        );
        requireCondition(
          commands.length === 3 &&
            commands.every((line) => line.endsWith(`--env ${environment}`)),
          "Secret commands lack the selected environment",
        );
        requireCondition(
          commands.some((line) => line.includes("SESSION_JWT_SECRET")),
          "Missing session credential guidance",
        );
        requireCondition(
          !commands.some((line) =>
            /PDS_DID|PDS_HANDLE|ACCESS_TOKEN|REFRESH_TOKEN/.test(line)
          ),
          "Credential guidance contains an identity or legacy token secret",
        );
        const storage = environment === "dev" ? "--local" : "--remote";
        requireCondition(
          output.includes(
            `d1 migrations apply ALTERAN_DB --env ${environment} ${storage}`,
          ),
          "Migration guidance is not scoped to the selected environment",
        );
        requireCondition(
          !output.includes("bun run") &&
            !output.includes("migrations apply pds"),
          "Credential guidance contains an unsupported command",
        );
      }
    } finally {
      await Deno.remove(cwd, { recursive: true });
    }
  });

  it("writes private local credentials and refuses to overwrite them without force", async () => {
    const cwd = await Deno.makeTempDir();
    try {
      const result = await run(cwd, "--env", "dev", "--write-dev-vars");
      requireCondition(result.success, "Local credential setup failed");
      const file = join(cwd, ".dev.vars");
      const content = await Deno.readTextFile(file);
      requireCondition(
        (await Deno.stat(file)).mode! % 0o1000 === 0o600,
        "Local credentials are not private",
      );
      requireCondition(
        content.includes("SESSION_JWT_SECRET=") &&
          !content.includes("REFRESH_TOKEN="),
        "Local credentials do not match the modern session configuration",
      );
      const second = await run(cwd, "--env", "dev", "--write-dev-vars");
      requireCondition(
        !second.success && await Deno.readTextFile(file) === content,
        "Local credentials were unexpectedly overwritten",
      );
    } finally {
      await Deno.remove(cwd, { recursive: true });
    }
  });
});
