import { describe, it } from "@std/testing/bdd";
import { expect } from "@std/expect";
import { join } from "node:path";
import { type DeploymentCommand, deployProduction } from "../scripts/deploy.ts";

async function project() {
  const root = await Deno.makeTempDir();
  await Deno.mkdir(join(root, "node_modules"));
  await Deno.writeTextFile(
    join(root, ".env.production"),
    "private test value",
    { mode: 0o600 },
  );
  await Deno.mkdir(join(root, "src"));
  await Deno.writeTextFile(join(root, "src", "app.ts"), "export default 1;");
  await Deno.mkdir(join(root, "atproto"));
  await Deno.writeTextFile(
    join(root, "atproto", "large-reference-clone"),
    "test",
  );
  return root;
}

describe("production deployment workflow", () => {
  it("stops before the deploy subprocess when preflight fails", async () => {
    const root = await project();
    const stages: string[] = [];
    let snapshot = "";
    try {
      const result = await deployProduction(
        root,
        {},
        async (command: DeploymentCommand) => {
          stages.push(command.stage);
          snapshot = command.cwd;
          expect((await Deno.stat(command.cwd)).mode! & 0o777).toBe(0o700);
          expect(
            (await Deno.stat(join(command.cwd, ".env.production"))).mode! &
              0o777,
          ).toBe(0o600);
          expect(await Deno.readTextFile(join(command.cwd, ".env.production")))
            .toBe("private test value");
          expect(
            await Deno.stat(join(command.cwd, "atproto")).then(
              () => true,
              () => false,
            ),
          ).toBe(false);
          expect(command.environment.CLOUDFLARE_ENV).toBe("production");
          return command.stage !== "preflight";
        },
      );
      expect(result).toBe(false);
      expect(stages).toEqual(["build", "preflight"]);
      expect(await Deno.stat(snapshot).then(() => true, () => false)).toBe(
        false,
      );
    } finally {
      await Deno.remove(root, { recursive: true });
    }
  });

  it("uses only the guarded redirected deploy arguments after successful validation", async () => {
    const root = await project();
    const commands: DeploymentCommand[] = [];
    try {
      expect(
        await deployProduction(
          root,
          { CLOUDFLARE_ENV: "production" },
          async (command) => {
            commands.push(command);
            if (command.stage === "preflight") {
              await Deno.mkdir(join(command.cwd, "dist", "server"), {
                recursive: true,
              });
              await Deno.writeTextFile(
                join(command.cwd, "dist", "server", "wrangler.json"),
                JSON.stringify({
                  name: "alteran-production",
                  account_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                }),
              );
            }
            return true;
          },
        ),
      ).toBe(true);
      expect(commands.map(({ stage }) => stage)).toEqual([
        "build",
        "preflight",
        "deploy",
      ]);
      expect(commands[2].args).toEqual([
        "run",
        "-A",
        "npm:wrangler",
        "deploy",
        "--strict",
        "--no-x-provision",
        "--no-x-auto-create",
      ]);
      expect(commands[2].environment.WRANGLER_CI_OVERRIDE_NAME).toBe(
        "alteran-production",
      );
      expect(commands[2].environment.CLOUDFLARE_ACCOUNT_ID).toBe(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      );
    } finally {
      await Deno.remove(root, { recursive: true });
    }
  });

  it("rejects conflicting targeting overrides and external symlinks", async () => {
    const root = await project();
    let calls = 0;
    try {
      const environments: Readonly<Record<string, string>>[] = [
        { CLOUDFLARE_ENV: "staging" },
        { WRANGLER_CI_OVERRIDE_NAME: "other" },
        { CLOUDFLARE_VITE_WRANGLER_CONFIG_PATH: "/tmp/other" },
      ];
      for (const environment of environments) {
        await expect(deployProduction(root, environment, async () => {
          calls++;
          return true;
        })).rejects.toThrow();
      }
      await Deno.symlink("/tmp", join(root, "src", "outside"), { type: "dir" });
      await expect(deployProduction(root, {}, async () => {
        calls++;
        return true;
      })).rejects.toThrow();
      expect(calls).toBe(0);
    } finally {
      await Deno.remove(root, { recursive: true });
    }
  });

  it("rejects target arguments before attempting a build", async () => {
    const script = new URL("../scripts/deploy.ts", import.meta.url);
    for (const argument of ["--config=elsewhere.jsonc", "--env=staging"]) {
      const result = await new Deno.Command(Deno.execPath(), {
        args: ["run", "-A", script.pathname, argument],
        stdout: "piped",
        stderr: "piped",
      }).output();
      expect(result.success).toBe(false);
      expect(new TextDecoder().decode(result.stderr)).toContain(
        "does not accept targeting overrides",
      );
    }
  });
});
