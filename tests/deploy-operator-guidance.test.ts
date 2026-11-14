import { describe, it } from "@std/testing/bdd";
import { expect } from "@std/expect";
import { join } from "node:path";

const root = join(import.meta.dirname!, "..");

describe("deployment operator guidance", () => {
  it("uses an explicit production target for every documented secret command", async () => {
    for (
      const path of [
        "README.md",
        "docs/CONFIGURATION.md",
        "docs/SINGLE_USER.md",
        "docs/SECRET_ROTATION.md",
      ]
    ) {
      const text = await Deno.readTextFile(join(root, path));
      const commands = text.split("\n").filter((line) =>
        /wrangler secret put \w+/.test(line)
      );
      expect(commands.length > 0).toBe(true);
      expect(commands.every((line) => line.includes("--env production"))).toBe(
        true,
      );
      expect(
        commands.some((line) =>
          /secret put (PDS_DID|PDS_HANDLE|PDS_HOSTNAME)\b/.test(line)
        ),
      ).toBe(false);
    }
  });

  it("selects explicit D1 targets and does not delete tracked migrations", async () => {
    const config = JSON.parse(
      await Deno.readTextFile(join(root, "deno.json")),
    ) as { tasks: Record<string, string> };
    expect(config.tasks["db:apply:production"]).toBe(
      "deno run -A npm:wrangler d1 migrations apply ALTERAN_DB --env production --remote",
    );
    for (
      const name of ["db:apply", "db:apply:local", "db:apply:local:direct"]
    ) {
      expect(config.tasks[name]).toBe(
        "deno run -A npm:wrangler d1 migrations apply ALTERAN_DB --env dev --local",
      );
    }
    expect(config.tasks["db:reset:local"]).toBe(
      "deno run -A scripts/reset-local-d1.ts",
    );
  });
});
