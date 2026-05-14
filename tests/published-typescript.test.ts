import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";

const publishedTypeScriptRoots = [
  "mod.ts",
  "index.d.ts",
  "src",
  "types",
] as const;

const portableTypeScriptExtensions = [
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".d.ts",
] as const;

const packagedWellKnownRoutes = [
  "src/entrypoints/well-known/atproto-did.ts",
  "src/entrypoints/well-known/did.json.ts",
  "src/entrypoints/well-known/oauth-authorization-server.ts",
  "src/entrypoints/well-known/oauth-protected-resource.ts",
  "src/pages/well-known/atproto-did.ts",
  "src/pages/well-known/did.json.ts",
  "src/pages/well-known/oauth-authorization-server.ts",
  "src/pages/well-known/oauth-protected-resource.ts",
] as const;

type DenoPublishConfig = {
  readonly publish: {
    readonly include: readonly string[];
  };
};

type NpmPackageConfig = {
  readonly files: readonly string[];
};

function isPortableTypeScriptPath(path: string): boolean {
  return portableTypeScriptExtensions.some((extension) =>
    path.endsWith(extension)
  );
}

async function collectPublishedTypeScriptFiles(
  path: string,
): Promise<readonly string[]> {
  const stat = await Deno.stat(path);
  if (!stat.isDirectory) {
    return isPortableTypeScriptPath(path) ? [path] : [];
  }

  const files: string[] = [];
  for await (const entry of Deno.readDir(path)) {
    const childPath = `${path}/${entry.name}`;
    files.push(...await collectPublishedTypeScriptFiles(childPath));
  }
  return files;
}

describe("published TypeScript package surface", () => {
  it("uses portable module specifiers", async () => {
    const files = (
      await Promise.all(
        publishedTypeScriptRoots.map((path) =>
          collectPublishedTypeScriptFiles(path)
        ),
      )
    ).flat().sort();

    const filesWithDenoOnlySpecifiers: string[] = [];
    for (const file of files) {
      const source = await Deno.readTextFile(file);
      if (source.includes("npm:")) {
        filesWithDenoOnlySpecifiers.push(file);
      }
    }

    expect(filesWithDenoOnlySpecifiers).toEqual([]);
  });

  it("includes packaged well-known route files", async () => {
    const denoConfig = JSON.parse(
      await Deno.readTextFile("deno.json"),
    ) as DenoPublishConfig;
    const packageConfig = JSON.parse(
      await Deno.readTextFile("package.json"),
    ) as NpmPackageConfig;

    expect(denoConfig.publish.include).toContain("src/**/*.ts");
    expect(packageConfig.files).toContain("src");

    for (const route of packagedWellKnownRoutes) {
      await Deno.stat(route);
    }
  });
});
