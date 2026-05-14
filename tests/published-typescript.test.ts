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
    if (entry.name.startsWith(".")) continue;
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
});
