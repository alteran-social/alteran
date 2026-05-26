import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import {
  CORE_ROUTES,
  DEBUG_ROUTES,
  ROUTES,
  WORKER_ONLY_ROUTES,
  integrationRoutes,
} from "../route-registry.js";

type DenoConfig = {
  readonly exports: Record<string, string>;
  readonly publish: { readonly include: readonly string[] };
};

type PackageConfig = {
  readonly exports: Record<string, { readonly types?: string; readonly import: string }>;
  readonly files: readonly string[];
};

describe("route registry", () => {
  it("is the source of truth for integration route injection", () => {
    const baseRoutes = integrationRoutes();
    const debugRoutes = integrationRoutes({ debugRoutes: true });
    const rootRoutes = integrationRoutes({ includeRootEndpoint: true });

    expect(baseRoutes).toEqual(CORE_ROUTES);
    expect(debugRoutes).toEqual([...CORE_ROUTES, ...DEBUG_ROUTES]);
    expect(rootRoutes[0].pattern).toBe("/");
    expect(WORKER_ONLY_ROUTES.map((route) => route.pattern)).toContain(
      "/xrpc/com.atproto.sync.subscribeRepos",
    );
    expect(ROUTES.map((route) => route.pattern)).toContain("/debug/sequencer");
  });

  it("keeps npm and JSR package exports aligned", async () => {
    const denoConfig = JSON.parse(await Deno.readTextFile("deno.json")) as DenoConfig;
    const packageConfig = JSON.parse(await Deno.readTextFile("package.json")) as PackageConfig;

    expect(denoConfig.exports["."]).toBe("./mod.ts");
    expect(denoConfig.exports["./worker"]).toBe("./src/worker/index.ts");
    expect(packageConfig.exports["."]?.import).toBe("./index.js");
    expect(packageConfig.exports["./worker"]?.import).toBe("./src/worker/index.ts");
  });

  it("publishes the route registry with both package formats", async () => {
    const denoConfig = JSON.parse(await Deno.readTextFile("deno.json")) as DenoConfig;
    const packageConfig = JSON.parse(await Deno.readTextFile("package.json")) as PackageConfig;

    expect(denoConfig.publish.include).toContain("route-registry.js");
    expect(denoConfig.publish.include).toContain("route-registry.d.ts");
    expect(packageConfig.files).toContain("route-registry.js");
    expect(packageConfig.files).toContain("route-registry.d.ts");
  });
});
