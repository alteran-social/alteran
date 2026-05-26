export type RouteKind = "astro" | "debug" | "root" | "worker-only";

export type AstroRouteDefinition = {
  readonly kind: "astro" | "debug" | "root";
  readonly pattern: string;
  readonly entrypoint: string;
};

export type WorkerRouteDefinition = {
  readonly kind: "worker-only";
  readonly pattern: string;
};

export type RouteDefinition = AstroRouteDefinition | WorkerRouteDefinition;

export declare const RouteKind: {
  readonly Astro: "astro";
  readonly Debug: "debug";
  readonly Root: "root";
  readonly WorkerOnly: "worker-only";
};

export declare const CORE_ROUTES: readonly AstroRouteDefinition[];
export declare const ROOT_ROUTE: AstroRouteDefinition;
export declare const DEBUG_ROUTES: readonly AstroRouteDefinition[];
export declare const WORKER_ONLY_ROUTES: readonly WorkerRouteDefinition[];
export declare const ROUTES: readonly RouteDefinition[];
export declare const DEBUG_SEQUENCER_ROUTE: "/debug/sequencer";
export declare const SUBSCRIBE_REPOS_ROUTE:
  "/xrpc/com.atproto.sync.subscribeRepos";

export declare function integrationRoutes(options?: {
  readonly includeRootEndpoint?: boolean;
  readonly debugRoutes?: boolean;
}): readonly AstroRouteDefinition[];
