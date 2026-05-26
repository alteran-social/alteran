import { seed } from "../db/seed";
import type { Env } from "../env";
import { validateConfigOrThrow } from "../lib/config";
import { notifyRelaysIfNeeded } from "../lib/relay";
import { resolveEnvSecrets } from "../lib/secrets";
import { SUBSCRIBE_REPOS_ROUTE } from "../../route-registry.js";
import { handleWorkerDebugRoute } from "./debug-routes";
import { normalizePdsRequestForAstro } from "./normalize-request";
import type {
  ExecutionContext,
  Request as WorkersRequest,
  Response as WorkersResponse,
} from "@cloudflare/workers-types";

export type PdsFetchHandler = (
  request: WorkersRequest,
  env: Env,
  executionContext: ExecutionContext,
) => Promise<WorkersResponse>;

type AstroCloudflareHandler = (
  request: Request,
  env: Env,
  executionContext: ExecutionContext,
) => Promise<Response>;

export function createPdsFetchHandler(): PdsFetchHandler {
  return async function fetch(
    request: WorkersRequest,
    env: Env,
    executionContext: ExecutionContext,
  ) {
    const debugResponse = await handleWorkerDebugRoute(
      env,
      request as unknown as Request,
    );
    if (debugResponse) return debugResponse as unknown as WorkersResponse;

    const resolvedEnv = await resolveEnvSecrets(env);

    if (!resolvedEnv.ASSETS) {
      resolvedEnv.ASSETS = {
        async fetch() {
          return new Response("Not Found", {
            status: 404,
            headers: { "Cache-Control": "public, max-age=60" },
          });
        },
      };
    }

    try {
      validateConfigOrThrow(resolvedEnv);
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: "ConfigurationError",
          message: error instanceof Error
            ? error.message
            : "Invalid configuration",
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        },
      ) as unknown as WorkersResponse;
    }

    if (request.method === "OPTIONS") {
      const headers = new Headers({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Max-Age": "86400",
      });
      return new Response(null, {
        status: 204,
        headers,
      }) as unknown as WorkersResponse;
    }

    await seed(resolvedEnv.ALTERAN_DB, resolvedEnv.PDS_DID as string);

    try {
      const pathname = new URL(request.url).pathname;
      const isRelayPath =
        pathname === "/xrpc/com.atproto.server.describeServer" ||
        pathname === SUBSCRIBE_REPOS_ROUTE;
      if (!isRelayPath) {
        executionContext.waitUntil(
          notifyRelaysIfNeeded(resolvedEnv, request.url),
        );
      }
    } catch {
      // Never block on relay notification.
    }

    const url = new URL(request.url);
    if (url.pathname === SUBSCRIBE_REPOS_ROUTE) {
      const upgrade = request.headers.get("upgrade");
      if (upgrade !== "websocket") {
        try {
          console.log(JSON.stringify({
            level: "warn",
            type: "ws_expected",
            path: url.pathname,
            method: request.method,
            message: "subscribeRepos requires WebSocket upgrade",
            timestamp: new Date().toISOString(),
          }));
        } catch {
          // Logging-only path; never block the response on log serialization.
        }
        return new Response(
          "This endpoint requires a WebSocket (wss://) upgrade",
          { status: 426 },
        ) as unknown as WorkersResponse;
      }
      if (!resolvedEnv.ALTERAN_SEQUENCER) {
        return new Response("Sequencer not configured", {
          status: 503,
        }) as unknown as WorkersResponse;
      }

      const id = resolvedEnv.ALTERAN_SEQUENCER.idFromName("default");
      const stub = resolvedEnv.ALTERAN_SEQUENCER.get(id);
      return (await stub.fetch(
        request as unknown as Request,
      )) as unknown as WorkersResponse;
    }

    const { handle: rawHandle } = await import("@astrojs/cloudflare/handler");
    const handle = rawHandle as unknown as AstroCloudflareHandler;
    const response = await handle(
      normalizePdsRequestForAstro(request) as unknown as Request,
      resolvedEnv,
      executionContext,
    );
    return response as unknown as WorkersResponse;
  };
}
