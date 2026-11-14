import { createPdsFetchHandler } from "../../src/worker/runtime";
import type { Env } from "../../src/env";

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const mode = request.headers.get("x-test-mode");
    let changed: unknown = env;
    if (mode === "secret-throws" || mode === "secret-throws-observed") {
      changed = {
        ...env,
        PDS_DID: {
          get: () => {
            throw new Error("private-entry-secret");
          },
        },
      };
    } else if (mode === "secret-getter-throws-observed") {
      changed = { ...env };
      Object.defineProperty(changed, "USER_PASSWORD", {
        enumerable: true,
        get() {
          throw new Error("private-entry-secret");
        },
      });
    } else if (mode === "reflection-throws-observed") {
      changed = new Proxy({ ...env }, {
        ownKeys() {
          throw new Error("private-entry-secret");
        },
      });
    } else if (
      mode === "config-values-observed" || mode === "config-missing-observed"
    ) {
      changed = {
        ...env,
        PDS_DID: mode === "config-values-observed"
          ? { get: async () => "private-entry-secret" }
          : undefined,
        PDS_HANDLE: { get: async () => "https://private-entry-secret" },
        PDS_MAX_BLOB_SIZE: "private-entry-secret",
        PDS_MAX_JSON_BYTES: "private-entry-secret",
        PDS_RATE_LIMIT_PER_MIN: "private-entry-secret",
        ENVIRONMENT: "private-entry-secret",
      };
    } else if (mode === "invalid-config") {
      changed = { ...env, PDS_DID: "" };
    } else if (mode === "seed-throws") {
      changed = { ...env, PDS_DID: "did:example:seedfailure" };
    }
    if (
      mode !== "secret-throws-observed" &&
      mode !== "secret-getter-throws-observed" &&
      mode !== "reflection-throws-observed" &&
      mode !== "config-values-observed" &&
      mode !== "config-missing-observed"
    ) {
      return await createPdsFetchHandler()(
        request as never,
        changed as Env,
        ctx as never,
      ) as unknown as Response;
    }
    const entries: string[] = [];
    const original = {
      log: console.log,
      error: console.error,
      warn: console.warn,
    };
    const collect = (...values: unknown[]) => {
      entries.push(values.map(String).join(" "));
    };
    try {
      console.log = collect;
      console.error = collect;
      console.warn = collect;
      const response = await createPdsFetchHandler()(
        request as never,
        changed as Env,
        ctx as never,
      ) as unknown as Response;
      const headers = new Headers(response.headers);
      headers.set(
        "x-secret-marker-observed",
        String(entries.some((line) => line.includes("private-entry-secret"))),
      );
      headers.set(
        "x-config-names-observed",
        String(
          [
            "PDS_DID",
            "PDS_HANDLE",
            "PDS_MAX_BLOB_SIZE",
            "PDS_MAX_JSON_BYTES",
            "PDS_RATE_LIMIT_PER_MIN",
          ]
            .every((name) => entries.some((line) => line.includes(name))),
        ),
      );
      return new Response(response.body, { status: response.status, headers });
    } finally {
      console.log = original.log;
      console.error = original.error;
      console.warn = original.warn;
    }
  },
};
