import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import type { APIContext } from "astro";
import type {
  ExecutionContext,
  Request as WorkersRequest,
} from "@cloudflare/workers-types";
import {
  DEBUG_SEQUENCER_ROUTE,
  WORKER_ONLY_ROUTES,
} from "../route-registry.js";
import type { Env } from "../src/env";
import { makeEnv } from "./helpers/env";
import { isDebugRequestAllowed } from "../src/lib/debug-policy";
import { createPdsFetchHandler } from "../src/worker/fetch-handler";
import { handleWorkerDebugRoute } from "../src/worker/debug-routes";
import * as DebugBlob from "../src/pages/debug/blob/[...key].ts";
import * as DebugDbBootstrap from "../src/pages/debug/db/bootstrap";
import * as DebugDbCommits from "../src/pages/debug/db/commits";
import * as DebugRecord from "../src/pages/debug/record";
import * as DebugBlobGc from "../src/pages/debug/gc/blobs";
import * as DebugSequencer from "../src/pages/debug/sequencer";

function context(
  env: Awaited<ReturnType<typeof makeEnv>>,
  request: Request,
  params: Record<string, string | undefined> = {},
): APIContext {
  return { locals: { env }, request, params } as unknown as APIContext;
}

function sideEffectRejectingContext(): ExecutionContext {
  return {
    waitUntil() {
      throw new Error(
        "debug route should return before scheduling side effects",
      );
    },
    passThroughOnException() {},
  } as unknown as ExecutionContext;
}

describe("debug routes", () => {
  it("does not expose debug routes in production", async () => {
    const env = await makeEnv({
      ENVIRONMENT: "production",
      PDS_HOSTNAME: "pds.example",
    });

    const recordPost = await DebugRecord.POST(
      context(
        env,
        new Request("https://pds.example/debug/record", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            uri: "at://did:example:test/app.bsky.feed.post/debug",
            json: { text: "blocked" },
          }),
        }),
      ),
    );
    expect(recordPost.status).toBe(404);

    const gcPost = await DebugBlobGc.POST(
      context(
        env,
        new Request("https://pds.example/debug/gc/blobs", {
          method: "POST",
        }),
      ),
    );
    expect(gcPost.status).toBe(404);

    const blobGet = await DebugBlob.GET(context(
      env,
      new Request("https://pds.example/debug/blob/example", { method: "GET" }),
      { key: "example" },
    ));
    expect(blobGet.status).toBe(404);

    const blobPut = await DebugBlob.PUT(context(
      env,
      new Request("https://pds.example/debug/blob/example", {
        method: "PUT",
        body: new Uint8Array([1]),
      }),
      { key: "example" },
    ));
    expect(blobPut.status).toBe(404);

    const bootstrapPost = await DebugDbBootstrap.POST(context(
      env,
      new Request("https://pds.example/debug/db/bootstrap", { method: "POST" }),
    ));
    expect(bootstrapPost.status).toBe(404);

    const commitsGet = await DebugDbCommits.GET(context(
      env,
      new Request("https://pds.example/debug/db/commits", { method: "GET" }),
    ));
    expect(commitsGet.status).toBe(404);

    const sequencerGet = await DebugSequencer.GET(context(
      env,
      new Request("https://pds.example/debug/sequencer", { method: "GET" }),
    ));
    expect(sequencerGet.status).toBe(404);
  });

  it("allows debug routes only for loopback development requests by default", async () => {
    const env = await makeEnv();

    const localAllowed = await isDebugRequestAllowed(
      env,
      new Request("http://localhost/debug/record", { method: "GET" }),
    );
    expect(localAllowed).toBe(true);

    const remoteAllowed = await isDebugRequestAllowed(
      env,
      new Request("https://pds.example/debug/record", { method: "GET" }),
    );
    expect(remoteAllowed).toBe(false);

    const bootstrapResponse = await DebugDbBootstrap.POST(context(
      env,
      new Request("http://localhost/debug/db/bootstrap", { method: "POST" }),
    ));
    expect(bootstrapResponse.status).toBe(200);

    await env.ALTERAN_BLOBS.put("example", "stored locally", {
      httpMetadata: { contentType: "text/plain" },
    });

    const blobGet = await DebugBlob.GET(context(
      env,
      new Request("http://localhost/debug/blob/example", { method: "GET" }),
      { key: "example" },
    ));
    expect(blobGet.status).toBe(200);
    expect(await blobGet.text()).toBe("stored locally");

    const sequencerResponse = await DebugSequencer.GET(context(
      env,
      new Request("http://localhost/debug/sequencer", { method: "GET" }),
    ));
    expect(sequencerResponse.status).toBe(503);
  });

  it("uses public-host parsing for local debug hostnames", async () => {
    const localhostWithPort = await makeEnv({
      PDS_HOSTNAME: "localhost:4321",
    });
    expect(
      await isDebugRequestAllowed(
        localhostWithPort,
        new Request("http://localhost:4321/debug/record"),
      ),
    ).toBe(true);

    const ipv6WithPort = await makeEnv({
      PDS_HOSTNAME: "https://[::1]:4321",
    });
    expect(
      await isDebugRequestAllowed(
        ipv6WithPort,
        new Request("http://[::1]:4321/debug/record"),
      ),
    ).toBe(true);
  });

  it("fails closed when the debug token cannot be resolved", async () => {
    const env = {
      ENVIRONMENT: "production",
      PDS_HOSTNAME: "pds.example",
      PDS_DEBUG_TOKEN: {
        async get(): Promise<string> {
          throw new Error("unavailable");
        },
      },
    } as Env;

    const allowed = await isDebugRequestAllowed(
      env,
      new Request("https://pds.example/debug/record", {
        headers: { authorization: "Bearer debug-secret" },
      }),
    );

    expect(allowed).toBe(false);
  });

  it("allows production debug routes with an explicit bearer token", async () => {
    const env = await makeEnv({
      ENVIRONMENT: "production",
      PDS_HOSTNAME: "pds.example",
      PDS_DEBUG_TOKEN: "debug-secret",
    });

    const response = await DebugRecord.GET(context(
      env,
      new Request("https://pds.example/debug/record", {
        method: "GET",
        headers: { authorization: "Bearer debug-secret" },
      }),
    ));

    expect(response.status).toBe(400);
  });

  it("applies the same production policy to the Worker sequencer bypass", async () => {
    const env = await makeEnv({
      ENVIRONMENT: "production",
      PDS_HOSTNAME: "pds.example",
    });

    expect(WORKER_ONLY_ROUTES.map((route) => route.pattern)).toContain(
      DEBUG_SEQUENCER_ROUTE,
    );

    const response = await handleWorkerDebugRoute(
      env,
      new Request(`https://pds.example${DEBUG_SEQUENCER_ROUTE}`, {
        method: "GET",
      }),
    );

    expect(response?.status).toBe(404);

    const unsupported = await handleWorkerDebugRoute(
      env,
      new Request("https://pds.example/debug/other", { method: "GET" }),
    );
    expect(unsupported).toBeNull();
  });

  it("denies Worker debug routes before Worker initialization side effects", async () => {
    const fetch = createPdsFetchHandler();
    const env = {
      ENVIRONMENT: "production",
      PDS_HOSTNAME: "pds.example",
    } as Env;

    const response = await fetch(
      new Request(`https://pds.example${DEBUG_SEQUENCER_ROUTE}`, {
        method: "GET",
      }) as unknown as WorkersRequest,
      env,
      sideEffectRejectingContext(),
    );

    expect(response.status).toBe(404);
  });
});
