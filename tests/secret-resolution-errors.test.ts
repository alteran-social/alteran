import { describe, it } from "@std/testing/bdd";
import { expect } from "@std/expect";
import type { APIContext } from "astro";
import type { Env } from "../src/env";
import {
  getRuntimeString,
  resolveEnvSecrets,
  resolveSecret,
  SecretResolutionError,
} from "../src/lib/secrets";
import { onRequest } from "../src/middleware";

function requestContext(env: Env): APIContext {
  const request = new Request("https://pds.example/health");
  return {
    request,
    locals: { env },
    url: new URL(request.url),
  } as unknown as APIContext;
}

async function runMiddleware(
  context: APIContext,
  next: () => Promise<Response>,
): Promise<Response> {
  const result = await onRequest(context, next);
  if (!(result instanceof Response)) {
    throw new Error("Middleware returned no response");
  }
  return result;
}

async function capture<T>(
  callback: () => Promise<T>,
): Promise<{ result: T; logs: string[] }> {
  const logs: string[] = [];
  const original = {
    log: console.log,
    error: console.error,
    warn: console.warn,
  };
  const collect = (...values: unknown[]) => {
    logs.push(values.map(String).join(" "));
  };
  try {
    console.log = collect;
    console.error = collect;
    console.warn = collect;
    return { result: await callback(), logs };
  } finally {
    console.log = original.log;
    console.error = original.error;
    console.warn = original.warn;
  }
}

describe("Secret Store failure handling", () => {
  it("sanitizes eager and later request-Env resolution without retaining the cause", async () => {
    const marker = `secret-marker-${crypto.randomUUID()}`;
    const broken = {
      get: async () => {
        throw new Error(marker);
      },
    };
    const env = {
      USER_PASSWORD: broken,
      PDS_SPACE_KEM_KEY: broken,
    } as unknown as Env;
    for (
      const resolve of [
        () => resolveEnvSecrets(env),
        () => getRuntimeString(env, "PDS_SPACE_KEM_KEY", "fallback"),
        () =>
          resolveSecret({
            get get() {
              throw new Error(marker);
            },
          }),
        () => resolveSecret({ get: async () => undefined }),
        () => resolveSecret({ get: "invalid" }),
      ]
    ) {
      let caught: unknown;
      try {
        await resolve();
      } catch (error) {
        caught = error;
      }
      expect(caught instanceof SecretResolutionError).toBe(true);
      const sanitized = caught instanceof Error
        ? `${caught.message}\n${caught.stack ?? ""}`
        : String(caught);
      expect(sanitized.includes(marker)).toBe(false);
      expect(caught instanceof Error && "cause" in caught).toBe(false);
    }
  });

  it("returns a controlled 500 without disclosing store errors in responses or logs", async () => {
    const marker = `secret-marker-${crypto.randomUUID()}`;
    const broken = {
      get: async () => {
        throw new Error(marker);
      },
    };
    for (
      const env of [
        { USER_PASSWORD: broken },
        { PDS_SPACE_KEM_KEY: broken },
      ] as unknown as Env[]
    ) {
      const context = requestContext(env);
      let nextCalled = false;
      const { result, logs } = await capture(() =>
        runMiddleware(context, async () => {
          nextCalled = true;
          await getRuntimeString(env, "PDS_SPACE_KEM_KEY", "fallback");
          return new Response("unexpected");
        })
      );
      expect(result.status).toBe(500);
      const body = await result.text();
      expect(body.includes("Secret binding could not be resolved")).toBe(true);
      expect(
        body.includes(marker) || logs.some((line) => line.includes(marker)),
      ).toBe(false);
      expect(nextCalled).toBe(env.USER_PASSWORD === undefined);
    }
  });

  it("does not replace unrelated application or D1 errors", async () => {
    const marker = `application-marker-${crypto.randomUUID()}`;
    const database = {
      prepare() {
        throw new Error(marker);
      },
    };
    const env = {
      ALTERAN_DB: database,
      PDS_DID: "did:example:test",
      PDS_HANDLE: "test.example",
    } as unknown as Env;
    const { result, logs } = await capture(() =>
      runMiddleware(requestContext(env), async () => {
        database.prepare();
        return new Response("unexpected");
      })
    );
    expect(result.status).toBe(500);
    expect((await result.text()).includes(marker)).toBe(true);
    expect(logs.some((line) => line.includes(marker))).toBe(true);
  });

  it("sanitizes credential getters at capture and later lookup", async () => {
    const marker = `getter-marker-${crypto.randomUUID()}`;
    for (
      const key of [
        "PDS_DID",
        "PDS_HANDLE",
        "PDS_HOSTNAME",
        "USER_PASSWORD",
        "SESSION_JWT_SECRET",
        "REPO_SIGNING_KEY",
        "PDS_PLC_ROTATION_KEY",
        "PDS_SPACE_KEM_KEY",
      ] as const
    ) {
      const env = {} as Env;
      Object.defineProperty(env, key, {
        enumerable: true,
        get() {
          throw new Error(marker);
        },
      });
      for (
        const read of [
          () => resolveEnvSecrets(env),
          () => getRuntimeString(env, key, "fallback"),
        ]
      ) {
        let caught: unknown;
        try {
          await read();
        } catch (error) {
          caught = error;
        }
        expect(caught instanceof SecretResolutionError).toBe(true);
        expect(caught instanceof Error && !caught.message.includes(marker))
          .toBe(true);
        expect(caught instanceof Error && !caught.stack?.includes(marker))
          .toBe(true);
        expect(caught instanceof Error && !("cause" in caught)).toBe(true);
      }
      const { result, logs } = await capture(() =>
        runMiddleware(
          requestContext(env),
          async () => new Response("unexpected"),
        )
      );
      const body = await result.text();
      expect(result.status).toBe(500);
      expect(body.includes("Secret binding could not be resolved")).toBe(true);
      expect(
        body.includes(marker) || logs.some((line) => line.includes(marker)),
      )
        .toBe(false);
    }
  });

  it("rejects non-string credential values without using a fallback", async () => {
    for (
      const key of [
        "PDS_DID",
        "PDS_HANDLE",
        "PDS_HOSTNAME",
        "USER_PASSWORD",
        "SESSION_JWT_SECRET",
        "REPO_SIGNING_KEY",
        "PDS_PLC_ROTATION_KEY",
        "PDS_SPACE_KEM_KEY",
      ] as const
    ) {
      for (const value of [false, 0, true, null, {}]) {
        const env = { [key]: value } as unknown as Env;
        for (
          const read of [
            () => resolveEnvSecrets(env),
            () => getRuntimeString(env, key, "fallback"),
            () => resolveSecret(value),
          ]
        ) {
          let caught: unknown;
          try {
            await read();
          } catch (error) {
            caught = error;
          }
          expect(caught instanceof SecretResolutionError).toBe(true);
        }
      }
    }
    const scalars = {
      PDS_MAX_BLOB_SIZE: 0,
      PDS_WS_HIBERNATE: false,
    } as unknown as Env;
    expect(await getRuntimeString(scalars, "PDS_MAX_BLOB_SIZE")).toBe("0");
    expect(await getRuntimeString(scalars, "PDS_WS_HIBERNATE")).toBe("false");
  });

  it("rejects a Secret Store hostname without consulting it", async () => {
    let reads = 0;
    const env = {
      PDS_HOSTNAME: {
        get: async () => {
          reads++;
          return "canonical.example";
        },
      },
    } as unknown as Env;
    for (
      const read of [
        () => resolveEnvSecrets(env),
        () => getRuntimeString(env, "PDS_HOSTNAME", "fallback"),
      ]
    ) {
      let caught: unknown;
      try {
        await read();
      } catch (error) {
        caught = error;
      }
      expect(caught instanceof SecretResolutionError).toBe(true);
    }
    expect(reads).toBe(0);
  });

  it("validates inherited or non-enumerable lazy credential properties", async () => {
    const marker = `getter-marker-${crypto.randomUUID()}`;
    const inherited = Object.create({
      get PDS_SPACE_KEM_KEY() {
        throw new Error(marker);
      },
    }) as Env;
    const hidden = {} as Env;
    Object.defineProperty(hidden, "PDS_SPACE_KEM_KEY", { value: false });
    for (const env of [inherited, hidden]) {
      let caught: unknown;
      try {
        await resolveEnvSecrets(env);
      } catch (error) {
        caught = error;
      }
      expect(caught instanceof SecretResolutionError).toBe(true);
      expect(caught instanceof Error && !caught.message.includes(marker)).toBe(
        true,
      );
      expect(caught instanceof Error && !("cause" in caught)).toBe(true);
    }
  });

  it("sanitizes reflection and ordinary binding getter failures at the middleware boundary", async () => {
    const marker = `reflection-marker-${crypto.randomUUID()}`;
    const fail = () => {
      throw new Error(marker);
    };
    const examples = [
      new Proxy({}, { ownKeys: fail }),
      new Proxy({ USER_PASSWORD: "value" }, { getOwnPropertyDescriptor: fail }),
      new Proxy({}, { has: fail }),
      new Proxy({ ALTERAN_DB: {} }, { get: fail }),
    ] as Env[];
    for (const env of examples) {
      const { result, logs } = await capture(() =>
        runMiddleware(
          requestContext(env),
          async () => new Response("unexpected"),
        )
      );
      const body = await result.text();
      expect(result.status).toBe(500);
      expect(body.includes("Secret binding could not be resolved")).toBe(true);
      expect(
        body.includes(marker) || logs.some((line) => line.includes(marker)),
      ).toBe(false);
    }
  });

  it("retains lazy Spaces secrets and ordinary binding copy behavior", async () => {
    let secretReads = 0;
    let bindingReads = 0;
    const store = {
      get: async () => {
        secretReads++;
        return "key";
      },
    };
    const binding = {};
    const symbol = Symbol("binding");
    const env = {
      PDS_SPACE_KEM_KEY: store,
      [symbol]: binding,
    } as unknown as Env;
    Object.defineProperty(env, "ALTERAN_DB", {
      enumerable: true,
      configurable: true,
      get() {
        bindingReads++;
        return binding;
      },
    });
    Object.defineProperty(env, "hidden", { value: true, enumerable: false });
    Object.defineProperty(env, "__proto__", {
      value: binding,
      enumerable: true,
    });
    const resolved = await resolveEnvSecrets(env);
    expect(bindingReads).toBe(1);
    expect(resolved.ALTERAN_DB === binding).toBe(true);
    expect(
      (resolved as unknown as Record<PropertyKey, unknown>)[symbol] === binding,
    ).toBe(true);
    expect(Object.hasOwn(resolved, "hidden")).toBe(false);
    expect(Object.hasOwn(resolved, "__proto__")).toBe(true);
    expect(Object.getPrototypeOf(resolved) === Object.prototype).toBe(true);
    expect(resolved.PDS_SPACE_KEM_KEY === store).toBe(true);
    expect(secretReads).toBe(0);
    expect((await resolveSecret(resolved.PDS_SPACE_KEM_KEY)) === "key").toBe(
      true,
    );
    expect(secretReads).toBe(1);

    const unrelated = new Error("ordinary binding failed");
    Object.defineProperty(env, "ALTERAN_DB", {
      enumerable: true,
      configurable: true,
      get() {
        throw unrelated;
      },
    });
    for (
      const read of [
        () => resolveEnvSecrets(env),
        () => getRuntimeString(env, "ALTERAN_DB"),
      ]
    ) {
      let caught: unknown;
      try {
        await read();
      } catch (error) {
        caught = error;
      }
      expect(caught instanceof SecretResolutionError).toBe(true);
      expect(
        caught instanceof Error && !caught.message.includes(unrelated.message),
      ).toBe(true);
    }
  });
});
