import { describe, it } from "@std/testing/bdd";
import { expect } from "@std/expect";
import type { Env } from "../src/env";
import {
  getRuntimeString,
  resolveEnvSecrets,
  SecretResolutionError,
} from "../src/lib/secrets";
import { loadSpaceKemKey } from "../src/lib/spaces/kem-key";

async function isConfigurationFailure(
  run: () => Promise<unknown>,
): Promise<boolean> {
  try {
    await run();
    return false;
  } catch (error) {
    return error instanceof SecretResolutionError;
  }
}

describe("request Env placement and credential values", () => {
  it("captures hidden or inherited bindings with their original receivers and lazy KEM store", async () => {
    for (const placement of ["inherited", "hidden"] as const) {
      let storeReads = 0;
      const database = {
        test() {
          return this === database;
        },
      };
      const bucket = {
        test() {
          return this === bucket;
        },
      };
      const sequencer = {
        test() {
          return this === sequencer;
        },
      };
      const assets = {
        test() {
          return this === assets;
        },
      };
      const session = {
        test() {
          return this === session;
        },
      };
      const store = {
        async get() {
          storeReads++;
          return "01".repeat(32);
        },
      };
      const values: Record<string, unknown> = {
        ALTERAN_DB: database,
        ALTERAN_BLOBS: bucket,
        ALTERAN_SEQUENCER: sequencer,
        ASSETS: assets,
        SESSION: session,
        PDS_HOSTNAME: "canonical.example",
        PDS_CORS_ORIGIN: "https://client.example",
        PDS_SPACE_KEM_KEY: store,
      };
      const holder = {};
      const env = Object.create(
        placement === "inherited" ? holder : Object.prototype,
      ) as Env;
      const target = placement === "inherited" ? holder : env;
      const reads: Record<string, number> = {};
      for (const [key, value] of Object.entries(values)) {
        Object.defineProperty(target, key, {
          enumerable: false,
          get() {
            if (this !== env) throw new Error("Wrong Env getter receiver");
            reads[key] = (reads[key] ?? 0) + 1;
            return value;
          },
        });
      }
      Object.defineProperty(target, "HOST_CUSTOM_BINDING", {
        value: {},
        enumerable: false,
      });
      const captured = await resolveEnvSecrets(env);
      for (const [key, value] of Object.entries(values)) {
        expect(reads[key]).toBe(1);
        expect(Object.hasOwn(captured, key)).toBe(true);
        expect((captured as unknown as Record<string, unknown>)[key] === value)
          .toBe(true);
      }
      expect(Object.hasOwn(captured, "HOST_CUSTOM_BINDING")).toBe(false);
      expect((captured.ALTERAN_DB as unknown as typeof database).test()).toBe(
        true,
      );
      expect((captured.ALTERAN_BLOBS as unknown as typeof bucket).test()).toBe(
        true,
      );
      expect((captured.ALTERAN_SEQUENCER as unknown as typeof sequencer).test())
        .toBe(true);
      expect((captured.ASSETS as unknown as typeof assets).test()).toBe(true);
      expect(
        (captured as unknown as { SESSION: typeof session }).SESSION.test(),
      )
        .toBe(true);
      expect(storeReads).toBe(0);
      expect((await loadSpaceKemKey(captured)).tag).toBe("ready");
      expect(storeReads).toBe(1);
    }
  });

  it("rejects blank strings and Secret Store values without changing nonblank bytes", async () => {
    for (
      const key of [
        "USER_PASSWORD",
        "SESSION_JWT_SECRET",
        "REPO_SIGNING_KEY",
        "PDS_PLC_ROTATION_KEY",
        "PDS_SPACE_KEM_KEY",
      ] as const
    ) {
      for (const blank of ["", " \t\n"]) {
        for (const stored of [false, true]) {
          let storeReads = 0;
          const value = stored
            ? {
              get: async () => {
                storeReads++;
                return blank;
              },
            }
            : blank;
          const env = { [key]: value } as unknown as Env;
          expect(
            await isConfigurationFailure(() =>
              getRuntimeString(env, key, "fallback")
            ),
          ).toBe(true);
          storeReads = 0;
          if (key === "PDS_SPACE_KEM_KEY" && stored) {
            const captured = await resolveEnvSecrets(env);
            expect(storeReads).toBe(0);
            expect(
              await isConfigurationFailure(() =>
                getRuntimeString(captured, key, "fallback")
              ),
            ).toBe(true);
            expect(storeReads).toBe(1);
            storeReads = 0;
            expect((await loadSpaceKemKey(captured)).tag).toBe("unavailable");
            expect(storeReads).toBe(1);
          } else {
            expect(await isConfigurationFailure(() => resolveEnvSecrets(env)))
              .toBe(true);
          }
        }
      }
      const nonblank = "  value-with-space  ";
      for (const value of [nonblank, { get: async () => nonblank }]) {
        const env = { [key]: value } as unknown as Env;
        expect((await getRuntimeString(env, key, "fallback")) === nonblank)
          .toBe(true);
      }
      expect(
        (await getRuntimeString({} as Env, key, "fallback")) === "fallback",
      ).toBe(true);
    }
  });
});
