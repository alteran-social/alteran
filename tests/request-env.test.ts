import { describe, it } from "@std/testing/bdd";
import { expect } from "@std/expect";
import type { Env } from "../src/env";
import { currentRequestEnv, withRequestEnv } from "../src/lib/request-env";

describe("request-local Worker environment", () => {
  it("isolates overlapping requests and restores nested contexts", async () => {
    const first = { PDS_DID: "did:example:first" } as Env;
    const second = { PDS_DID: "did:example:second" } as Env;
    let release: (() => void) | undefined;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    const firstRequest = withRequestEnv(first, async () => {
      await barrier;
      const nested = await withRequestEnv(second, async () => {
        await Promise.resolve();
        return currentRequestEnv() === second;
      });
      return nested && currentRequestEnv() === first;
    });
    const secondRequest = withRequestEnv(second, async () => {
      await Promise.resolve();
      release?.();
      await Promise.resolve();
      return currentRequestEnv() === second;
    });
    expect(await Promise.all([firstRequest, secondRequest])).toEqual([
      true,
      true,
    ]);
    expect(currentRequestEnv() === undefined).toBe(true);
  });
});
