import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { resolveSpaceScopes } from "../src/lib/spaces/resolve-scopes";

describe("Space scope resolver transport", () => {
  it("requires BYOB streams when the production fetch is wrapped for counting", async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = () => {
      calls++;
      return Promise.resolve(
        Response.json({ id: "did:plc:abcdefghijklmnopqrstuvwx" }),
      );
    };
    try {
      const result = await resolveSpaceScopes({
        subject: "did:plc:abcdefghijklmnopqrstuvwx",
        clientId: "https://client.example/metadata.json",
        scopes: ["space:com.example.forum"],
      }, {
        resolveTxt: () =>
          Promise.resolve([["did=did:plc:abcdefghijklmnopqrstuvwx"]]),
      });
      expect(result.tag).toBe("unavailable");
      expect(calls).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
