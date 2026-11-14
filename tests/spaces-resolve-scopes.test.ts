import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import {
  MAX_SPACE_DECLARATIONS_PER_REQUEST,
  resolveSpaceScopes,
  type ResolveSpaceScopesOptions,
} from "../src/lib/spaces/resolve-scopes";
import type { SpaceLexiconResolution } from "../src/lib/spaces/lexicon-resolution";

const SUBJECT = "did:plc:abcdefghijklmnopqrstuvwx";
const CLIENT = "https://client.example/metadata.json";
const TYPE = "com.example.forum";
const COLLECTION = "com.example.note";
const CID = "bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua";
const REVISION = "3n2a5tw2wd22l";

function proven(
  spaceType: string,
  collections = [COLLECTION],
): SpaceLexiconResolution {
  return {
    tag: "proven",
    main: {
      spaceType,
      publisherDid: SUBJECT,
      recordCid: CID,
      key: "any",
      collections,
    },
    definitions: "main-only",
    head: { cid: CID, revision: REVISION },
    observedAt: Date.now(),
  };
}

function request(scopes: readonly string[]) {
  return { subject: SUBJECT, clientId: CLIENT, scopes };
}

describe("request-wide Space scope resolution", () => {
  it("deduplicates declarations and preserves each original scope", async () => {
    const calls: string[] = [];
    const scopes = [
      `space:${TYPE}?action=create`,
      `space?spaceType=${TYPE}&action=delete`,
      `space:com.example.blog?collection=${COLLECTION}&action=update`,
      "space:*?action=read_self",
    ];
    const result = await resolveSpaceScopes(request(scopes), {
      resolve: (type) => {
        calls.push(type);
        return Promise.resolve(proven(type, [COLLECTION, COLLECTION]));
      },
    });
    expect(result.tag).toBe("resolved");
    if (result.tag !== "resolved") return;
    expect(calls).toEqual([TYPE]);
    expect(result.subject).toBe(SUBJECT);
    expect(result.clientId).toBe(CLIENT);
    expect(result.grants.map((grant) => grant.requestedScope)).toEqual(scopes);
    expect(result.declarations[0].collections).toEqual([COLLECTION]);
    expect(result.grants[0].permission.collections.values).toEqual([
      COLLECTION,
    ]);
    expect(result.grants[1].permission.collections.values).toEqual([
      COLLECTION,
    ]);
    expect(result.grants[3].permission.collections.values).toEqual([]);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.declarations[0].collections)).toBe(true);
    expect(Object.isFrozen(result.grants[0].permission.actions)).toBe(true);
  });

  it("does not resolve explicit collections or wildcard defaults", async () => {
    let calls = 0;
    const result = await resolveSpaceScopes(
      request([
        `space:${TYPE}?collection=${COLLECTION}`,
        "space:*?action=read",
      ]),
      {
        resolve: () => {
          calls++;
          throw new Error("unexpected resolution");
        },
      },
    );
    expect(result.tag).toBe("resolved");
    expect(calls).toBe(0);
  });

  it("rejects excess types before starting any network work", async () => {
    let calls = 0;
    const scopes = Array.from({
      length: MAX_SPACE_DECLARATIONS_PER_REQUEST + 1,
    }, (_, index) => `space:com.example.type${index}`);
    const result = await resolveSpaceScopes(request(scopes), {
      resolve: (type) => {
        calls++;
        return Promise.resolve(proven(type));
      },
    });
    expect(result.tag).toBe("limit");
    expect(calls).toBe(0);
  });

  it("enforces the reserved DNS and HTTP subrequest limits", async () => {
    let dnsCalls = 0;
    let httpCalls = 0;
    const result = await resolveSpaceScopes(request([`space:${TYPE}`]), {
      resolveTxt: () => {
        dnsCalls++;
        return Promise.resolve([[`did=${SUBJECT}`]]);
      },
      fetch: () => {
        httpCalls++;
        return Promise.resolve(new Response(null));
      },
      resolve: async (type, options) => {
        if (!options.resolveTxt || !options.fetch) {
          throw new Error("Expected budgeted adapters");
        }
        for (let index = 0; index < 6; index++) {
          await options.resolveTxt("_lexicon.example.com").catch(() => null);
        }
        for (let index = 0; index < 12; index++) {
          await options.fetch("https://example.com/").catch(() => null);
        }
        return proven(type);
      },
    });
    expect(result.tag).toBe("limit");
    expect(dnsCalls).toBe(4);
    expect(httpCalls).toBe(10);
  });

  it("does not merge distinct NSID names or change their case", async () => {
    const calls: string[] = [];
    const result = await resolveSpaceScopes(
      request([`space:${TYPE}`, "space:com.example.Forum"]),
      {
        resolve: (type) => {
          calls.push(type);
          return Promise.resolve(proven(type));
        },
      },
    );
    expect(result.tag).toBe("resolved");
    expect(calls).toEqual([TYPE, "com.example.Forum"]);
  });

  it("rejects invalid or excessive scope inputs before lookup", async () => {
    let calls = 0;
    const options: ResolveSpaceScopesOptions = {
      resolve: (type) => {
        calls++;
        return Promise.resolve(proven(type));
      },
    };
    for (
      const scopes of [
        [`space:${TYPE}`, `space:${TYPE}`],
        ["space:invalid"],
        [`space:${"a".repeat(8193)}`],
        Array(129).fill(`space:${TYPE}`),
      ]
    ) {
      expect((await resolveSpaceScopes(request(scopes), options)).tag).toBe(
        "invalid",
      );
    }
    expect(calls).toBe(0);
    expect(
      (await resolveSpaceScopes({
        ...request([`space:${TYPE}?collection=${COLLECTION}`]),
        subject: "did:example:%ZZ",
      }, options)).tag,
    ).toBe("invalid");
    expect(
      (await resolveSpaceScopes({
        ...request([`space:${TYPE}?collection=${COLLECTION}`]),
        clientId: "not-a-uri",
      }, options)).tag,
    ).toBe("invalid");
    expect(
      (await resolveSpaceScopes(
        request([
          `space:${TYPE}?authority=did%3Aexample%3A%25ZZ&collection=${COLLECTION}`,
        ]),
        options,
      )).tag,
    ).toBe("invalid");
  });

  it("returns no partial grants if a declaration is unsupported", async () => {
    let calls = 0;
    const result = await resolveSpaceScopes(
      request([`space:${TYPE}`, "space:com.example.blog"]),
      {
        resolve: (type) => {
          calls++;
          return Promise.resolve(
            calls === 1 ? proven(type) : {
              tag: "unsupported",
              recordCid: CID,
              head: { cid: CID, revision: REVISION },
              observedAt: Date.now(),
            },
          );
        },
      },
    );
    expect(result.tag).toBe("unsupported");
    expect(Object.hasOwn(result, "grants")).toBe(false);
    expect(calls).toBe(2);
  });

  it("rejects stale, malformed and mismatched declaration evidence", async () => {
    const good = proven(TYPE);
    if (good.tag !== "proven") throw new Error("Expected proof");
    const bad = [
      { ...good, observedAt: Date.now() - 60_000 },
      { ...good, observedAt: Date.now() + 60_000 },
      { ...good, main: { ...good.main, spaceType: "com.example.other" } },
      { ...good, main: { ...good.main, recordCid: "not-a-cid" } },
      { ...good, head: { ...good.head, revision: "bad" } },
      { ...good, main: { ...good.main, key: "../../invalid" } },
    ];
    for (const value of bad) {
      expect(
        (await resolveSpaceScopes(request([`space:${TYPE}`]), {
          resolve: () => Promise.resolve(value),
        })).tag,
      ).toBe("invalid");
    }
  });

  it("rejects resolver results with getters or revoked proxies", async () => {
    let reads = 0;
    const changing = Object.defineProperty({}, "tag", {
      enumerable: true,
      get() {
        reads++;
        return reads === 1 ? "invalid" : "resolved";
      },
    });
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    for (
      const [value, expected] of [[changing, "invalid"], [
        revoked.proxy,
        "unavailable",
      ]] as const
    ) {
      const result = await resolveSpaceScopes(request([`space:${TYPE}`]), {
        resolve: () => Promise.resolve(value as SpaceLexiconResolution),
      });
      expect(result.tag).toBe(expected);
    }
    expect(reads).toBe(0);
    const signal = Proxy.revocable(new AbortController().signal, {});
    signal.revoke();
    expect(
      (await resolveSpaceScopes(request([`space:${TYPE}`]), {
        signal: signal.proxy,
      })).tag,
    ).toBe("invalid");
  });

  it("stops at a shared deadline and ignores a late resolution", async () => {
    let calls = 0;
    let complete: ((value: SpaceLexiconResolution) => void) | undefined;
    const pending = new Promise<SpaceLexiconResolution>((resolve) =>
      complete = resolve
    );
    const result = await resolveSpaceScopes(
      request([`space:${TYPE}`, "space:com.example.blog"]),
      {
        timeoutMs: 20,
        resolve: () => {
          calls++;
          return pending;
        },
      },
    );
    expect(result.tag).toBe("unavailable");
    expect(calls).toBe(1);
    complete?.(proven(TYPE));
    await Promise.resolve();
    expect(result.tag).toBe("unavailable");
  });

  it("captures scope inputs before the first asynchronous resolution", async () => {
    const scopes = [`space:${TYPE}`];
    let release: ((value: SpaceLexiconResolution) => void) | undefined;
    const pending = new Promise<SpaceLexiconResolution>((resolve) =>
      release = resolve
    );
    const result = resolveSpaceScopes(request(scopes), {
      resolve: () => pending,
    });
    scopes[0] = "space:com.example.other?collection=*";
    release?.(proven(TYPE));
    const resolved = await result;
    expect(resolved.tag).toBe("resolved");
    if (resolved.tag === "resolved") {
      expect(resolved.grants[0].requestedScope).toBe(`space:${TYPE}`);
    }
  });
});
