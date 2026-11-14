import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import {
  resolveLexiconAuthority,
  type ResolveLexiconAuthorityOptions,
} from "../src/lib/spaces/lexicon-authority";

const DID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

describe("Lexicon namespace DNS authority", () => {
  it("queries the exact reversed namespace authority once", async () => {
    const queries: string[] = [];
    const result = await resolveLexiconAuthority(
      "edu.university.dept.lab.blogging.getBlogPost",
      {
        resolveTxt: (name) => {
          queries.push(name);
          return Promise.resolve([[`did=${DID}`]]);
        },
      },
    );
    expect(result).toEqual({ tag: "resolved", did: DID });
    expect(queries).toEqual(["_lexicon.blogging.lab.dept.university.edu"]);
  });

  it("joins each TXT record's chunks and ignores unrelated records", async () => {
    const result = await resolveLexiconAuthority("app.toy.record", {
      resolveTxt: () =>
        Promise.resolve([["v=spf1", " ~all"], [
          "di",
          "d=did:plc:",
          "ewvi7nxzyoun6zhxrhs64oiz",
        ]]),
    });
    expect(result).toEqual({ tag: "resolved", did: DID });
  });

  it("does not fall back to a parent authority after a DNS failure", async () => {
    const queries: string[] = [];
    const result = await resolveLexiconAuthority("app.toy.record", {
      resolveTxt: (name) => {
        queries.push(name);
        return Promise.reject(
          Object.assign(new Error("not found"), { code: "ENOTFOUND" }),
        );
      },
    });
    expect(result).toEqual({ tag: "notFound" });
    expect(queries).toEqual(["_lexicon.toy.app"]);
  });

  it("distinguishes absent, ambiguous, malformed and unavailable DNS results", async () => {
    for (const answer of [[], [["unrelated"]], [["DID=did:plc:alice"]]]) {
      expect(
        await resolveLexiconAuthority("app.toy.record", {
          resolveTxt: () => Promise.resolve(answer),
        }),
      ).toEqual({
        tag: "notFound",
      });
    }
    for (
      const answer of [
        [[`did=${DID}`], [`did=${DID}`]],
        [["did=invalid"], [`did=${DID}`]],
      ]
    ) {
      expect(
        await resolveLexiconAuthority("app.toy.record", {
          resolveTxt: () => Promise.resolve(answer),
        }),
      ).toEqual({
        tag: "invalid",
        reason: "ambiguous",
      });
    }
    for (const answer of [[["did="]], [["did=not-a-did"]], [[`did=${DID} `]]]) {
      expect(
        await resolveLexiconAuthority("app.toy.record", {
          resolveTxt: () => Promise.resolve(answer),
        }),
      ).toEqual({
        tag: "invalid",
        reason: "did",
      });
    }
    for (const code of ["ENOTFOUND", "ENODATA"]) {
      const result = await resolveLexiconAuthority("app.toy.record", {
        resolveTxt: () =>
          Promise.reject(Object.assign(new Error("dns"), { code })),
      });
      expect(result).toEqual({ tag: "notFound" });
    }
    for (const code of ["SERVFAIL", "ENOTIMP", "ETIMEOUT"]) {
      const result = await resolveLexiconAuthority("app.toy.record", {
        resolveTxt: () =>
          Promise.reject(Object.assign(new Error("dns"), { code })),
      });
      expect(result).toEqual({ tag: "unavailable", reason: "dns" });
    }
    const invalidError = Object.defineProperty({}, "code", {
      get: () => {
        throw new Error("bad code");
      },
    });
    expect(
      await resolveLexiconAuthority("app.toy.record", {
        resolveTxt: () => Promise.reject(invalidError),
      }),
    ).toEqual({ tag: "unavailable", reason: "dns" });
  });

  it("rejects malformed and oversized DNS responses", async () => {
    const malformed = [
      null,
      {},
      ["did=did:plc:alice"],
      [[]],
      [[42]],
      Array.from({ length: 257 }, () => ["x"]),
      [Array.from({ length: 257 }, () => "x")],
      [["x".repeat(65_536)]],
      [["🧪".repeat(20_000)]],
      Array.from({ length: 17 }, () => Array.from({ length: 256 }, () => "")),
    ];
    for (const answer of malformed) {
      expect(
        await resolveLexiconAuthority("app.toy.record", {
          resolveTxt: () => Promise.resolve(answer),
        }),
      ).toEqual({
        tag: "invalid",
        reason: "response",
      });
    }
  });

  it("does not query invalid NSIDs, DNS names or timeout settings", async () => {
    let calls = 0;
    const resolveTxt = () => {
      calls++;
      return Promise.resolve([[`did=${DID}`]]);
    };
    const tooLongAuthority = ["com", ...Array(4).fill("a".repeat(60)), "record"]
      .join(".");
    for (
      const nsid of ["*", "invalid", "com.example..x", tooLongAuthority, null]
    ) {
      expect(await resolveLexiconAuthority(nsid, { resolveTxt })).toEqual({
        tag: "invalid",
        reason: "nsid",
      });
    }
    for (const timeoutMs of [0, -1, 1.5, 10_001, Number.NaN]) {
      expect(
        await resolveLexiconAuthority("app.toy.record", {
          resolveTxt,
          timeoutMs,
        }),
      ).toEqual({
        tag: "invalid",
        reason: "options",
      });
    }
    for (
      const value of [{ timeoutMs: null }, { resolveTxt: null }, {
        signal: { aborted: false },
      }]
    ) {
      expect(
        await resolveLexiconAuthority(
          "app.toy.record",
          value as unknown as ResolveLexiconAuthorityOptions,
        ),
      ).toEqual({
        tag: "invalid",
        reason: "options",
      });
    }
    expect(calls).toBe(0);
  });

  it("does not start a DNS query when already aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    let calls = 0;
    const result = await resolveLexiconAuthority("app.toy.record", {
      signal: controller.signal,
      resolveTxt: () => {
        calls++;
        return Promise.resolve([[`did=${DID}`]]);
      },
    });
    expect(result).toEqual({ tag: "unavailable", reason: "aborted" });
    expect(calls).toBe(0);
  });

  it("does not start a queued lookup if aborted before the DNS call", async () => {
    const controller = new AbortController();
    let calls = 0;
    const pending = resolveLexiconAuthority("app.toy.record", {
      signal: controller.signal,
      resolveTxt: () => {
        calls++;
        return Promise.resolve([[`did=${DID}`]]);
      },
    });
    controller.abort();
    expect(await pending).toEqual({ tag: "unavailable", reason: "aborted" });
    await Promise.resolve();
    expect(calls).toBe(0);
  });

  it("ignores a late success or rejection after an in-flight abort", async () => {
    for (const reject of [false, true]) {
      const controller = new AbortController();
      let complete: (value: unknown) => void = () => {};
      let fail: (error: unknown) => void = () => {};
      let calls = 0;
      const result = resolveLexiconAuthority("app.toy.record", {
        signal: controller.signal,
        resolveTxt: () => {
          calls++;
          return new Promise((resolve, rejectPromise) => {
            complete = resolve;
            fail = rejectPromise;
          });
        },
      });
      await Promise.resolve();
      controller.abort();
      expect(await result).toEqual({ tag: "unavailable", reason: "aborted" });
      if (reject) fail(new Error("late failure"));
      else complete([[`did=${DID}`]]);
      await Promise.resolve();
      expect(calls).toBe(1);
    }
  });

  it("times out without accepting a late DNS answer", async () => {
    let complete: (value: unknown) => void = () => {};
    const result = await resolveLexiconAuthority("app.toy.record", {
      timeoutMs: 5,
      resolveTxt: () =>
        new Promise((resolve) => {
          complete = resolve;
        }),
    });
    expect(result).toEqual({ tag: "unavailable", reason: "timeout" });
    complete([[`did=${DID}`]]);
    await Promise.resolve();
  });
});
