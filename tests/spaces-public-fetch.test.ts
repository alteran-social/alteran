import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import {
  fetchPublicHttps,
  type PublicFetchOptions,
} from "../src/lib/spaces/public-fetch";

const URL = "https://publisher.example.com/proof";

function deferred<T>() {
  return Promise.withResolvers<T>();
}

function responseWithChunks(
  chunks: Uint8Array[],
  onCancel: () => void = () => {},
): Response {
  let index = 0;
  return new Response(
    new ReadableStream<Uint8Array>({
      pull(controller) {
        if (index === chunks.length) controller.close();
        else controller.enqueue(chunks[index++]);
      },
      cancel: onCancel,
    }, { highWaterMark: 0 }),
  );
}

function withResponse(response: Response): typeof fetch {
  return () => Promise.resolve(response);
}

describe("public HTTPS transport", () => {
  it("normalizes the URL and creates a credential-free request with fixed headers", async () => {
    let receivedUrl = "";
    let received: RequestInit | undefined;
    const options = {
      maxBytes: 20,
      headers: { authorization: "secret", cookie: "secret" },
      fetch(input: string | URL | Request, init?: RequestInit) {
        receivedUrl = String(input);
        received = init;
        return Promise.resolve(responseWithChunks([new Uint8Array([1, 2])]));
      },
    };
    const pending = fetchPublicHttps(
      "HTTPS://Publisher.Example.COM:443/a/../proof?x=1",
      options,
    );
    options.maxBytes = 1;
    options.headers.authorization = "changed";
    const result = await pending;
    expect(result).toEqual({
      tag: "ok",
      bytes: new Uint8Array([1, 2]),
      contentType: null,
    });
    expect(receivedUrl).toBe("https://publisher.example.com/proof?x=1");
    expect(received?.method).toBe("GET");
    expect(received?.redirect).toBe("manual");
    expect(received?.credentials).toBe("omit");
    expect(received?.cache).toBe("no-store");
    const headers = new Headers(received?.headers);
    expect([...headers.keys()].sort()).toEqual(["accept", "cache-control"]);
    expect(headers.get("accept")).toBe(
      "application/json, application/did+ld+json, application/vnd.ipld.car",
    );
    expect(headers.get("cache-control")).toBe("no-cache");
    expect(headers.has("authorization")).toBe(false);
    expect(headers.has("cookie")).toBe(false);
  });

  it("allows only Cloudflare-proxied HTTPS ports, retaining explicit supported ports", async () => {
    for (const port of ["2053", "2083", "2087", "2096", "8443"]) {
      let requested = "";
      const result = await fetchPublicHttps(
        `https://publisher.example.com:${port}/`,
        {
          maxBytes: 1,
          fetch: (url) => {
            requested = String(url);
            return Promise.resolve(new Response());
          },
        },
      );
      expect(result.tag).toBe("ok");
      expect(requested).toBe(`https://publisher.example.com:${port}/`);
    }
  });

  it("rejects ambiguous, local and IP-literal targets before any network request", async () => {
    let calls = 0;
    const fetch = () => {
      calls++;
      return Promise.resolve(new Response());
    };
    for (
      const input of [
        "http://publisher.example.com/",
        "https:publisher.example.com",
        "https://@example.com/",
        "https://user:pass@example.com/",
        "https://example.com/#",
        "https://example.com:444/",
        "https://example.com\\@evil.com/",
        "https://exam ple.com/",
        "https://example.com./",
        "https://foo.localhost/",
        "https://foo.local/",
        "https://foo.internal/",
        "https://test.home.arpa/",
        "https://127.1/",
        "https://[::1]/",
        "https://bad_host.example.com/",
        "https://example.com/" + "a".repeat(4097),
        null,
        new Request("https://example.com/"),
      ]
    ) {
      expect(await fetchPublicHttps(input, { maxBytes: 1, fetch })).toEqual({
        tag: "invalid",
        reason: "url",
      });
    }
    expect(calls).toBe(0);
  });

  it("rejects invalid options before invoking fetch", async () => {
    let calls = 0;
    const fetch = () => {
      calls++;
      return Promise.resolve(new Response());
    };
    for (
      const options of [
        { maxBytes: 0 },
        { maxBytes: 4 * 1024 * 1024 + 1 },
        { maxBytes: 1.5 },
        { maxBytes: NaN },
        { maxBytes: 1, timeoutMs: 0 },
        { maxBytes: 1, timeoutMs: 10_001 },
        { maxBytes: 1, timeoutMs: null },
        { maxBytes: 1, signal: { aborted: false } },
        { maxBytes: 1, fetch: null },
      ]
    ) {
      const merged = { fetch, ...options } as unknown as PublicFetchOptions;
      expect(await fetchPublicHttps(URL, merged)).toEqual({
        tag: "invalid",
        reason: "options",
      });
    }
    expect(calls).toBe(0);
  });

  it("rejects every redirect and unsuccessful status while cancelling the body", async () => {
    for (const status of [301, 302, 303, 304, 307, 308, 201, 400, 500]) {
      let cancelled = false;
      const body = new ReadableStream<Uint8Array>({
        cancel: () => {
          cancelled = true;
        },
      });
      const response = new Response(status === 304 ? null : body, { status });
      const expected = status >= 300 && status < 400
        ? { tag: "rejected", reason: "redirect" }
        : { tag: "rejected", reason: "status", status };
      expect(
        await fetchPublicHttps(URL, {
          maxBytes: 100,
          fetch: withResponse(response),
        }),
      ).toEqual(expected);
      expect(cancelled).toBe(status !== 304);
    }
  });

  it("accepts bounded streamed content independently of a shorter length hint", async () => {
    const response = new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array([1, 2]));
          controller.enqueue(new Uint8Array([3, 4]));
          controller.close();
        },
      }),
      {
        headers: { "content-length": "2", "content-type": "application/json" },
      },
    );
    expect(
      await fetchPublicHttps(URL, {
        maxBytes: 4,
        fetch: withResponse(response),
      }),
    ).toEqual({
      tag: "ok",
      bytes: new Uint8Array([1, 2, 3, 4]),
      contentType: "application/json",
    });
    expect(
      await fetchPublicHttps(URL, {
        maxBytes: 1,
        fetch: withResponse(new Response()),
      }),
    ).toEqual({
      tag: "ok",
      bytes: new Uint8Array(),
      contentType: null,
    });
  });

  it("uses bounded BYOB reads for byte streams", async () => {
    for (const maxBytes of [3, 4]) {
      const body = new ReadableStream({
        type: "bytes",
        start(controller) {
          controller.enqueue(new Uint8Array([1, 2, 3, 4]));
          controller.close();
        },
      });
      const response = new Response(body);
      const reader = body.getReader({ mode: "byob" });
      let firstMinimum = 0;
      Object.defineProperty(reader, "readAtLeast", {
        value(minimum: number, view: Uint8Array) {
          if (!firstMinimum) firstMinimum = minimum;
          return reader.read(view);
        },
      });
      Object.defineProperty(body, "getReader", { value: () => reader });
      const result = await fetchPublicHttps(URL, {
        maxBytes,
        fetch: withResponse(response),
      });
      expect(result).toEqual(
        maxBytes === 3 ? { tag: "rejected", reason: "tooLarge" } : {
          tag: "ok",
          bytes: new Uint8Array([1, 2, 3, 4]),
          contentType: null,
        },
      );
      expect(firstMinimum).toBe(maxBytes + 1);
    }
  });

  it("rejects malformed or oversized length hints and cancels before reading", async () => {
    for (
      const value of [
        "-1",
        "1.0",
        "1, 2",
        "nope",
        "9007199254740992",
        "12345678901234567",
        "11",
      ]
    ) {
      let cancelled = false;
      const response = new Response(
        new ReadableStream({
          cancel: () => {
            cancelled = true;
          },
        }),
        {
          headers: { "content-length": value },
        },
      );
      const reason = value === "11" ? "tooLarge" : "contentLength";
      expect(
        await fetchPublicHttps(URL, {
          maxBytes: 10,
          fetch: withResponse(response),
        }),
      ).toEqual({
        tag: "rejected",
        reason,
      });
      expect(cancelled).toBe(true);
    }
  });

  it("caps actual bytes before copying and cancels an oversized first or later chunk", async () => {
    for (
      const chunks of [
        [new Uint8Array(11)],
        [new Uint8Array(8), new Uint8Array(3)],
      ]
    ) {
      let cancelled = false;
      const response = responseWithChunks(chunks, () => {
        cancelled = true;
      });
      expect(
        await fetchPublicHttps(URL, {
          maxBytes: 10,
          fetch: withResponse(response),
        }),
      ).toEqual({
        tag: "rejected",
        reason: "tooLarge",
      });
      expect(cancelled).toBe(true);
    }
  });

  it("bounds even empty chunks and cancels a stream that exceeds the count", async () => {
    let cancelled = false;
    const response = responseWithChunks(
      Array.from({ length: 4097 }, () => new Uint8Array()),
      () => {
        cancelled = true;
      },
    );
    expect(
      await fetchPublicHttps(URL, {
        maxBytes: 1,
        fetch: withResponse(response),
      }),
    ).toEqual({
      tag: "rejected",
      reason: "tooManyChunks",
    });
    expect(cancelled).toBe(true);
  });

  it("copies each source chunk before awaiting another chunk", async () => {
    const source = new Uint8Array([1, 2]);
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(source);
      },
      pull(controller) {
        source[0] = 9;
        controller.close();
      },
    }, { highWaterMark: 0 });
    expect(
      await fetchPublicHttps(URL, {
        maxBytes: 2,
        fetch: withResponse(new Response(body)),
      }),
    ).toEqual({
      tag: "ok",
      bytes: new Uint8Array([1, 2]),
      contentType: null,
    });
  });

  it("never starts a fetch if the caller aborts before it begins", async () => {
    for (const alreadyAborted of [true, false]) {
      const controller = new AbortController();
      let calls = 0;
      if (alreadyAborted) controller.abort();
      const pending = fetchPublicHttps(URL, {
        maxBytes: 1,
        signal: controller.signal,
        fetch: () => {
          calls++;
          return Promise.resolve(new Response());
        },
      });
      controller.abort();
      expect(await pending).toEqual({ tag: "unavailable", reason: "aborted" });
      expect(calls).toBe(0);
    }
  });

  it("cancels a late response after an in-flight abort or timeout", async () => {
    for (const reason of ["aborted", "timeout"]) {
      const controller = new AbortController();
      const response = deferred<Response>();
      let signal: AbortSignal | undefined;
      let cancelled = false;
      const pending = fetchPublicHttps(URL, {
        maxBytes: 1,
        timeoutMs: 5,
        signal: controller.signal,
        fetch: (_url, init) => {
          signal = init?.signal ?? undefined;
          return response.promise;
        },
      });
      if (reason === "aborted") {
        await Promise.resolve();
        controller.abort();
      }
      expect(await pending).toEqual({ tag: "unavailable", reason });
      expect(signal?.aborted).toBe(true);
      response.resolve(responseWithChunks([new Uint8Array([1])], () => {
        cancelled = true;
      }));
      for (let index = 0; index < 8; index++) await Promise.resolve();
      expect(cancelled).toBe(true);
    }
  });

  it("aborts and cancels a pending body read after headers", async () => {
    const controller = new AbortController();
    const started = deferred<void>();
    let cancelled = false;
    let signal: AbortSignal | undefined;
    const response = new Response(
      new ReadableStream({
        type: "bytes",
        pull() {
          started.resolve();
        },
        cancel() {
          cancelled = true;
        },
      }, { highWaterMark: 0 }),
    );
    const pending = fetchPublicHttps(URL, {
      maxBytes: 1,
      signal: controller.signal,
      fetch: (_url, init) => {
        signal = init?.signal ?? undefined;
        return Promise.resolve(response);
      },
    });
    await started.promise;
    controller.abort();
    expect(await pending).toEqual({ tag: "unavailable", reason: "aborted" });
    expect(signal?.aborted).toBe(true);
    expect(cancelled).toBe(true);
  });

  it("times out during a stalled body and does not wait for stalled cancellation", async () => {
    let cancelled = false;
    const cancellation = deferred<void>();
    const response = new Response(
      new ReadableStream<Uint8Array>({
        pull() {},
        cancel() {
          cancelled = true;
          return cancellation.promise;
        },
      }, { highWaterMark: 0 }),
    );
    expect(
      await fetchPublicHttps(URL, {
        maxBytes: 1,
        timeoutMs: 5,
        fetch: withResponse(response),
      }),
    ).toEqual({
      tag: "unavailable",
      reason: "timeout",
    });
    expect(cancelled).toBe(true);
    cancellation.resolve();

    const busy = new ReadableStream<Uint8Array>({
      pull(controller) {
        const until = performance.now() + 20;
        while (performance.now() < until) {}
        controller.enqueue(new Uint8Array([1]));
        controller.close();
      },
    }, { highWaterMark: 0 });
    expect(
      await fetchPublicHttps(URL, {
        maxBytes: 1,
        timeoutMs: 5,
        fetch: withResponse(new Response(busy)),
      }),
    )
      .toEqual({ tag: "unavailable", reason: "timeout" });
  });

  it("classifies fetch and body failures without leaking a rejection", async () => {
    const network = await fetchPublicHttps(URL, {
      maxBytes: 1,
      fetch: () => {
        throw new Error("offline");
      },
    });
    expect(network).toEqual({ tag: "unavailable", reason: "network" });
    const response = new Response(
      new ReadableStream<Uint8Array>({
        pull(controller) {
          controller.error(new Error("broken body"));
        },
      }, { highWaterMark: 0 }),
    );
    expect(
      await fetchPublicHttps(URL, {
        maxBytes: 1,
        fetch: withResponse(response),
      }),
    ).toEqual({
      tag: "unavailable",
      reason: "body",
    });
  });
});
