const MAX_BYTES = 4 * 1024 * 1024;
const MAX_CHUNKS = 4096;
const MAX_READ_BYTES = 64 * 1024;
const MIN_READ_BYTES = 4 * 1024;
const MAX_TIMEOUT_MS = 10_000;
const DEFAULT_TIMEOUT_MS = 3000;

export type PublicFetchOptions = {
  readonly maxBytes: number;
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
  /** Trusted test seam; production callers must use Cloudflare global fetch. */
  readonly fetch?: typeof fetch;
  /** Trusted tests only; production must require byte-stream BYOB reads. */
  readonly allowTestStreams?: boolean;
};

export type PublicFetchResult =
  | {
    readonly tag: "ok";
    readonly bytes: Uint8Array;
    readonly contentType: string | null;
  }
  | { readonly tag: "invalid"; readonly reason: "url" | "options" }
  | {
    readonly tag: "rejected";
    readonly reason: "status";
    readonly status: number;
  }
  | {
    readonly tag: "rejected";
    readonly reason:
      | "redirect"
      | "contentLength"
      | "tooLarge"
      | "tooManyChunks"
      | "response";
  }
  | {
    readonly tag: "unavailable";
    readonly reason: "network" | "body" | "aborted" | "timeout";
  };

type StopReason = "aborted" | "timeout";
type Outcome<T> =
  | { readonly tag: "value"; readonly value: T }
  | { readonly tag: "error" }
  | { readonly tag: "stopped"; readonly reason: StopReason };

type CloudflareByteReader = ReadableStreamBYOBReader & {
  readAtLeast?: (
    minimum: number,
    view: Uint8Array,
  ) => Promise<ReadableStreamReadResult<Uint8Array>>;
};

function publicUrl(input: unknown): string | null {
  if (
    typeof input !== "string" || input.length > 4096 ||
    !/^https:\/\//i.test(input) || /[\x00-\x20\x7f\\#]/.test(input)
  ) return null;
  const authority = input.slice(input.indexOf("//") + 2).split(/[/?]/, 1)[0];
  if (authority.includes("@")) return null;

  try {
    const url = new URL(input);
    const hostname = url.hostname;
    const labels = hostname.split(".");
    if (
      url.protocol !== "https:" || url.username || url.password ||
      !["", "2053", "2083", "2087", "2096", "8443"].includes(url.port) ||
      hostname.length > 253 || labels.length < 2 ||
      labels.some((label) =>
        !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
      ) ||
      /^\d+(?:\.\d+){3}$/.test(hostname) ||
      labels.at(-1) === "localhost" || labels.at(-1) === "local" ||
      labels.at(-1) === "internal" || hostname === "home.arpa" ||
      hostname.endsWith(".home.arpa")
    ) return null;
    return url.href;
  } catch {
    return null;
  }
}

function cancelBody(body: ReadableStream<Uint8Array> | null): void {
  if (!body) return;
  try {
    // A broken or stalled cancellation must not extend the caller's deadline.
    void body.cancel().catch(() => {});
  } catch {
    // Cancellation is best effort after the request has already failed.
  }
}

function cancelReader(
  reader: ReadableStreamDefaultReader<Uint8Array> | ReadableStreamBYOBReader,
): void {
  try {
    // The pending read may itself be stalled; aborting it must remain bounded.
    void reader.cancel().catch(() => {});
  } catch {
    // Cancellation is best effort after the request has already failed.
  }
}

/**
 * Unwired transport for untrusted public HTTPS endpoints. Production use requires
 * Cloudflare global fetch with global_fetch_strictly_public enabled and the
 * platform's public-egress restrictions. This code cannot verify either setting,
 * bind DNS to the connected address, or establish that an endpoint is trustworthy.
 * Only HTTPS ports supported by Cloudflare's proxy are allowed because other
 * ports can be silently ignored for proxied destinations. The current project
 * compatibility date enables allow_custom_ports; it must remain enabled.
 * Native responses must support BYOB so the application bounds each read;
 * Cloudflare's internal network and decompression buffering is outside this limit.
 * On runtimes without readAtLeast, 4096 small reads can reject otherwise valid
 * responses even when their total size is below the configured limit.
 */
export async function fetchPublicHttps(
  input: unknown,
  options: PublicFetchOptions,
): Promise<PublicFetchResult> {
  const url = publicUrl(input);
  if (url === null) return { tag: "invalid", reason: "url" };
  if (!options || typeof options !== "object") {
    return { tag: "invalid", reason: "options" };
  }
  // Capture caller-controlled values before yielding to any network operation.
  const maxBytes = options.maxBytes;
  const timeoutMs = options.timeoutMs === undefined
    ? DEFAULT_TIMEOUT_MS
    : options.timeoutMs;
  const externalSignal = options.signal;
  const injectedFetch = options.fetch;
  const allowTestStreams = options.allowTestStreams;
  const fetchPublic = injectedFetch === undefined
    ? globalThis.fetch
    : injectedFetch;
  if (
    !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_BYTES ||
    !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 ||
    timeoutMs > MAX_TIMEOUT_MS ||
    (externalSignal !== undefined &&
      !(externalSignal instanceof AbortSignal)) ||
    typeof fetchPublic !== "function" ||
    (allowTestStreams !== undefined && typeof allowTestStreams !== "boolean")
  ) return { tag: "invalid", reason: "options" };
  if (externalSignal?.aborted) return { tag: "unavailable", reason: "aborted" };

  const controller = new AbortController();
  let stopReason: StopReason | null = null;
  let stop: (reason: StopReason) => void = () => {};
  const stopped = new Promise<StopReason>((resolve) => {
    stop = (reason) => {
      if (stopReason !== null) return;
      stopReason = reason;
      controller.abort();
      resolve(reason);
    };
  });
  const deadline = performance.now() + timeoutMs;
  const checkDeadline = (): StopReason | null => {
    if (stopReason === null && performance.now() >= deadline) stop("timeout");
    return stopReason;
  };
  const onAbort = () => stop("aborted");
  externalSignal?.addEventListener("abort", onAbort, { once: true });
  if (externalSignal?.aborted) stop("aborted");
  const timer = setTimeout(() => stop("timeout"), timeoutMs);
  let body: ReadableStream<Uint8Array> | null = null;
  let reader:
    | ReadableStreamDefaultReader<Uint8Array>
    | ReadableStreamBYOBReader
    | null = null;
  let completed = false;

  const wait = <T>(promise: Promise<T>): Promise<Outcome<T>> =>
    Promise.race([
      promise.then<Outcome<T>, Outcome<T>>(
        (value) => ({ tag: "value", value }),
        () => ({ tag: "error" }),
      ),
      stopped.then<Outcome<T>>((reason) => ({ tag: "stopped", reason })),
    ]);

  try {
    const pendingFetch = Promise.resolve().then(() => {
      if (stopReason !== null) return null;
      return fetchPublic(url, {
        method: "GET",
        redirect: "manual",
        credentials: "omit",
        cache: "no-store",
        headers: {
          accept:
            "application/json, application/did+json, application/did+ld+json, application/vnd.ipld.car",
          "cache-control": "no-cache",
        },
        signal: controller.signal,
      });
    });
    const fetched = await wait(pendingFetch);
    const fetchStop = checkDeadline();
    if (fetched.tag === "stopped" || fetchStop !== null) {
      // A fetch implementation can ignore its signal and deliver a late body.
      void pendingFetch.then(
        (response) => cancelBody(response?.body ?? null),
        () => {},
      );
      return { tag: "unavailable", reason: fetchStop ?? "aborted" };
    }
    if (fetched.tag === "error" || fetched.value === null) {
      return { tag: "unavailable", reason: "network" };
    }
    const response = fetched.value;
    body = response.body;
    if (
      response.type === "opaqueredirect" || response.redirected ||
      (response.status >= 300 && response.status < 400)
    ) return { tag: "rejected", reason: "redirect" };
    if (response.status !== 200) {
      return { tag: "rejected", reason: "status", status: response.status };
    }
    const length = response.headers.get("content-length");
    if (length !== null) {
      if (!/^\d{1,16}$/.test(length) || !Number.isSafeInteger(Number(length))) {
        return { tag: "rejected", reason: "contentLength" };
      }
      if (Number(length) > maxBytes) {
        return { tag: "rejected", reason: "tooLarge" };
      }
    }
    const contentType = response.headers.get("content-type");
    if (contentType !== null && contentType.length > 512) {
      return { tag: "rejected", reason: "response" };
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    let count = 0;
    if (body !== null) {
      let readChunk: () => Promise<ReadableStreamReadResult<Uint8Array>>;
      try {
        const byteReader: CloudflareByteReader = body.getReader({
          mode: "byob",
        });
        reader = byteReader;
        readChunk = () => {
          const size = Math.min(MAX_READ_BYTES, maxBytes - total + 1);
          const buffer = new Uint8Array(size);
          return byteReader.readAtLeast === undefined
            ? byteReader.read(buffer)
            : byteReader.readAtLeast(Math.min(MIN_READ_BYTES, size), buffer);
        };
      } catch {
        // A trusted test double may supply a non-byte stream; native fetch may not.
        if (!(allowTestStreams ?? injectedFetch !== undefined)) {
          return { tag: "rejected", reason: "response" };
        }
        const defaultReader = body.getReader();
        reader = defaultReader;
        readChunk = () => defaultReader.read();
      }
      while (true) {
        const read = await wait(Promise.resolve().then(readChunk));
        const readStop = checkDeadline();
        if (read.tag === "stopped" || readStop !== null) {
          return { tag: "unavailable", reason: readStop ?? "aborted" };
        }
        if (read.tag === "error") {
          return { tag: "unavailable", reason: "body" };
        }
        if (read.value.done) {
          if (read.value.value?.byteLength) {
            return { tag: "rejected", reason: "response" };
          }
          break;
        }
        if (!(read.value.value instanceof Uint8Array)) {
          return { tag: "rejected", reason: "response" };
        }
        count++;
        if (count > MAX_CHUNKS) {
          return { tag: "rejected", reason: "tooManyChunks" };
        }
        total += read.value.value.byteLength;
        if (total > maxBytes) return { tag: "rejected", reason: "tooLarge" };
        chunks.push(Uint8Array.from(read.value.value));
      }
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    const finalStop = checkDeadline();
    if (finalStop !== null) return { tag: "unavailable", reason: finalStop };
    completed = true;
    return { tag: "ok", bytes, contentType };
  } catch {
    return { tag: "unavailable", reason: "body" };
  } finally {
    clearTimeout(timer);
    externalSignal?.removeEventListener("abort", onAbort);
    if (!completed) {
      controller.abort();
      if (reader !== null) cancelReader(reader);
      else cancelBody(body);
    } else {
      reader?.releaseLock();
    }
  }
}
