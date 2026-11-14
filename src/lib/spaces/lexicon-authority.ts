import { resolveTxt } from "node:dns/promises";
import { isValidDid, NSID } from "@atproto/syntax-spaces";

const DEFAULT_TIMEOUT_MS = 3_000;
const MAX_TIMEOUT_MS = 10_000;
const MAX_DNS_NAME_LENGTH = 253;
const MAX_RECORDS = 256;
const MAX_CHUNKS_PER_RECORD = 256;
const MAX_TOTAL_CHUNKS = 4_096;
const MAX_TOTAL_BYTES = 65_535;

export type LexiconAuthorityResult =
  | { readonly tag: "resolved"; readonly did: string }
  | { readonly tag: "notFound" }
  | {
    readonly tag: "invalid";
    readonly reason: "nsid" | "options" | "response" | "ambiguous" | "did";
  }
  | {
    readonly tag: "unavailable";
    readonly reason: "dns" | "timeout" | "aborted";
  };

/** Trusted internal DNS dependency, returning one array of chunks per TXT record. */
export type ResolveLexiconTxt = (name: string) => Promise<unknown>;

export type ResolveLexiconAuthorityOptions = {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
  readonly resolveTxt?: ResolveLexiconTxt;
};

/**
 * Resolve only the Lexicon namespace's DNS TXT binding. This does not validate
 * a DID document, its signing key, a PDS, or a repository head. The module-level
 * Node resolveTxt API accepts no AbortSignal. Abort or timeout stops waiting
 * and ignores any later answer, but the DNS subrequest may continue.
 */
export async function resolveLexiconAuthority(
  nsid: unknown,
  options: ResolveLexiconAuthorityOptions = {},
): Promise<LexiconAuthorityResult> {
  if (typeof nsid !== "string") return { tag: "invalid", reason: "nsid" };
  let name: string;
  try {
    name = `_lexicon.${NSID.parse(nsid).authority}`;
  } catch {
    return { tag: "invalid", reason: "nsid" };
  }
  if (name.length > MAX_DNS_NAME_LENGTH) {
    return { tag: "invalid", reason: "nsid" };
  }
  if (
    typeof options !== "object" || options === null || Array.isArray(options)
  ) {
    return { tag: "invalid", reason: "options" };
  }
  const timeoutMs = options.timeoutMs === undefined
    ? DEFAULT_TIMEOUT_MS
    : options.timeoutMs;
  const lookup = options.resolveTxt === undefined
    ? resolveTxt
    : options.resolveTxt;
  const signal = options.signal;
  if (
    !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 ||
    timeoutMs > MAX_TIMEOUT_MS ||
    typeof lookup !== "function" ||
    (signal !== undefined && !isAbortSignal(signal))
  ) {
    return { tag: "invalid", reason: "options" };
  }
  if (signal?.aborted) return { tag: "unavailable", reason: "aborted" };

  return await new Promise<LexiconAuthorityResult>((resolve) => {
    let settled = false;
    const finish = (result: LexiconAuthorityResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      resolve(result);
    };
    const onAbort = () => finish({ tag: "unavailable", reason: "aborted" });
    const timer = setTimeout(
      () => finish({ tag: "unavailable", reason: "timeout" }),
      timeoutMs,
    );
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) {
      onAbort();
      return;
    }
    Promise.resolve().then(() => {
      if (settled) return;
      return lookup(name);
    }).then((records) => {
      if (settled) return;
      try {
        finish(parseTxt(records));
      } catch {
        finish({ tag: "invalid", reason: "response" });
      }
    }, (error: unknown) => {
      if (settled) return;
      finish(
        isAbsentDnsError(error)
          ? { tag: "notFound" }
          : { tag: "unavailable", reason: "dns" },
      );
    });
  });
}

function parseTxt(value: unknown): LexiconAuthorityResult {
  if (!Array.isArray(value) || value.length > MAX_RECORDS) {
    return { tag: "invalid", reason: "response" };
  }
  let chunks = 0;
  let bytes = 0;
  let didLine: string | undefined;
  const encoder = new TextEncoder();
  for (const record of value) {
    if (
      !Array.isArray(record) || record.length === 0 ||
      record.length > MAX_CHUNKS_PER_RECORD
    ) {
      return { tag: "invalid", reason: "response" };
    }
    const parts: string[] = [];
    for (const chunk of record) {
      if (
        typeof chunk !== "string" || chunk.length > MAX_TOTAL_BYTES ||
        ++chunks > MAX_TOTAL_CHUNKS
      ) {
        return { tag: "invalid", reason: "response" };
      }
      bytes += encoder.encode(chunk).byteLength;
      if (bytes > MAX_TOTAL_BYTES) {
        return { tag: "invalid", reason: "response" };
      }
      parts.push(chunk);
    }
    const line = parts.join("");
    if (!line.startsWith("did=")) continue;
    if (didLine !== undefined) return { tag: "invalid", reason: "ambiguous" };
    didLine = line.slice(4);
  }
  if (didLine === undefined) return { tag: "notFound" };
  if (!isValidDid(didLine)) return { tag: "invalid", reason: "did" };
  return { tag: "resolved", did: didLine };
}

function isAbsentDnsError(error: unknown): boolean {
  try {
    if (typeof error !== "object" || error === null || !("code" in error)) {
      return false;
    }
    return error.code === "ENOTFOUND" || error.code === "ENODATA";
  } catch {
    return false;
  }
}

function isAbortSignal(value: unknown): value is AbortSignal {
  return value instanceof AbortSignal;
}
