import { authorityPdsOrigin, authoritySigningKey } from "./authority-document";
import { spaceIdentityDocumentUrl } from "./identity-url";
import {
  resolveLexiconAuthority,
  type ResolveLexiconTxt,
} from "./lexicon-authority";
import {
  type ProvenSpaceMain,
  verifyLexiconProofAtTrustedHead,
} from "./lexicon-proof";
import { fetchPublicHttps } from "./public-fetch";
import { parsePublicRepoHead, type PublicRepoHead } from "./repo-head";

const JSON_LIMIT = 64 * 1024;
const PROOF_LIMIT = 4 * 1024 * 1024;
const MAX_TIMEOUT_MS = 10_000;
const SCHEMA_COLLECTION = "com.atproto.lexicon.schema";

export type SpaceLexiconResolution =
  | {
    readonly tag: "proven";
    readonly main: ProvenSpaceMain;
    readonly definitions: "main-only" | "additional";
    readonly head: PublicRepoHead;
    readonly observedAt: number;
  }
  | {
    readonly tag: "unsupported";
    readonly recordCid: string;
    readonly head: PublicRepoHead;
    readonly observedAt: number;
  }
  | { readonly tag: "notFound" }
  | {
    readonly tag: "invalid";
    readonly reason: "input" | "identity" | "head" | "proof";
  }
  | {
    readonly tag: "unavailable";
    readonly reason:
      | "authority"
      | "network"
      | "unstable"
      | "aborted"
      | "timeout";
  };

export type SpaceLexiconResolutionOptions = {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
  /** Trusted test seams; production must use the default Cloudflare DNS and global fetch. */
  readonly resolveTxt?: ResolveLexiconTxt;
  readonly fetch?: typeof fetch;
};

type Identity = {
  readonly did: string;
  readonly signingKey: string;
  readonly pds: string;
};
type ResolutionFailure = Exclude<SpaceLexiconResolution, { tag: "proven" }>;
type Step<T> = { readonly tag: "ok"; readonly value: T } | ResolutionFailure;

/**
 * Prove the Space main against a head stably reported by the DID-advertised PDS.
 * This requires Cloudflare's strict-public global-fetch configuration and trusts
 * DNS, the DID method, and the PDS/CDN to report current data. Two matching head
 * responses do not rule out a consistently replayed older head. The result is
 * not an OAuth grant. Proven results validate only the supported Lexicon subset;
 * unsupported records do not return declarations.
 */
export async function resolveSpaceLexiconProof(
  nsid: unknown,
  options: SpaceLexiconResolutionOptions = {},
): Promise<SpaceLexiconResolution> {
  if (typeof nsid !== "string" || !options || typeof options !== "object") {
    return { tag: "invalid", reason: "input" };
  }
  const signal = options.signal;
  const timeoutMs = options.timeoutMs ?? MAX_TIMEOUT_MS;
  const lookup = options.resolveTxt;
  const fetcher = options.fetch;
  if (
    !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 ||
    timeoutMs > MAX_TIMEOUT_MS ||
    (signal !== undefined && !(signal instanceof AbortSignal)) ||
    (lookup !== undefined && typeof lookup !== "function") ||
    (fetcher !== undefined && typeof fetcher !== "function")
  ) {
    return { tag: "invalid", reason: "input" };
  }
  if (signal?.aborted) return { tag: "unavailable", reason: "aborted" };

  const controller = new AbortController();
  let stopped: "aborted" | "timeout" | undefined;
  const abort = () => {
    stopped ??= "aborted";
    controller.abort();
  };
  const timer = setTimeout(() => {
    stopped ??= "timeout";
    controller.abort();
  }, timeoutMs);
  signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) abort();
  const failure = (): ResolutionFailure | undefined =>
    stopped ? { tag: "unavailable", reason: stopped } : undefined;

  const get = async (url: string, maxBytes: number) =>
    await fetchPublicHttps(url, {
      maxBytes,
      timeoutMs,
      signal: controller.signal,
      fetch: fetcher,
    });
  const authority = async (): Promise<Step<string>> => {
    const result = await resolveLexiconAuthority(nsid, {
      signal: controller.signal,
      timeoutMs,
      resolveTxt: lookup,
    });
    const interrupted = failure();
    if (interrupted) return interrupted;
    if (result.tag === "resolved") return { tag: "ok", value: result.did };
    if (result.tag === "notFound") return result;
    if (result.tag === "invalid") return { tag: "invalid", reason: "input" };
    return { tag: "unavailable", reason: "authority" };
  };
  const identity = async (did: string): Promise<Step<Identity>> => {
    const url = spaceIdentityDocumentUrl(did);
    if (!url) return { tag: "invalid", reason: "identity" };
    const response = await get(url, JSON_LIMIT);
    const interrupted = failure();
    if (interrupted) return interrupted;
    if (response.tag !== "ok") return { tag: "unavailable", reason: "network" };
    const document = parseJson(response.bytes);
    const signingKey = authoritySigningKey(did, document);
    const pds = authorityPdsOrigin(did, document);
    return signingKey && pds
      ? { tag: "ok", value: { did, signingKey, pds } }
      : { tag: "invalid", reason: "identity" };
  };
  const head = async (identity: Identity): Promise<Step<PublicRepoHead>> => {
    const url = rpcUrl(identity.pds, "com.atproto.sync.getLatestCommit", {
      did: identity.did,
    });
    const response = await get(url, JSON_LIMIT);
    const interrupted = failure();
    if (interrupted) return interrupted;
    if (response.tag !== "ok") return { tag: "unavailable", reason: "network" };
    const value = parsePublicRepoHead(parseJson(response.bytes));
    return value ? { tag: "ok", value } : { tag: "invalid", reason: "head" };
  };

  try {
    for (let attempt = 0; attempt < 2; attempt++) {
      const firstAuthority = await authority();
      if (firstAuthority.tag !== "ok") return firstAuthority;
      const firstIdentity = await identity(firstAuthority.value);
      if (firstIdentity.tag !== "ok") return firstIdentity;
      const firstHead = await head(firstIdentity.value);
      if (firstHead.tag !== "ok") return firstHead;

      const proofUrl = rpcUrl(
        firstIdentity.value.pds,
        "com.atproto.sync.getRecord",
        {
          did: firstIdentity.value.did,
          collection: SCHEMA_COLLECTION,
          rkey: nsid,
        },
      );
      const proof = await get(proofUrl, PROOF_LIMIT);
      const interrupted = failure();
      if (interrupted) return interrupted;
      if (proof.tag !== "ok") return { tag: "unavailable", reason: "network" };
      const lastHead = await head(firstIdentity.value);
      if (lastHead.tag !== "ok") return lastHead;
      const headObservedAt = Date.now();
      if (
        firstHead.value.cid !== lastHead.value.cid ||
        firstHead.value.revision !== lastHead.value.revision
      ) continue;

      const checked = await verifyLexiconProofAtTrustedHead({
        nsid,
        publisherDid: firstIdentity.value.did,
        signingKey: firstIdentity.value.signingKey,
        currentCommitCid: firstHead.value.cid,
        proof: proof.bytes,
      });
      const stoppedAfterProof = failure();
      if (stoppedAfterProof) return stoppedAfterProof;
      const lastAuthority = await authority();
      if (lastAuthority.tag !== "ok") return lastAuthority;
      if (lastAuthority.value !== firstIdentity.value.did) continue;
      const lastIdentity = await identity(lastAuthority.value);
      if (lastIdentity.tag !== "ok") return lastIdentity;
      if (
        lastIdentity.value.signingKey !== firstIdentity.value.signingKey ||
        lastIdentity.value.pds !== firstIdentity.value.pds
      ) continue;
      if (
        checked.tag === "invalid" || checked.headCid !== firstHead.value.cid ||
        checked.revision !== firstHead.value.revision
      ) {
        if (attempt === 0) continue;
        return { tag: "invalid", reason: "proof" };
      }
      const stoppedResult = failure();
      if (stoppedResult) return stoppedResult;
      if (checked.tag === "unsupported") {
        return Object.freeze({
          tag: "unsupported",
          recordCid: checked.recordCid,
          head: Object.freeze({ ...firstHead.value }),
          observedAt: headObservedAt,
        });
      }
      return Object.freeze({
        tag: "proven",
        main: checked.main,
        definitions: checked.definitions,
        head: Object.freeze({ ...firstHead.value }),
        observedAt: headObservedAt,
      });
    }
    return failure() ?? { tag: "unavailable", reason: "unstable" };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
}

function parseJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
}

function rpcUrl(
  origin: string,
  method: string,
  parameters: Record<string, string>,
): string {
  const url = new URL(`/xrpc/${method}`, origin);
  url.search = new URLSearchParams(parameters).toString();
  return url.href;
}
