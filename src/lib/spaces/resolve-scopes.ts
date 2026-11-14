import { resolveTxt } from "node:dns/promises";
import { SPACE_LEXICON_LIMITS } from "./lexicon-limits";
import { type ResolveLexiconTxt } from "./lexicon-authority";
import {
  resolveSpaceLexiconProof,
  type SpaceLexiconResolution,
  type SpaceLexiconResolutionOptions,
} from "./lexicon-resolution";
import {
  type IssuedSpacePermission,
  materializeSpacePermission,
  parseSpacePermission,
  type SpacePermission,
} from "./oauth-scopes";
import {
  copyPlainArray,
  copyPlainRecord,
  copyPlainRecordWithExtensions,
} from "./plain-values";
import { isSpaceDid } from "./space-did";
import { isLexiconUri } from "./lexicon-uri";
import {
  copySpaceDeclarationEvidence,
  type SpaceDeclarationEvidence,
} from "./declaration-evidence";

export const MAX_SPACE_DECLARATIONS_PER_REQUEST =
  SPACE_LEXICON_LIMITS.declarationsPerRequest;
const MAX_SCOPES = 128;
const MAX_SCOPE_BYTES = 64 * 1024;
const MAX_TIMEOUT_MS = 10_000;
const MAX_OBSERVATION_AGE_MS = 30_000;

export type ResolvedSpaceScope = {
  readonly requestedScope: string;
  readonly permission: IssuedSpacePermission;
};

export type ResolveSpaceScopesResult =
  | {
    readonly tag: "resolved";
    readonly subject: string;
    readonly clientId: string;
    readonly grants: readonly ResolvedSpaceScope[];
    readonly declarations: readonly SpaceDeclarationEvidence[];
  }
  | {
    readonly tag:
      | "invalid"
      | "limit"
      | "unsupported"
      | "unavailable"
      | "notFound";
  };

type SpaceScopeRequest = {
  readonly subject: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
};

export type ResolveSpaceScopesOptions = {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
  /** Trusted test seams; production uses Cloudflare global fetch and DNS. */
  readonly fetch?: typeof fetch;
  readonly resolveTxt?: ResolveLexiconTxt;
  readonly resolve?: (
    type: string,
    options: SpaceLexiconResolutionOptions,
  ) => Promise<SpaceLexiconResolution>;
};

/**
 * Resolve declaration defaults after authenticating the subject and PAR.
 * A fixed preflight cap reserves both attempts for each type, including every
 * DNS and HTTP call and each resolver's bounded proof/semantic work. This does
 * not establish PDS-head freshness or global concurrency and CPU limits.
 */
export async function resolveSpaceScopes(
  input: SpaceScopeRequest,
  options: ResolveSpaceScopesOptions = {},
): Promise<ResolveSpaceScopesResult> {
  const request = copyPlainRecord(input, ["subject", "clientId", "scopes"]);
  const source = request && copyPlainArray(request.scopes, MAX_SCOPES);
  if (
    !request || !isSpaceDid(request.subject) ||
    typeof request.clientId !== "string" || request.clientId.length > 2048 ||
    !isLexiconUri(request.clientId) || !source
  ) return { tag: "invalid" };
  const captured: Array<
    { readonly requestedScope: string; readonly permission: SpacePermission }
  > = [];
  const types = new Set<string>();
  const seen = new Set<string>();
  let bytes = 0;
  for (const scope of source) {
    if (
      typeof scope !== "string" || scope.length > 8192 ||
      (bytes += scope.length) > MAX_SCOPE_BYTES
    ) {
      return { tag: "invalid" };
    }
    if (seen.has(scope)) return { tag: "invalid" };
    seen.add(scope);
    const permission = parseSpacePermission(scope);
    if (!permission) return { tag: "invalid" };
    captured.push({ requestedScope: scope, permission });
    if (
      permission.collections.tag === "declaration" &&
      permission.spaceType !== "*"
    ) {
      types.add(permission.spaceType);
    }
  }
  if (types.size > MAX_SPACE_DECLARATIONS_PER_REQUEST) return { tag: "limit" };

  const configuration = copyPlainRecordWithExtensions(options, 5);
  if (
    !configuration ||
    Object.keys(configuration).some((key) =>
      !["signal", "timeoutMs", "fetch", "resolveTxt", "resolve"].includes(key)
    )
  ) return { tag: "invalid" };
  const timeoutMs = configuration.timeoutMs ?? MAX_TIMEOUT_MS;
  const signal = configuration.signal;
  const fetcher = configuration.fetch ?? globalThis.fetch;
  const lookup = configuration.resolveTxt ?? resolveTxt;
  const resolve = configuration.resolve ?? resolveSpaceLexiconProof;
  if (
    typeof timeoutMs !== "number" || !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS ||
    (signal !== undefined && !isAbortSignal(signal)) ||
    typeof fetcher !== "function" || typeof lookup !== "function" ||
    typeof resolve !== "function"
  ) return { tag: "invalid" };
  if (signal?.aborted) return { tag: "unavailable" };

  const count = {
    dns: 0,
    http: 0,
    exhausted: false,
    maxDns: types.size * SPACE_LEXICON_LIMITS.attempts *
      SPACE_LEXICON_LIMITS.dnsCallsPerAttempt,
    maxHttp: types.size * SPACE_LEXICON_LIMITS.attempts *
      SPACE_LEXICON_LIMITS.httpCallsPerAttempt,
  };
  const boundedLookup: ResolveLexiconTxt = (name) => {
    if (controller.signal.aborted || ++count.dns > count.maxDns) {
      if (!controller.signal.aborted) count.exhausted = true;
      return Promise.reject(new Error("DNS request limit exceeded"));
    }
    return lookup(name);
  };
  const boundedFetch: typeof fetch = (resource, init) => {
    if (controller.signal.aborted || ++count.http > count.maxHttp) {
      if (!controller.signal.aborted) count.exhausted = true;
      return Promise.reject(new Error("HTTP request limit exceeded"));
    }
    return fetcher(resource, init);
  };
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  signal?.addEventListener("abort", onAbort, { once: true });
  if (signal?.aborted) controller.abort();
  const deadline = performance.now() + timeoutMs;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const stopped = new Promise<null>((done) =>
    controller.signal.addEventListener("abort", () => done(null), {
      once: true,
    })
  );
  const declarations = new Map<string, SpaceDeclarationEvidence>();
  try {
    for (const type of types) {
      const remaining = Math.floor(deadline - performance.now());
      if (controller.signal.aborted || remaining < 1) {
        return { tag: "unavailable" };
      }
      const pending = Promise.resolve().then(() => {
        if (controller.signal.aborted) return null;
        return resolve(type, {
          signal: controller.signal,
          timeoutMs: Math.min(MAX_TIMEOUT_MS, remaining),
          resolveTxt: boundedLookup,
          fetch: boundedFetch,
          allowTestStreams: configuration.fetch !== undefined,
        });
      }).catch(() => null);
      const result = await Promise.race([pending, stopped]);
      if (
        controller.signal.aborted || performance.now() >= deadline || !result
      ) return { tag: "unavailable" };
      if (count.exhausted) return { tag: "limit" };
      const capturedResult = copyPlainRecordWithExtensions(result, 5);
      if (!capturedResult) return { tag: "invalid" };
      if (capturedResult.tag !== "proven") {
        if (
          capturedResult.tag === "notFound" ||
          capturedResult.tag === "unsupported"
        ) {
          return { tag: capturedResult.tag };
        }
        return {
          tag: capturedResult.tag === "invalid" ? "invalid" : "unavailable",
        };
      }
      const declaration = copyDeclaration(capturedResult, type);
      if (!declaration) return { tag: "invalid" };
      declarations.set(type, declaration);
    }

    const grants: ResolvedSpaceScope[] = [];
    for (const item of captured) {
      const declaration = declarations.get(item.permission.spaceType);
      const issued = materializeSpacePermission(
        item.permission,
        request.subject,
        declaration &&
          {
            spaceType: declaration.spaceType,
            collections: declaration.collections,
          },
      );
      if (!issued) return { tag: "invalid" };
      Object.freeze(issued.collections.values);
      Object.freeze(issued.collections);
      Object.freeze(issued.actions);
      Object.freeze(issued.manage);
      Object.freeze(issued);
      grants.push(
        Object.freeze({
          requestedScope: item.requestedScope,
          permission: issued,
        }),
      );
    }
    if (controller.signal.aborted || performance.now() >= deadline) {
      return { tag: "unavailable" };
    }
    return Object.freeze({
      tag: "resolved",
      subject: request.subject,
      clientId: request.clientId,
      grants: Object.freeze(grants),
      declarations: Object.freeze([...declarations.values()]),
    });
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}

function isAbortSignal(value: unknown): value is AbortSignal {
  try {
    return value instanceof AbortSignal && typeof value.aborted === "boolean";
  } catch {
    return false;
  }
}

function copyDeclaration(
  value: unknown,
  expectedType: string,
): SpaceDeclarationEvidence | null {
  const result = copyPlainRecord(value, [
    "tag",
    "main",
    "definitions",
    "head",
    "observedAt",
  ]);
  const main = result &&
    (copyPlainRecord(result.main, [
      "spaceType",
      "publisherDid",
      "recordCid",
      "key",
      "collections",
    ]) ??
      copyPlainRecord(result.main, [
        "spaceType",
        "publisherDid",
        "recordCid",
        "key",
        "title",
        "collections",
      ]));
  const head = result && copyPlainRecord(result.head, ["cid", "revision"]);
  if (
    !result || result.tag !== "proven" ||
    (result.definitions !== "main-only" &&
      result.definitions !== "additional") ||
    !main || !head || main.spaceType !== expectedType
  ) return null;
  const evidence = copySpaceDeclarationEvidence({
    spaceType: main.spaceType,
    publisherDid: main.publisherDid,
    recordCid: main.recordCid,
    headCid: head.cid,
    revision: head.revision,
    observedAt: result.observedAt,
    key: main.key,
    ...(main.title === undefined ? {} : { title: main.title }),
    collections: main.collections,
  });
  return evidence && Date.now() - evidence.observedAt <= MAX_OBSERVATION_AGE_MS
    ? evidence
    : null;
}
