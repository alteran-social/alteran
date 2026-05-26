import { jsonToLex, lexicons } from "@atproto/api";
import { isValidNsid, isValidTid } from "@atproto/syntax";
import { CID } from "multiformats/cid";
import type { Env } from "../env";
import { resolveSecret } from "./secrets";
import { generateTid } from "./commit";
import { RepoManager } from "../services/repo-manager";
import { resolveRecordBlobKeys } from "../services/repo/blob-refs";
import {
  parseRepositoryRecord,
  type RepositoryRecord,
} from "./repo-write-data";
import { RepoWriteError } from "./repo-write-error";
import { enforceRepoWriteLexiconConstraints } from "./repo-write-blob-constraints";
import {
  assertRepoWriteInput,
  hasSwapCommit,
  repoPath,
  type RepoWriteAction,
  requireString,
  validatePath,
} from "./repo-write-input";

export {
  handleRepoWriteError,
  invalidSwap,
  jsonError,
  RepoWriteError,
} from "./repo-write-error";
export type ValidationStatus = "valid" | "unknown" | undefined;

export type PreparedRecordWrite = {
  action: Extract<RepoWriteAction, "create" | "update">;
  collection: string;
  rkey: string;
  record: RepositoryRecord;
  validationStatus: ValidationStatus;
  blobKeys: string[];
};

export type PreparedDeleteWrite = {
  action: "delete";
  collection: string;
  rkey: string;
};

export type PreparedWrite = PreparedRecordWrite | PreparedDeleteWrite;

export type RepoWriteContext = {
  did: string;
  handle: string | undefined;
  currentCommitCid: string | null;
  repo: RepoManager;
};

export type RepoWriteContextWithSwap = RepoWriteContext & {
  expectedCommitCid: string | null | undefined;
};

type AuthLike = { did: string };

export async function buildRepoWriteContext(
  env: Env,
  auth: AuthLike,
  repoValue: unknown,
): Promise<RepoWriteContext> {
  const did = await resolveSecret(env.PDS_DID);
  if (!did) {
    throw new RepoWriteError("InvalidRequest", "PDS_DID is not configured");
  }
  const handle = await resolveSecret(env.PDS_HANDLE);

  if (auth.did !== did) {
    throw new RepoWriteError(
      "InvalidRequest",
      "authenticated user does not own this repo",
    );
  }

  if (typeof repoValue !== "string" || repoValue.length === 0) {
    throw new RepoWriteError("InvalidRequest", "repo is required");
  }
  const normalizedRepo = repoValue.toLowerCase();
  const normalizedHandle = typeof handle === "string"
    ? handle.toLowerCase()
    : undefined;
  if (repoValue !== did && normalizedRepo !== normalizedHandle) {
    throw new RepoWriteError(
      "InvalidRequest",
      "repo is not hosted by this PDS",
    );
  }

  return {
    did,
    handle,
    currentCommitCid: await getCurrentCommitCid(env, did),
    repo: new RepoManager(env),
  };
}

export async function prepareCreateRecord(
  env: Env,
  auth: AuthLike,
  input: unknown,
): Promise<RepoWriteContextWithSwap & { write: PreparedRecordWrite }> {
  const body = assertRepoWriteInput("com.atproto.repo.createRecord", input);
  const ctx = await buildRepoWriteContext(env, auth, body.repo);
  const expectedCommitCid = expectedCommitCidForRequest(
    body,
    ctx.currentCommitCid,
  );

  const collection = requireString(body.collection, "collection");
  const rkey = typeof body.rkey === "string" ? body.rkey : generateTid();
  validatePath(collection, rkey);

  const currentCid = await ctx.repo.getRecordCid(collection, rkey);
  if (currentCid) {
    throw new RepoWriteError("InvalidRequest", "record already exists");
  }

  return {
    ...ctx,
    expectedCommitCid,
    write: await prepareRecordWrite(env, ctx.did, {
      action: "create",
      collection,
      rkey,
      record: body.record,
      validate: body.validate,
    }),
  };
}

export async function preparePutRecord(
  env: Env,
  auth: AuthLike,
  input: unknown,
): Promise<RepoWriteContextWithSwap & { write: PreparedRecordWrite }> {
  const body = assertRepoWriteInput("com.atproto.repo.putRecord", input);
  const ctx = await buildRepoWriteContext(env, auth, body.repo);

  const collection = requireString(body.collection, "collection");
  const rkey = requireString(body.rkey, "rkey");
  validatePath(collection, rkey);

  const currentCid = await ctx.repo.getRecordCid(collection, rkey);
  const write = await prepareRecordWrite(env, ctx.did, {
    action: currentCid ? "update" : "create",
    collection,
    rkey,
    record: body.record,
    validate: body.validate,
  });
  const expectedCommitCid = expectedCommitCidForRequest(
    body,
    ctx.currentCommitCid,
  );
  checkSwapRecord(body.swapRecord, currentCid, true);

  return {
    ...ctx,
    expectedCommitCid,
    write,
  };
}

export async function prepareDeleteRecord(
  env: Env,
  auth: AuthLike,
  input: unknown,
): Promise<
  RepoWriteContextWithSwap & {
    write: PreparedDeleteWrite;
    currentCid: CID | null;
  }
> {
  const body = assertRepoWriteInput("com.atproto.repo.deleteRecord", input);
  const ctx = await buildRepoWriteContext(env, auth, body.repo);

  const collection = requireString(body.collection, "collection");
  const rkey = requireString(body.rkey, "rkey");
  validatePath(collection, rkey);

  const currentCid = await ctx.repo.getRecordCid(collection, rkey);
  const expectedCommitCid = expectedCommitCidForRequest(
    body,
    ctx.currentCommitCid,
  );
  checkSwapRecord(body.swapRecord, currentCid, false);

  return {
    ...ctx,
    expectedCommitCid,
    currentCid,
    write: { action: "delete", collection, rkey },
  };
}

export async function prepareApplyWrites(
  env: Env,
  auth: AuthLike,
  input: unknown,
): Promise<RepoWriteContextWithSwap & { writes: PreparedWrite[] }> {
  const body = assertRepoWriteInput("com.atproto.repo.applyWrites", input);
  const ctx = await buildRepoWriteContext(env, auth, body.repo);
  const expectedCommitCid = expectedCommitCidForRequest(
    body,
    ctx.currentCommitCid,
  );

  const rawWrites = Array.isArray(body.writes) ? body.writes : [];
  if (rawWrites.length > 200) {
    throw new RepoWriteError("InvalidRequest", "Too many writes. Max: 200");
  }
  const prepared: PreparedWrite[] = [];
  const state = new Map<string, boolean>();

  for (const raw of rawWrites) {
    const write = raw as Record<string, unknown>;
    const type = write.$type;
    const collection = requireString(write.collection, "collection");
    const rkey = typeof write.rkey === "string" ? write.rkey : generateTid();
    validatePath(collection, rkey);
    const path = repoPath(collection, rkey);

    let exists = state.get(path);
    if (exists === undefined) {
      exists = !!(await ctx.repo.getRecordCid(collection, rkey));
    }

    if (type === "com.atproto.repo.applyWrites#create") {
      if (exists) {
        throw new RepoWriteError("InvalidRequest", "record already exists");
      }
      const preparedWrite = await prepareRecordWrite(env, ctx.did, {
        action: "create",
        collection,
        rkey,
        record: write.value,
        validate: body.validate,
      });
      prepared.push(preparedWrite);
      state.set(path, true);
      continue;
    }

    if (type === "com.atproto.repo.applyWrites#update") {
      if (!exists) {
        throw new RepoWriteError("InvalidRequest", "record does not exist");
      }
      const preparedWrite = await prepareRecordWrite(env, ctx.did, {
        action: "update",
        collection,
        rkey,
        record: write.value,
        validate: body.validate,
      });
      prepared.push(preparedWrite);
      state.set(path, true);
      continue;
    }

    if (type === "com.atproto.repo.applyWrites#delete") {
      if (!exists) {
        throw new RepoWriteError("InvalidRequest", "record does not exist");
      }
      prepared.push({ action: "delete", collection, rkey });
      state.set(path, false);
      continue;
    }

    throw new RepoWriteError("InvalidRequest", "unsupported write type");
  }

  return { ...ctx, expectedCommitCid, writes: prepared };
}

async function prepareRecordWrite(
  env: Env,
  did: string,
  input: {
    action: Extract<RepoWriteAction, "create" | "update">;
    collection: string;
    rkey: string;
    record: unknown;
    validate: unknown;
  },
): Promise<PreparedRecordWrite> {
  const record = parseRepositoryRecord(input.collection, input.record);
  const validationStatus = validateLexiconRecord(
    input.collection,
    input.rkey,
    record,
    input.validate,
  );
  const blobKeys = await validateBlobRefs(env, did, record);
  return { ...input, record, validationStatus, blobKeys };
}

function validateLexiconRecord(
  collection: string,
  rkey: string,
  record: RepositoryRecord,
  validate: unknown,
): ValidationStatus {
  if (validate === false) return undefined;

  const def = lexicons.getDef(collection);
  const knownRecord = def?.type === "record" ? def : null;

  if (!knownRecord) {
    if (validate === true) {
      throw new RepoWriteError(
        "InvalidRequest",
        `Lexicon not found: ${collection}`,
      );
    }
    return "unknown";
  }

  enforceRecordKeyPolicy(knownRecord.key, rkey);

  let result: ReturnType<typeof lexicons.validate>;
  try {
    result = lexicons.validate(collection, jsonToLex(record));
  } catch (error) {
    throw new RepoWriteError(
      "InvalidRequest",
      error instanceof Error ? error.message : "invalid record",
    );
  }
  if (!result.success) {
    throw new RepoWriteError(
      "InvalidRequest",
      result.error?.message ?? "invalid record",
    );
  }
  enforceRepoWriteLexiconConstraints(knownRecord, record);
  return "valid";
}

function enforceRecordKeyPolicy(policy: unknown, rkey: string): void {
  if (typeof policy !== "string" || policy === "" || policy === "any") return;
  if (policy === "tid") {
    if (!isValidTid(rkey)) {
      throw new RepoWriteError("InvalidRequest", "rkey must be a valid TID");
    }
    return;
  }
  if (policy === "nsid") {
    if (!isValidNsid(rkey)) {
      throw new RepoWriteError("InvalidRequest", "rkey must be a valid NSID");
    }
    return;
  }
  if (policy.startsWith("literal:")) {
    const expected = policy.slice("literal:".length);
    if (rkey !== expected) {
      throw new RepoWriteError("InvalidRequest", `rkey must be ${expected}`);
    }
  }
}

function validateBlobRefs(
  env: Env,
  did: string,
  record: RepositoryRecord,
): Promise<string[]> {
  return resolveRecordBlobKeys(env, did, record);
}

function checkSwapCommit(
  value: unknown,
  currentCommitCid: string | null,
): void {
  if (value === undefined) return;
  const expected = parseSwapCid(value, "swapCommit");
  if (!currentCommitCid || !expected.equals(CID.parse(currentCommitCid))) {
    throw new RepoWriteError("InvalidSwap", "swapCommit mismatch");
  }
}

function expectedCommitCidForRequest(
  body: Record<string, unknown>,
  currentCommitCid: string | null,
): string | null | undefined {
  if (hasSwapCommit(body)) checkSwapCommit(body.swapCommit, currentCommitCid);
  return currentCommitCid;
}

function checkSwapRecord(
  value: unknown,
  currentCid: CID | null,
  nullable: boolean,
): void {
  if (value === undefined) return;
  if (value === null && nullable) {
    if (currentCid) {
      throw new RepoWriteError("InvalidSwap", "swapRecord mismatch");
    }
    return;
  }
  const expected = parseSwapCid(value, "swapRecord");
  if (!currentCid || !expected.equals(currentCid)) {
    throw new RepoWriteError("InvalidSwap", "swapRecord mismatch");
  }
}

async function getCurrentCommitCid(
  env: Env,
  did: string,
): Promise<string | null> {
  const row = await env.ALTERAN_DB.prepare(
    "SELECT commit_cid AS commitCid FROM repo_root WHERE did = ? LIMIT 1",
  ).bind(did).first<{ commitCid: string }>();
  return row?.commitCid ?? null;
}

function parseSwapCid(value: unknown, field: "swapCommit" | "swapRecord"): CID {
  if (typeof value !== "string") {
    throw new RepoWriteError("InvalidRequest", `${field} must be a CID`);
  }
  try {
    return CID.parse(value);
  } catch {
    throw new RepoWriteError("InvalidRequest", `${field} must be a CID`);
  }
}
