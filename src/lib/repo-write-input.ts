import { lexicons } from "@atproto/api";
import { isValidNsid, isValidRecordKey } from "@atproto/syntax";
import { RepoWriteError } from "./repo-write-error";

export type RepoWriteAction = "create" | "update" | "delete";

export type RequestedWriteAuthorization = {
  collection: string;
  action: RepoWriteAction;
};

export function hasSwapCommit(input: Record<string, unknown>): boolean {
  return Object.prototype.hasOwnProperty.call(input, "swapCommit");
}

export function repoPath(collection: string, rkey: string): string {
  return `${collection}/${rkey}`;
}

export function createRecordAuthorizations(
  input: Record<string, unknown>,
): RequestedWriteAuthorization[] {
  return [{
    collection: requireString(input.collection, "collection"),
    action: "create",
  }];
}

export function putRecordAuthorizations(
  input: Record<string, unknown>,
): RequestedWriteAuthorization[] {
  const collection = requireString(input.collection, "collection");
  if (input.swapRecord === null) {
    return [{ collection, action: "create" }];
  }
  if (typeof input.swapRecord === "string") {
    return [{ collection, action: "update" }];
  }
  return [
    { collection, action: "create" },
    { collection, action: "update" },
  ];
}

export function deleteRecordAuthorizations(
  input: Record<string, unknown>,
): RequestedWriteAuthorization[] {
  return [{
    collection: requireString(input.collection, "collection"),
    action: "delete",
  }];
}

export function applyWritesAuthorizations(
  input: Record<string, unknown>,
): RequestedWriteAuthorization[] {
  const rawWrites = Array.isArray(input.writes) ? input.writes : [];
  return rawWrites.map((raw) => {
    const write = raw as Record<string, unknown>;
    const collection = requireString(write.collection, "collection");
    switch (write.$type) {
      case "com.atproto.repo.applyWrites#create":
        return { collection, action: "create" };
      case "com.atproto.repo.applyWrites#update":
        return { collection, action: "update" };
      case "com.atproto.repo.applyWrites#delete":
        return { collection, action: "delete" };
      default:
        throw new RepoWriteError("InvalidRequest", "unsupported write type");
    }
  });
}

export function assertRepoWriteInput(
  lexUri: string,
  input: unknown,
): Record<string, unknown> {
  try {
    return lexicons.assertValidXrpcInput(lexUri, input) as Record<
      string,
      unknown
    >;
  } catch (error) {
    throw new RepoWriteError(
      "InvalidRequest",
      error instanceof Error ? error.message : "invalid input",
    );
  }
}

export function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new RepoWriteError("InvalidRequest", `${field} is required`);
  }
  return value;
}

export function validatePath(collection: string, rkey: string): void {
  if (!isValidNsid(collection)) {
    throw new RepoWriteError(
      "InvalidRequest",
      "collection must be a valid NSID",
    );
  }
  if (!isValidRecordKey(rkey)) {
    throw new RepoWriteError(
      "InvalidRequest",
      "rkey must be a valid record key",
    );
  }
}
