import { CID } from "multiformats/cid";
import { isLexBytesBase64 } from "./lex-bytes";
import { RepoWriteError } from "./repo-write-error";

export type BlobReference = {
  cid: string;
  mimeType: string;
  size: number;
};

export type RepositoryRecordValue =
  | string
  | number
  | boolean
  | null
  | readonly RepositoryRecordValue[]
  | Readonly<Record<string, RepositoryRecordValue>>;

export type RepositoryRecord = Readonly<Record<string, RepositoryRecordValue>>;

export function parseRepositoryRecord(
  collection: string,
  value: unknown,
): RepositoryRecord {
  if (!isPlainObject(value)) {
    throw new RepoWriteError("InvalidRequest", "record must be an object");
  }
  if (value.$type === undefined) {
    throw new RepoWriteError("InvalidRequest", "record $type is required");
  }
  if (typeof value.$type !== "string") {
    throw new RepoWriteError("InvalidRequest", "record $type must be a string");
  }
  if (value.$type !== collection) {
    throw new RepoWriteError(
      "InvalidRequest",
      "record $type must match collection",
    );
  }
  validateRawValue(value, "record");
  return cloneFrozenObject(value);
}

export function collectBlobRefs(value: unknown, refs: BlobReference[]): void {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) collectBlobRefs(item, refs);
    return;
  }
  const obj = value as Record<string, unknown>;
  if (obj.$type === "blob") {
    const blob = validateBlobObject(obj, "blob");
    refs.push({
      cid: blob.cid.toString(),
      mimeType: blob.mimeType,
      size: blob.size,
    });
    return;
  }
  for (const child of Object.values(obj)) collectBlobRefs(child, refs);
}

function validateRawValue(value: unknown, path: string): void {
  if (value === null) return;
  if (typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new RepoWriteError(
        "InvalidRequest",
        `${path} must contain integer numbers`,
      );
    }
    if (!Number.isSafeInteger(value)) {
      throw new RepoWriteError(
        "InvalidRequest",
        `${path} contains an unsafe integer`,
      );
    }
    return;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++) {
      validateRawValue(value[index], `${path}/${index}`);
    }
    return;
  }
  if (!isPlainObject(value)) {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path} contains an unsupported value`,
    );
  }

  if ("$link" in value) {
    validateCidLinkObject(value, path);
    return;
  }
  if ("$bytes" in value) {
    validateBytesObject(value, path);
    return;
  }
  if (isLegacyBlobObject(value)) {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path} contains a legacy blob object`,
    );
  }
  if (value.$type === "blob") {
    validateBlobObject(value, path);
    return;
  }

  for (const [key, child] of Object.entries(value)) {
    if (key.length === 0) {
      throw new RepoWriteError(
        "InvalidRequest",
        `${path} contains an empty object key`,
      );
    }
    if (key === "__proto__") {
      throw new RepoWriteError(
        "InvalidRequest",
        `${path} contains a forbidden object key`,
      );
    }
    if (key === "$type" && (typeof child !== "string" || child.length === 0)) {
      throw new RepoWriteError(
        "InvalidRequest",
        `${path} $type must be a non-empty string`,
      );
    }
    validateRawValue(child, `${path}/${key}`);
  }
}

function cloneFrozenValue(value: unknown): RepositoryRecordValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(value.map((item) => cloneFrozenValue(item)));
  }
  if (isPlainObject(value)) {
    return cloneFrozenObject(value);
  }
  throw new RepoWriteError(
    "InvalidRequest",
    "record contains an unsupported value",
  );
}

function cloneFrozenObject(
  value: Record<string, unknown>,
): Readonly<Record<string, RepositoryRecordValue>> {
  const record: Record<string, RepositoryRecordValue> = Object.create(null);
  for (const [key, child] of Object.entries(value)) {
    record[key] = cloneFrozenValue(child);
  }
  return Object.freeze(record);
}

function validateCidLinkObject(
  obj: Record<string, unknown>,
  path: string,
): CID {
  const keys = Object.keys(obj);
  if (keys.length !== 1 || typeof obj.$link !== "string") {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path} must be a CID link object`,
    );
  }
  if (!obj.$link.startsWith("b") || obj.$link !== obj.$link.toLowerCase()) {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path} must contain a base32 CID string`,
    );
  }
  let cid: CID;
  try {
    cid = CID.parse(obj.$link);
  } catch {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path} must contain a valid CID`,
    );
  }
  if (cid.toString() !== obj.$link) {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path} must contain a base32 CID string`,
    );
  }
  validateDataCid(cid, path);
  return cid;
}

function validateBytesObject(obj: Record<string, unknown>, path: string): void {
  const keys = Object.keys(obj);
  if (keys.length !== 1 || typeof obj.$bytes !== "string") {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path} must be a bytes object`,
    );
  }
  if (!isLexBytesBase64(obj.$bytes)) {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path} must contain RFC-4648 base64 bytes`,
    );
  }
}

function validateBlobObject(obj: Record<string, unknown>, path: string): {
  cid: CID;
  mimeType: string;
  size: number;
} {
  const keys = Object.keys(obj).sort();
  if (
    keys.join("\0") !== ["$type", "mimeType", "ref", "size"].sort().join("\0")
  ) {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path} must be a regular blob object`,
    );
  }
  if (obj.$type !== "blob") {
    throw new RepoWriteError("InvalidRequest", `${path} must be a typed blob`);
  }
  if (!isPlainObject(obj.ref)) {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path}.ref must be a CID link`,
    );
  }
  const cid = validateCidLinkObject(obj.ref, `${path}/ref`);
  validateRawBlobCid(cid, path);
  if (!isMimeType(obj.mimeType)) {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path}.mimeType must be a valid MIME type`,
    );
  }
  if (
    typeof obj.size !== "number" ||
    !Number.isInteger(obj.size) ||
    !Number.isSafeInteger(obj.size) ||
    obj.size < 0
  ) {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path}.size must be a non-negative safe integer`,
    );
  }
  return { cid, mimeType: obj.mimeType, size: obj.size };
}

function validateRawBlobCid(cid: CID, path: string): void {
  if (cid.version !== 1 || cid.code !== 0x55) {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path}.ref must be a raw CIDv1 blob CID`,
    );
  }
}

function isLegacyBlobObject(obj: Record<string, unknown>): boolean {
  const keys = Object.keys(obj).sort();
  return keys.join("\0") === ["cid", "mimeType"].join("\0") &&
    typeof obj.cid === "string" &&
    typeof obj.mimeType === "string";
}

function validateDataCid(cid: CID, path: string): void {
  if (cid.version !== 1) {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path} must contain a CIDv1 link`,
    );
  }
  if (cid.code !== 0x71 && cid.code !== 0x55) {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path} must use dag-cbor or raw multicodec`,
    );
  }
  if (cid.multihash.code !== 0x12 || cid.multihash.digest.byteLength !== 32) {
    throw new RepoWriteError(
      "InvalidRequest",
      `${path} must use a SHA-256 multihash`,
    );
  }
}

function isMimeType(value: unknown): value is string {
  return typeof value === "string" && value.includes("/");
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}
