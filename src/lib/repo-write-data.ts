import { CID } from 'multiformats/cid';
import { RepoWriteError } from './repo-write-error';

export type BlobReference = {
  cid: string;
  mimeType: string;
  size: number;
};

export function validateRawRecord(collection: string, value: unknown): Record<string, unknown> {
  if (!isPlainObject(value)) {
    throw new RepoWriteError('InvalidRequest', 'record must be an object');
  }
  const record = { ...value };
  if (record.$type === undefined) {
    record.$type = collection;
  } else if (record.$type !== collection) {
    throw new RepoWriteError('InvalidRequest', 'record $type must match collection');
  }
  validateRawValue(record, 'record');
  return record;
}

export function collectBlobRefs(value: unknown, refs: BlobReference[]): void {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    for (const item of value) collectBlobRefs(item, refs);
    return;
  }
  const obj = value as Record<string, unknown>;
  if (obj.$type === 'blob') {
    const blob = validateBlobObject(obj, 'blob');
    refs.push({ cid: blob.cid.toString(), mimeType: blob.mimeType, size: blob.size });
    return;
  }
  for (const child of Object.values(obj)) collectBlobRefs(child, refs);
}

function validateRawValue(value: unknown, path: string): void {
  if (value === null) return;
  if (typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new RepoWriteError('InvalidRequest', `${path} must contain integer numbers`);
    }
    if (!Number.isSafeInteger(value)) {
      throw new RepoWriteError('InvalidRequest', `${path} contains an unsafe integer`);
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
    throw new RepoWriteError('InvalidRequest', `${path} contains an unsupported value`);
  }

  if ('$link' in value) {
    validateCidLinkObject(value, path);
    return;
  }
  if ('$bytes' in value) {
    validateBytesObject(value, path);
    return;
  }
  if (isLegacyBlobObject(value)) {
    throw new RepoWriteError('InvalidRequest', `${path} contains a legacy blob object`);
  }
  if (value.$type === 'blob') {
    validateBlobObject(value, path);
    return;
  }

  for (const [key, child] of Object.entries(value)) {
    if (key.length === 0) {
      throw new RepoWriteError('InvalidRequest', `${path} contains an empty object key`);
    }
    if (key === '$type' && typeof child !== 'string') {
      throw new RepoWriteError('InvalidRequest', `${path} $type must be a string`);
    }
    validateRawValue(child, `${path}/${key}`);
  }
}

function validateCidLinkObject(obj: Record<string, unknown>, path: string): CID {
  const keys = Object.keys(obj);
  if (keys.length !== 1 || typeof obj.$link !== 'string') {
    throw new RepoWriteError('InvalidRequest', `${path} must be a CID link object`);
  }
  if (!obj.$link.startsWith('b') || obj.$link !== obj.$link.toLowerCase()) {
    throw new RepoWriteError('InvalidRequest', `${path} must contain a base32 CID string`);
  }
  let cid: CID;
  try {
    cid = CID.parse(obj.$link);
  } catch {
    throw new RepoWriteError('InvalidRequest', `${path} must contain a valid CID`);
  }
  if (cid.toString() !== obj.$link) {
    throw new RepoWriteError('InvalidRequest', `${path} must contain a base32 CID string`);
  }
  validateDataCid(cid, path);
  return cid;
}

function validateBytesObject(obj: Record<string, unknown>, path: string): void {
  const keys = Object.keys(obj);
  if (keys.length !== 1 || typeof obj.$bytes !== 'string') {
    throw new RepoWriteError('InvalidRequest', `${path} must be a bytes object`);
  }
  if (!isSimpleBase64(obj.$bytes)) {
    throw new RepoWriteError('InvalidRequest', `${path} must contain RFC-4648 base64 bytes`);
  }
}

function validateBlobObject(obj: Record<string, unknown>, path: string): {
  cid: CID;
  mimeType: string;
  size: number;
} {
  const keys = Object.keys(obj).sort();
  if (keys.join('\0') !== ['$type', 'mimeType', 'ref', 'size'].sort().join('\0')) {
    throw new RepoWriteError('InvalidRequest', `${path} must be a regular blob object`);
  }
  if (obj.$type !== 'blob') {
    throw new RepoWriteError('InvalidRequest', `${path} must be a typed blob`);
  }
  if (!isPlainObject(obj.ref)) {
    throw new RepoWriteError('InvalidRequest', `${path}.ref must be a CID link`);
  }
  const cid = validateCidLinkObject(obj.ref, `${path}/ref`);
  validateRawBlobCid(cid, path);
  if (typeof obj.mimeType !== 'string' || obj.mimeType.length === 0) {
    throw new RepoWriteError('InvalidRequest', `${path}.mimeType must be non-empty`);
  }
  if (typeof obj.size !== 'number' || !Number.isInteger(obj.size) || obj.size < 0) {
    throw new RepoWriteError('InvalidRequest', `${path}.size must be a non-negative integer`);
  }
  return { cid, mimeType: obj.mimeType, size: obj.size };
}

function validateRawBlobCid(cid: CID, path: string): void {
  if (cid.version !== 1 || cid.code !== 0x55) {
    throw new RepoWriteError('InvalidRequest', `${path}.ref must be a raw CIDv1 blob CID`);
  }
  if (cid.multihash.code !== 0x12 || cid.multihash.digest.byteLength !== 32) {
    throw new RepoWriteError('InvalidRequest', `${path}.ref must use a SHA-256 multihash`);
  }
}

function isLegacyBlobObject(obj: Record<string, unknown>): boolean {
  const keys = Object.keys(obj).sort();
  return keys.join('\0') === ['cid', 'mimeType'].join('\0') &&
    typeof obj.cid === 'string' &&
    typeof obj.mimeType === 'string';
}

function validateDataCid(cid: CID, path: string): void {
  if (cid.version !== 1) {
    throw new RepoWriteError('InvalidRequest', `${path} must contain a CIDv1 link`);
  }
  if (cid.code !== 0x71 && cid.code !== 0x55) {
    throw new RepoWriteError('InvalidRequest', `${path} must use dag-cbor or raw multicodec`);
  }
  if (cid.multihash.code !== 0x12 || cid.multihash.digest.byteLength !== 32) {
    throw new RepoWriteError('InvalidRequest', `${path} must use a SHA-256 multihash`);
  }
}

function isSimpleBase64(value: string): boolean {
  if (value === '') return true;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return false;
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  const bodyLength = value.length - padding;
  if (bodyLength === 0) return false;
  if (padding > 0 && value.length % 4 !== 0) return false;
  if (padding === 1) return bodyLength % 4 === 3;
  if (padding === 2) return bodyLength % 4 === 2;
  return bodyLength % 4 !== 1;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}
