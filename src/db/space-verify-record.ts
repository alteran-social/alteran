import { decode, encode } from '@atproto/lex-cbor';
import { isValidNsid, isValidRecordKey } from '@atproto/syntax-spaces';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { checkRecordCborBounds } from '../lib/spaces/record-cbor-bounds';

const MAX_BYTES = 1024 * 1024;
const MAX_INTEGER = (1n << 63n) - 1n;

export type SpaceRecordVerification = 'valid' | 'invalid' | 'unsupported';

/** Validate a legacy record without exposing its bytes or enabling blob storage. */
export function verifySpaceRecordBlock(
  collection: string,
  rkey: string,
  claimedCid: string,
  input: Uint8Array,
): SpaceRecordVerification {
  try {
    if (!isValidNsid(collection) || !isValidRecordKey(rkey) || typeof claimedCid !== 'string' ||
      !ArrayBuffer.isView(input) || !(input instanceof Uint8Array)) return 'invalid';
    const length = Reflect.get(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength', input);
    if (!Number.isSafeInteger(length) || length < 1 || length > MAX_BYTES) return 'invalid';
    const bytes = new Uint8Array(input);
    if (bytes.byteLength !== length) return 'invalid';
    const bounded = checkRecordCborBounds(bytes);
    if (bounded !== 'valid') return bounded;
    const expectedCid = CID.createV1(0x71, createDigest(0x12, sha256(bytes))).toString();
    if (claimedCid !== expectedCid) return 'invalid';
    const value = decode(bytes);
    const canonical = encode(value);
    if (canonical.byteLength !== bytes.byteLength || canonical.some((byte, index) => byte !== bytes[index])) return 'invalid';
    if (!isPlainRecord(value) || !Object.hasOwn(value, '$type') || value.$type !== collection) return 'invalid';
    return verifySpaceRecordDataModel(value);
  } catch {
    return 'invalid';
  }
}

export function verifySpaceRecordDataModel(root: unknown): SpaceRecordVerification {
  const pending = [root];
  while (pending.length) {
    const value = pending.pop();
    if (value === null || typeof value === 'string' || typeof value === 'boolean') continue;
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value)) return 'invalid';
      continue;
    }
    if (typeof value === 'bigint') {
      if (value < -MAX_INTEGER - 1n || value > MAX_INTEGER) return 'invalid';
      continue;
    }
    if (value instanceof Uint8Array) continue;
    const cid = CID.asCID(value);
    if (cid) {
      if (cid.version !== 1 || (cid.code !== 0x71 && cid.code !== 0x55) ||
        cid.multihash.code !== 0x12 || cid.multihash.digest.byteLength !== 32) return 'invalid';
      continue;
    }
    if (Array.isArray(value)) {
      for (const child of value) pending.push(child);
      continue;
    }
    if (!isPlainRecord(value)) return 'invalid';
    const keys = Object.keys(value);
    if (keys.some((key) => key.length === 0 || key === '__proto__')) return 'invalid';
    const type = Object.hasOwn(value, '$type') ? value.$type : undefined;
    if (type === 'blob' || (keys.length === 2 && Object.hasOwn(value, 'cid') && Object.hasOwn(value, 'mimeType') &&
      typeof value.cid === 'string' && typeof value.mimeType === 'string')) {
      return 'unsupported';
    }
    if (type !== undefined) {
      if (typeof type !== 'string' || type.length === 0) return 'invalid';
    }
    if (Object.hasOwn(value, '$link') || Object.hasOwn(value, '$bytes')) return 'invalid';
    for (const child of Object.values(value)) pending.push(child);
  }
  return 'valid';
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
