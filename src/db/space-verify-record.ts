import { decode, encode } from '@atproto/lex-cbor';
import { isValidNsid, isValidRecordKey } from '@atproto/syntax-spaces';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';

const MAX_BYTES = 1024 * 1024;
const MAX_ITEMS = 100_000;
const MAX_DEPTH = 100;
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
    const bounded = checkCborBounds(bytes);
    if (bounded !== 'valid') return bounded;
    const expectedCid = CID.createV1(0x71, createDigest(0x12, sha256(bytes))).toString();
    if (claimedCid !== expectedCid) return 'invalid';
    const value = decode(bytes);
    const canonical = encode(value);
    if (canonical.byteLength !== bytes.byteLength || canonical.some((byte, index) => byte !== bytes[index])) return 'invalid';
    if (!isPlainRecord(value) || !Object.hasOwn(value, '$type') || value.$type !== collection) return 'invalid';
    return checkDataModel(value);
  } catch {
    return 'invalid';
  }
}

function checkCborBounds(bytes: Uint8Array): SpaceRecordVerification {
  const pending = [1];
  let offset = 0;
  let items = 0;
  while (pending.length) {
    if (pending[pending.length - 1] === 0) {
      pending.pop();
      continue;
    }
    pending[pending.length - 1]--;
    if (++items > MAX_ITEMS) return 'unsupported';
    if (offset >= bytes.length) return 'invalid';
    const initial = bytes[offset++];
    const major = initial >> 5;
    const additional = initial & 31;
    let argument = BigInt(additional);
    if (additional >= 24) {
      const length = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
      if (length === 0 || offset + length > bytes.length) return 'invalid';
      argument = 0n;
      for (let index = 0; index < length; index++) argument = argument * 256n + BigInt(bytes[offset++]);
    }
    if (major === 0 || major === 1) {
      if (argument > MAX_INTEGER) return 'invalid';
    } else if (major === 2 || major === 3) {
      if (argument > BigInt(bytes.length - offset)) return 'invalid';
      offset += Number(argument);
    } else if (major === 4 || major === 5 || major === 6) {
      if (major === 6 && argument !== 42n) return 'invalid';
      const children = major === 6 ? 1n : argument * (major === 5 ? 2n : 1n);
      if (children > BigInt(MAX_ITEMS) || pending.length >= MAX_DEPTH) return 'unsupported';
      pending.push(Number(children));
    } else if (major === 7 && additional !== 20 && additional !== 21 && additional !== 22) {
      return 'invalid';
    }
  }
  return offset === bytes.length ? 'valid' : 'invalid';
}

function checkDataModel(root: unknown): SpaceRecordVerification {
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
    const type = Object.hasOwn(value, '$type') ? value.$type : undefined;
    if (type === 'blob' || (keys.length === 2 && Object.hasOwn(value, 'cid') && Object.hasOwn(value, 'mimeType') &&
      typeof value.cid === 'string' && typeof value.mimeType === 'string')) {
      return 'unsupported';
    }
    if (type !== undefined) {
      if (typeof type !== 'string') return 'invalid';
      const parts = type.split('#');
      if (!isValidNsid(parts[0]) || parts.length > 2 ||
        (parts.length === 2 && (!isValidRecordKey(parts[1]) || parts[1] === 'main'))) return 'invalid';
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
