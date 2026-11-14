import { MAX_RECORD_SIZE } from '@atproto/space';

export const MAX_RECORD_CBOR_ITEMS = 131_072;
const MAX_DEPTH = 100;
const MAX_INTEGER = (1n << 63n) - 1n;

export type RecordCborBounds = 'valid' | 'invalid' | 'unsupported';
export type RecordCborInspection =
  | { readonly tag: 'valid'; readonly items: number }
  | { readonly tag: 'invalid' | 'unsupported' };

const invalid = Object.freeze({ tag: 'invalid' } as const);
const unsupported = Object.freeze({ tag: 'unsupported' } as const);

/** Bound decoder work before allocating record values from CBOR. */
export function checkRecordCborBounds(bytes: Uint8Array): RecordCborBounds {
  return inspectRecordCborBounds(bytes).tag;
}

/** Count items so callers can bound aggregate decoder work before allocation. */
export function inspectRecordCborBounds(bytes: Uint8Array, itemLimit = MAX_RECORD_CBOR_ITEMS): RecordCborInspection {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 1 || bytes.byteLength > MAX_RECORD_SIZE) return invalid;
  if (!Number.isSafeInteger(itemLimit) || itemLimit < 0 || itemLimit > MAX_RECORD_CBOR_ITEMS) return invalid;
  const pending = [1];
  let offset = 0;
  let items = 0;
  while (pending.length) {
    if (pending[pending.length - 1] === 0) {
      pending.pop();
      continue;
    }
    pending[pending.length - 1]--;
    if (++items > itemLimit) return unsupported;
    if (offset >= bytes.length) return invalid;
    const initial = bytes[offset++];
    const major = initial >> 5;
    const additional = initial & 31;
    let argument = BigInt(additional);
    if (additional >= 24) {
      const length = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
      if (length === 0 || offset + length > bytes.length) return invalid;
      argument = 0n;
      for (let index = 0; index < length; index++) argument = argument * 256n + BigInt(bytes[offset++]);
    }
    if (major === 0 || major === 1) {
      if (argument > MAX_INTEGER) return invalid;
    } else if (major === 2 || major === 3) {
      if (argument > BigInt(bytes.length - offset)) return invalid;
      offset += Number(argument);
    } else if (major === 4 || major === 5 || major === 6) {
      if (major === 6 && argument !== 42n) return invalid;
      const children = major === 6 ? 1n : argument * (major === 5 ? 2n : 1n);
      if (children > BigInt(itemLimit) || pending.length >= MAX_DEPTH) return unsupported;
      pending.push(Number(children));
    } else if (major === 7 && additional !== 20 && additional !== 21 && additional !== 22) {
      return invalid;
    }
  }
  return offset === bytes.length ? { tag: 'valid', items } : invalid;
}
