import { decode, encode, type LexValue } from "@atproto/lex-cbor";

const MAX_DEPTH = 100;
const MAX_FRAME_ITEMS = 100_000;
const MAX_SIGNED_INTEGER = (1n << 63n) - 1n;

export type CborBudget = { remaining: number };

/** Reject resource-amplifying CBOR before the decoder allocates its values. */
function checkStructure(bytes: Uint8Array, budget: CborBudget): void {
  const pending = [1];
  let offset = 0;
  let items = 0;
  while (pending.length) {
    if (pending[pending.length - 1] === 0) {
      pending.pop();
      continue;
    }
    pending[pending.length - 1]--;
    if (
      ++items > MAX_FRAME_ITEMS || --budget.remaining < 0 ||
      offset >= bytes.length
    ) throw invalid();
    const initial = bytes[offset++];
    const major = initial >> 5;
    const additional = initial & 31;
    let argument = BigInt(additional);
    if (additional >= 24) {
      const length = additional === 24
        ? 1
        : additional === 25
        ? 2
        : additional === 26
        ? 4
        : additional === 27
        ? 8
        : 0;
      if (!length || offset + length > bytes.length) throw invalid();
      argument = 0n;
      for (let index = 0; index < length; index++) {
        argument = argument * 256n + BigInt(bytes[offset++]);
      }
    }
    if (major === 0 || major === 1) {
      if (argument > MAX_SIGNED_INTEGER) throw invalid();
    } else if (major === 2 || major === 3) {
      if (argument > BigInt(bytes.length - offset)) throw invalid();
      offset += Number(argument);
    } else if (major === 4 || major === 5 || major === 6) {
      if (major === 6 && argument !== 42n) throw invalid();
      const children = major === 6 ? 1n : argument * (major === 5 ? 2n : 1n);
      if (children > BigInt(MAX_FRAME_ITEMS) || pending.length >= MAX_DEPTH) {
        throw invalid();
      }
      pending.push(Number(children));
    } else if (
      major === 7 && additional !== 20 && additional !== 21 && additional !== 22
    ) {
      throw invalid();
    }
  }
  if (offset !== bytes.length) throw invalid();
}

export function decodeCanonicalMap(
  bytes: Uint8Array,
  budget: CborBudget,
): Record<string, unknown> {
  checkStructure(bytes, budget);
  const value: unknown = decode(bytes);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalid();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) throw invalid();
  const canonical = encode(value as LexValue);
  if (
    canonical.length !== bytes.length ||
    canonical.some((byte, index) => byte !== bytes[index])
  ) throw invalid();
  return value as Record<string, unknown>;
}

export function encodeCanonicalMap(
  value: Record<string, unknown>,
  maximum: number,
  budget: CborBudget,
): Uint8Array {
  const bytes = encode(value as LexValue);
  if (bytes.length > maximum) throw invalid();
  checkStructure(bytes, budget);
  return bytes;
}

/** Measure normalized values before asking the encoder to allocate. */
export function measureCanonicalMap(
  value: Record<string, unknown>,
  maximum: number,
): number {
  const pending: unknown[] = [value];
  const encoder = new TextEncoder();
  let bytes = 0;
  let items = 0;
  const add = (count: number) => {
    bytes += count;
    if (bytes > maximum) throw invalid();
  };
  while (pending.length) {
    const item = pending.pop();
    if (++items > MAX_FRAME_ITEMS) throw invalid();
    if (typeof item === "string") {
      if (item.length > maximum) throw invalid();
      const length = encoder.encode(item).length;
      add(headLength(length) + length);
    } else if (typeof item === "boolean" || item === null) {
      add(1);
    } else if (
      typeof item === "number" && Number.isSafeInteger(item) && item >= 0
    ) {
      add(headLength(item));
    } else if (item instanceof Uint8Array) {
      add(headLength(item.byteLength) + item.byteLength);
    } else if (Array.isArray(item)) {
      add(headLength(item.length));
      for (const child of item) pending.push(child);
    } else if (item && typeof item === "object") {
      const fields = Object.entries(item);
      add(headLength(fields.length));
      for (const [key, child] of fields) pending.push(key, child);
    } else {
      throw invalid();
    }
  }
  return bytes;
}

function headLength(value: number): number {
  if (value < 24) return 1;
  if (value < 256) return 2;
  if (value < 65_536) return 3;
  if (value <= 0xffffffff) return 5;
  return 9;
}

function invalid(): Error {
  return new Error("Invalid bounded DRISL");
}
