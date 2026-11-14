import { parseSpecialJsonObject } from '@atproto/lex-json';
import { CID } from 'multiformats/cid';
import { base32 } from 'multiformats/bases/base32';
import { base58btc } from 'multiformats/bases/base58';
import { base64 } from 'multiformats/bases/base64';
import { MAX_INTEGER_PAGE_BIGINTS, MAX_INTEGER_PAGE_BYTES, MAX_INTEGER_PAGE_ITEMS } from './record-integer-budget';

const MIN_INTEGER = -(1n << 63n);
const MAX_INTEGER = (1n << 63n) - 1n;
const MIN_SAFE = BigInt(Number.MIN_SAFE_INTEGER);
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const MAX_DEPTH = 100;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'length')?.get;
const typedArrayBuffer = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer')?.get;

type SourceContext = { readonly source?: unknown };
type SourceParse = (text: string, reviver: (this: unknown, key: string, value: unknown, context?: SourceContext) => unknown) => unknown;
type RawJson = (value: string) => unknown;

/** Stringify bounded decoded Lex data while retaining exact 64-bit integer tokens. */
export function stringifyIntegerLex(value: unknown): string {
  const raw = (JSON as typeof JSON & { rawJSON?: RawJson }).rawJSON;
  if (typeof raw !== 'function' || !supportsSourceText()) throw new Error('Lossless JSON is unavailable');
  const seen = new WeakSet<object>();
  const encoder = new TextEncoder();
  let items = 0, bigints = 0, contentBytes = 0;

  const countBytes = (length: number) => {
    contentBytes += length;
    if (contentBytes > MAX_INTEGER_PAGE_BYTES) throw new Error('Lex value is too large');
  };
  const stringValue = (input: string): string => {
    if (input.length > MAX_INTEGER_PAGE_BYTES) throw new Error('Lex value is too large');
    countBytes(encoder.encode(input).byteLength);
    return input;
  };
  const bytesValue = (input: Uint8Array): Uint8Array => {
    if (!typedArrayLength || !typedArrayBuffer) throw new Error('Invalid Lex bytes');
    const length: unknown = typedArrayLength.call(input);
    const buffer: unknown = typedArrayBuffer.call(input);
    if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0 ||
      length > MAX_INTEGER_PAGE_BYTES || !(buffer instanceof ArrayBuffer)) throw new Error('Invalid Lex bytes');
    countBytes(length);
    return new Uint8Array(input);
  };
  const convert = (input: unknown, depth: number): unknown => {
    if (++items > MAX_INTEGER_PAGE_ITEMS || depth > MAX_DEPTH) throw new Error('Lex value is too complex');
    if (input === null || typeof input === 'boolean') return input;
    if (typeof input === 'string') return stringValue(input);
    if (typeof input === 'number') {
      if (!Number.isSafeInteger(input)) throw new Error('Invalid Lex integer');
      return input;
    }
    if (typeof input === 'bigint') {
      if (++bigints > MAX_INTEGER_PAGE_BIGINTS || input < MIN_INTEGER || input > MAX_INTEGER) throw new Error('Invalid Lex integer');
      const decimal = String(input);
      const marker = raw(decimal);
      if (!marker || typeof marker !== 'object' || Object.getPrototypeOf(marker) !== null || !Object.isFrozen(marker)) {
        throw new Error('Invalid raw JSON marker');
      }
      const keys = Reflect.ownKeys(marker), descriptor = Object.getOwnPropertyDescriptor(marker, 'rawJSON');
      if (keys.length !== 1 || keys[0] !== 'rawJSON' || !descriptor || !('value' in descriptor) || descriptor.value !== decimal) {
        throw new Error('Invalid raw JSON marker');
      }
      return marker;
    }
    if (!input || typeof input !== 'object') throw new Error('Invalid Lex value');
    if (input instanceof Uint8Array) {
      const output = Object.create(null) as Record<string, unknown>;
      output.$bytes = base64.encode(bytesValue(input)).slice(1);
      return output;
    }
    if (input instanceof CID) {
      if (++items > MAX_INTEGER_PAGE_ITEMS) throw new Error('Lex value is too complex');
      const bytes = Object.getOwnPropertyDescriptor(input, 'bytes');
      const version = Object.getOwnPropertyDescriptor(input, 'version');
      if (!bytes || !('value' in bytes) || !(bytes.value instanceof Uint8Array) ||
        !version || !('value' in version) || (version.value !== 0 && version.value !== 1)) throw new Error('Invalid Lex link');
      const encoded = bytesValue(bytes.value);
      const parsed = CID.decode(encoded);
      if (parsed.version !== version.value) throw new Error('Invalid Lex link');
      const output = Object.create(null) as Record<string, unknown>;
      output.$link = version.value === 0 ? base58btc.encode(encoded).slice(1) : base32.encode(encoded);
      return output;
    }
    if (seen.has(input)) throw new Error('Invalid Lex cycle');
    seen.add(input);
    if (Array.isArray(input)) {
      const length = Object.getOwnPropertyDescriptor(input, 'length');
      if (!length || !('value' in length) || !Number.isSafeInteger(length.value) || length.value < 0 ||
        length.value > MAX_INTEGER_PAGE_ITEMS - items) throw new Error('Invalid Lex array');
      const output: unknown[] = [];
      Object.setPrototypeOf(output, null);
      for (let index = 0; index < length.value; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
        if (!descriptor || !('value' in descriptor)) throw new Error('Invalid Lex array');
        Object.defineProperty(output, String(index), { value: convert(descriptor.value, depth + 1),
          enumerable: true, writable: true, configurable: true });
      }
      return output;
    }
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) throw new Error('Invalid Lex map');
    const keys = Object.keys(input);
    if (keys.length > MAX_INTEGER_PAGE_ITEMS - items) throw new Error('Lex value is too complex');
    const output = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      if (++items > MAX_INTEGER_PAGE_ITEMS) throw new Error('Lex value is too complex');
      stringValue(key);
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor || !('value' in descriptor)) throw new Error('Invalid Lex map');
      Object.defineProperty(output, key, { value: convert(descriptor.value, depth + 1),
        enumerable: true, writable: true, configurable: true });
    }
    return output;
  };
  return JSON.stringify(convert(value, 0));
}

/** Restore generated Lex JSON without rounding integer tokens. */
export function parseIntegerLex(text: string): unknown {
  if (!supportsSourceText()) throw new Error('Lossless JSON is unavailable');
  const parse = JSON.parse as unknown as SourceParse;
  return parse(text, function (_key, value, context) {
    if (typeof value === 'number') {
      const source = context && Object.getOwnPropertyDescriptor(context, 'source')?.value;
      if (typeof source !== 'string' || source.length > 20 || source === '-0' ||
        !/^-?(?:0|[1-9][0-9]*)$/.test(source)) throw new Error('Invalid Lex integer');
      const integer = BigInt(source);
      if (integer < MIN_INTEGER || integer > MAX_INTEGER) throw new Error('Invalid Lex integer');
      return integer >= MIN_SAFE && integer <= MAX_SAFE ? Number(integer) : integer;
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
    const safe = Object.create(null) as Record<string, unknown>;
    for (const key of Object.keys(value)) {
      if (key === '__proto__') throw new Error('Invalid Lex map');
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !('value' in descriptor)) throw new Error('Invalid Lex map');
      Object.defineProperty(safe, key, { value: descriptor.value, enumerable: true, writable: true, configurable: true });
    }
    if (Object.getOwnPropertyDescriptor(safe, '$type')?.value === 'blob') {
      for (const key of ['$type', 'ref', 'mimeType', 'size']) {
        const descriptor = Object.getOwnPropertyDescriptor(safe, key);
        if (!descriptor || !('value' in descriptor)) throw new Error('Invalid Lex blob');
      }
      const ref = Object.getOwnPropertyDescriptor(safe, 'ref')?.value;
      if (ref && typeof ref === 'object' && '$link' in ref && !Object.hasOwn(ref, '$link')) throw new Error('Invalid Lex blob');
    }
    // This pinned lex-json helper handles reserved link, bytes, type and blob
    // shapes, matching the strict parser used by the ordinary response path.
    return parseSpecialJsonObject(safe as Parameters<typeof parseSpecialJsonObject>[0], { strict: true }) ?? safe;
  });
}

function supportsSourceText(): boolean {
  try {
    const parse = JSON.parse as unknown as SourceParse;
    return parse('0', (_key, _value, context) =>
      !!context && Object.getOwnPropertyDescriptor(context, 'source')?.value === '0') === true;
  } catch {
    return false;
  }
}
