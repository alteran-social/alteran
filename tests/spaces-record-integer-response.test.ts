import { expect } from '@std/expect';
import { encode } from '@atproto/lex-cbor';
import { lexParse } from '@atproto/lex-json';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { inspectRecordCborDetails } from '../src/lib/spaces/record-cbor-bounds';
import { MAX_INTEGER_JSON_BYTES, MAX_INTEGER_PAGE_BIGINTS, MAX_INTEGER_PAGE_BYTES, MAX_INTEGER_PAGE_ITEMS } from '../src/lib/spaces/record-integer-budget';
import { parseIntegerLex, stringifyIntegerLex } from '../src/lib/spaces/record-integer-json';
import { createSpaceRecordResponse, serializeSpaceRecordValue, SpaceRecordResponseError } from '../src/lib/spaces/record-response';

const identity = { space: 'at://did:example:test/space/com.example.notes/room', repo: 'did:example:test',
  collection: 'com.example.note', rkey: 'one' };
const unsigned = { acceptSignature: null, kemKey: null, requireMac: false };
const link = CID.parse('bafkreigh2akiscaildcw453tj2mzyv4eicv7yqmx26iubepzwcndhy6eyu');

function block(value: unknown) {
  const bytes = encode(value as never);
  return { value: bytes, cid: CID.createV1(0x71, createDigest(0x12, sha256(bytes))).toString() };
}
function sameBytes(a: Uint8Array, b: Uint8Array) {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}
function isTooLarge(error: unknown) {
  return error instanceof SpaceRecordResponseError && error.code === 'ResponseTooLarge';
}
function captureError(fn: () => unknown): unknown {
  try { fn(); } catch (error) { return error; }
  throw new Error('Expected rejection');
}
function withTextBytes(size: number) {
  let low = 0, high = size;
  while (low <= high) {
    const length = Math.floor((low + high) / 2);
    const value = block({ $type: identity.collection, n: 9007199254740993n, text: 'x'.repeat(length) });
    if (value.value.byteLength === size) return value;
    if (value.value.byteLength < size) low = length + 1;
    else high = length - 1;
  }
  throw new Error('Unable to construct exact record size');
}
function withItems(items: number) {
  const base = block({ $type: identity.collection, n: 9007199254740993n, values: [] });
  const initial = inspectRecordCborDetails(base.value);
  if (initial.tag !== 'valid' || initial.items > items) throw new Error('Invalid item fixture');
  return block({ $type: identity.collection, n: 9007199254740993n, values: Array(items - initial.items).fill(0) });
}

Deno.test('lossless response retains signed integer locations and strict Lex special values', () => {
  const value = { $type: identity.collection, bounds: [9007199254740991, 9007199254740992n,
    9007199254740993n, -9007199254740991, -9007199254740992n, -9007199254740993n,
    9223372036854775807n, -9223372036854775808n], zero: 0,
    nested: [{ amount: 9007199254740993n }, { amount: 0 }], text: '9007199254740993',
    bytes: new Uint8Array([0, 255]), ref: link, blob: { $type: 'blob', ref: link, mimeType: 'text/plain', size: 2 } };
  const input = block(value);
  const serialized = serializeSpaceRecordValue(identity, input);
  expect(serialized.hasBigint).toBe(true);
  expect(serialized.valueJson).toContain('9007199254740993');
  expect(serialized.valueJson).toContain('-9223372036854775808');
  expect(serialized.valueJson).toContain(`"$link":"${link}"`);
  expect(serialized.valueJson).toContain('"$bytes":"AP8"');
  expect(sameBytes(encode(parseIntegerLex(serialized.valueJson) as never), input.value)).toBe(true);
  expect(createSpaceRecordResponse(identity, input, unsigned).body).toContain(serialized.valueJson);
  const swapped = serialized.valueJson.replace('"amount":9007199254740993', '"amount":"temporary"')
    .replace('"amount":0}', '"amount":9007199254740993}').replace('"amount":"temporary"', '"amount":0');
  expect(sameBytes(encode(parseIntegerLex(swapped) as never), input.value)).toBe(false);
});

Deno.test('lossless conversion retains the supported CIDv0 JSON spelling', () => {
  const cid0 = CID.parse('QmYwAPJzv5CZsnAzt8auVTLsbXzzhPP9LQfSAcZXd6aCxh');
  const input = block({ $type: identity.collection, n: 9007199254740993n, ref: cid0 });
  const output = serializeSpaceRecordValue(identity, input);
  expect(output.valueJson).toContain(`"$link":"${cid0}"`);
  expect(sameBytes(encode(parseIntegerLex(output.valueJson) as never), input.value)).toBe(true);
});

Deno.test('lossless parser rejects malformed numbers and reserved Lex values', () => {
  for (const value of ['9223372036854775808', '-9223372036854775809', '1.00000000000000001',
    '1e2', '-0', '01', '1.5', '1e999']) {
    expect(() => parseIntegerLex(`{"x":${value}}`)).toThrow();
  }
  for (const json of ['{"$link":"bad"}', `{ "\u0024link":"${link}", "extra":0 }`, '{"$bytes":"***"}', '{"$type":""}',
    '{"$type":"blob","ref":{"$link":"bad"},"mimeType":"x","size":1}',
    '{"nested":{"__proto__":"bad"}}']) {
    expect(() => parseIntegerLex(json)).toThrow();
  }
  const ambiguous = block({ $type: identity.collection, n: 9007199254740993n, nested: { $link: 'bad' } });
  expect(() => serializeSpaceRecordValue(identity, ambiguous)).toThrow();
  const unsupportedBlob = block({ $type: identity.collection, n: 9007199254740993n,
    blob: { $type: 'blob', ref: link, mimeType: 'text/plain', size: 9007199254740993n } });
  expect(() => serializeSpaceRecordValue(identity, unsupportedBlob)).toThrow();
});

Deno.test('canonical comparison rejects a bigint moved into a zero field', () => {
  const input = block({ $type: identity.collection, first: 9007199254740993n, second: 0 });
  const original = JSON.stringify;
  try {
    JSON.stringify = ((value: unknown, ...args: unknown[]) => {
      const result = Reflect.apply(original, JSON, [value, ...args]) as string;
      if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== null ||
        !Object.hasOwn(value, '$type')) return result;
      return result.replace('"first":9007199254740993', '"first":0')
        .replace('"second":0', '"second":9007199254740993');
    }) as typeof JSON.stringify;
    expect(() => serializeSpaceRecordValue(identity, input)).toThrow();
  } finally {
    JSON.stringify = original;
  }
});

Deno.test('CBOR integer counts use both signed safe boundaries', () => {
  const bytes = block({ $type: identity.collection, n: [9007199254740991n, 9007199254740992n,
    -9007199254740991n, -9007199254740992n] }).value;
  const inspected = inspectRecordCborDetails(bytes);
  expect(inspected.tag === 'valid' && inspected.bigints === 2).toBe(true);
});

Deno.test('bigint records enforce the provisional byte, item, and count envelope', () => {
  const bytes = withTextBytes(MAX_INTEGER_PAGE_BYTES);
  const tooManyBytes = withTextBytes(MAX_INTEGER_PAGE_BYTES + 1);
  expect(serializeSpaceRecordValue(identity, bytes).hasBigint).toBe(true);
  expect(isTooLarge(captureError(() => serializeSpaceRecordValue(identity, tooManyBytes)))).toBe(true);
  const items = withItems(MAX_INTEGER_PAGE_ITEMS);
  const tooManyItems = withItems(MAX_INTEGER_PAGE_ITEMS + 1);
  expect(serializeSpaceRecordValue(identity, items).hasBigint).toBe(true);
  expect(isTooLarge(captureError(() => serializeSpaceRecordValue(identity, tooManyItems)))).toBe(true);
  for (const count of [MAX_INTEGER_PAGE_BIGINTS, MAX_INTEGER_PAGE_BIGINTS + 1]) {
    const value = block({ $type: identity.collection, values: Array(count).fill(9007199254740993n) });
    if (count === MAX_INTEGER_PAGE_BIGINTS) expect(serializeSpaceRecordValue(identity, value).hasBigint).toBe(true);
    else expect(isTooLarge(captureError(() => serializeSpaceRecordValue(identity, value)))).toBe(true);
  }
  const escaped = block({ $type: identity.collection, n: 9007199254740993n, text: '\0'.repeat(1_000_000) });
  expect(isTooLarge(captureError(() => serializeSpaceRecordValue(identity, escaped)))).toBe(true);
});

Deno.test('bigint response fails closed when raw JSON or numeric source text is unavailable', () => {
  const input = block({ $type: identity.collection, n: 9007199254740993n });
  const descriptor = Object.getOwnPropertyDescriptor(JSON, 'rawJSON');
  if (!descriptor) throw new Error('Test runtime lacks JSON.rawJSON');
  try {
    Object.defineProperty(JSON, 'rawJSON', { ...descriptor, value: undefined });
    expect(() => serializeSpaceRecordValue(identity, input)).toThrow();
  } finally {
    Object.defineProperty(JSON, 'rawJSON', descriptor);
  }
  const original = JSON.parse;
  try {
    JSON.parse = ((text: string, reviver?: (key: string, value: unknown) => unknown) =>
      original(text, function (key, value) { return reviver?.call(this, key, value); })) as typeof JSON.parse;
    expect(() => serializeSpaceRecordValue(identity, input)).toThrow();
  } finally {
    JSON.parse = original;
  }
});

Deno.test('bigint JSON byte limit bounds serializer output before parsing', () => {
  const input = block({ $type: identity.collection, n: 9007199254740993n });
  const original = JSON.stringify;
  const prefix = '{"n":9007199254740993,"padding":"', suffix = '"}';
  let output = prefix + 'x'.repeat(MAX_INTEGER_JSON_BYTES - prefix.length - suffix.length) + suffix;
  try {
    JSON.stringify = ((value: unknown, ...args: unknown[]) => {
      if (value && typeof value === 'object' && Object.getPrototypeOf(value) === null &&
        Object.hasOwn(value, '$type')) return output;
      return Reflect.apply(original, JSON, [value, ...args]);
    }) as typeof JSON.stringify;
    const exact = captureError(() => serializeSpaceRecordValue(identity, input));
    expect(exact instanceof SpaceRecordResponseError && exact.code === 'InvalidRecord').toBe(true);
    output = prefix + 'x'.repeat(MAX_INTEGER_JSON_BYTES - prefix.length - suffix.length + 1) + suffix;
    expect(isTooLarge(captureError(() => serializeSpaceRecordValue(identity, input)))).toBe(true);
  } finally {
    JSON.stringify = original;
  }
});

Deno.test('bigint conversion does not invoke inherited serialization hooks', () => {
  const input = block({ $type: identity.collection, n: 9007199254740993n });
  let called = false;
  let response: string | undefined;
  Object.defineProperty(Object.prototype, 'toJSON', { configurable: true, get() { called = true; return () => 'bad'; } });
  try {
    response = serializeSpaceRecordValue(identity, input).valueJson;
  } finally {
    delete (Object.prototype as { toJSON?: unknown }).toJSON;
  }
  expect(called).toBe(false);
  expect(response).toContain('"n":9007199254740993');
});

Deno.test('lossless parsing ignores inherited Lex keys without invoking getters', () => {
  let called = false;
  let result: unknown;
  Object.defineProperty(Object.prototype, '$link', { configurable: true, get() { called = true; return 'bad'; } });
  try {
    result = parseIntegerLex('{"ok":1}');
  } finally {
    delete (Object.prototype as { $link?: unknown }).$link;
  }
  expect(called).toBe(false);
  expect((result as { ok: number }).ok).toBe(1);
});

Deno.test('bigint and CID toJSON getters never run in the bigint response path', () => {
  const input = block({ $type: identity.collection, n: 9007199254740993n, ref: link,
    blob: { $type: 'blob', ref: link, mimeType: 'text/plain', size: 2 } });
  for (const prototype of [BigInt.prototype, CID.prototype]) {
    let called = false;
    let response: string | undefined;
    const previous = Object.getOwnPropertyDescriptor(prototype, 'toJSON');
    Object.defineProperty(prototype, 'toJSON', { configurable: true, get() { called = true; return () => 'bad'; } });
    try {
      response = serializeSpaceRecordValue(identity, input).valueJson;
    } finally {
      if (previous) Object.defineProperty(prototype, 'toJSON', previous);
      else Reflect.deleteProperty(prototype, 'toJSON');
    }
    expect(called).toBe(false);
    expect(response).toContain('"n":9007199254740993');
    expect(response).toContain(`"$link":"${link}"`);
  }
});

Deno.test('lossless parsing requires own typed-blob fields without inherited getters', () => {
  const fields: Record<string, unknown> = { $type: 'blob', ref: { $link: link.toString() }, mimeType: 'text/plain', size: 2 };
  for (const missing of ['ref', 'mimeType', 'size']) {
    const input = { ...fields };
    delete input[missing];
    const text = JSON.stringify(input);
    const encoded = block({ $type: identity.collection, n: 9007199254740993n, blob: input });
    let called = false;
    let error: unknown;
    let responseError: unknown;
    Object.defineProperty(Object.prototype, missing, { configurable: true, get() { called = true; return fields[missing]; } });
    try {
      try { parseIntegerLex(text); } catch (cause) { error = cause; }
      try { serializeSpaceRecordValue(identity, encoded); } catch (cause) { responseError = cause; }
    } finally {
      Reflect.deleteProperty(Object.prototype, missing);
    }
    expect(error instanceof Error).toBe(true);
    expect(responseError instanceof Error).toBe(true);
    expect(called).toBe(false);
  }
  const text = JSON.stringify({ ref: { $link: link.toString() }, mimeType: 'text/plain', size: 2 });
  let called = false;
  let parsed: unknown;
  Object.defineProperty(Object.prototype, '$type', { configurable: true, get() { called = true; return 'blob'; } });
  try {
    parsed = parseIntegerLex(text);
  } finally {
    Reflect.deleteProperty(Object.prototype, '$type');
  }
  expect(called).toBe(false);
  expect(!!parsed && typeof parsed === 'object' && !Object.hasOwn(parsed, '$type')).toBe(true);
});

Deno.test('bigint transformation does not duck-type ordinary maps or traverse cycles', () => {
  const value = { $type: identity.collection, n: 9007199254740993n, nested: { text: 'value' }, ref: link };
  let called = false;
  let output: string | undefined;
  Object.defineProperty(Object.prototype, 'asCID', { configurable: true, get() { called = true; throw new Error('getter'); } });
  try {
    output = stringifyIntegerLex(value);
  } finally {
    Reflect.deleteProperty(Object.prototype, 'asCID');
  }
  expect(called).toBe(false);
  expect(output).toContain('"n":9007199254740993');
  const cyclic: Record<string, unknown> = { n: 9007199254740993n };
  cyclic.self = cyclic;
  expect(() => stringifyIntegerLex(cyclic)).toThrow();
  expect(() => stringifyIntegerLex({ values: Array(MAX_INTEGER_PAGE_ITEMS).fill(1), n: 9007199254740993n })).toThrow();
  expect(() => stringifyIntegerLex({ text: 'x'.repeat(MAX_INTEGER_PAGE_BYTES + 1), n: 9007199254740993n })).toThrow();
  expect(() => stringifyIntegerLex({ values: Array(MAX_INTEGER_PAGE_BIGINTS + 1).fill(9007199254740993n) })).toThrow();
});

Deno.test('lossless conversion preserves bounded nesting', () => {
  let nested: unknown = 9007199254740993n;
  for (let index = 0; index < 95; index++) nested = [nested];
  const value = block({ $type: identity.collection, nested });
  const output = serializeSpaceRecordValue(identity, value);
  expect(sameBytes(encode(parseIntegerLex(output.valueJson) as never), value.value)).toBe(true);
  for (let index = 0; index < 10; index++) nested = [nested];
  expect(() => serializeSpaceRecordValue(identity, block({ $type: identity.collection, nested }))).toThrow();
});

Deno.test('safe-integer serializer remains byte-identical', () => {
  const input = block({ $type: identity.collection, n: 9007199254740991, bytes: new Uint8Array([2]), ref: link });
  const result = serializeSpaceRecordValue(identity, input);
  expect(result.hasBigint).toBeUndefined();
  expect(sameBytes(encode(lexParse(result.valueJson, { strict: true })), input.value)).toBe(true);
  expect(() => stringifyIntegerLex({ n: 9223372036854775808n })).toThrow();
});
