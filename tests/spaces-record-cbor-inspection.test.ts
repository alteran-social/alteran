import { expect } from '@std/expect';
import * as dagCbor from '@ipld/dag-cbor';
import {
  checkRecordCborBounds, inspectRecordCborBounds, MAX_RECORD_CBOR_ITEMS,
} from '../src/lib/spaces/record-cbor-bounds';

function nullArray(length: number): Uint8Array {
  const headerLength = length <= 0xffff ? 3 : 5;
  const bytes = new Uint8Array(headerLength + length);
  bytes[0] = headerLength === 3 ? 0x99 : 0x9a;
  if (headerLength === 3) new DataView(bytes.buffer).setUint16(1, length);
  else new DataView(bytes.buffer).setUint32(1, length);
  bytes.fill(0xf6, headerLength);
  return bytes;
}

Deno.test('record CBOR inspection counts containers, map keys and tagged values', () => {
  const cases: { readonly value: Uint8Array; readonly items: number }[] = [
    { value: Uint8Array.of(0xf6), items: 1 },
    { value: Uint8Array.of(0x83, 0xf5, 0x01, 0xf6), items: 4 },
    { value: dagCbor.encode({ a: [1, 'x'], b: { c: false } }), items: 9 },
    { value: Uint8Array.of(0xd8, 0x2a, 0x41, 0x00), items: 2 },
  ];
  for (const { value, items } of cases) {
    expect(inspectRecordCborBounds(value)).toEqual({ tag: 'valid', items });
    expect(checkRecordCborBounds(value)).toBe('valid');
  }
});

Deno.test('record CBOR inspection supports a caller-owned aggregate item budget', () => {
  const half = inspectRecordCborBounds(nullArray(65_535));
  if (half.tag !== 'valid') throw new Error('Expected a valid half-budget record');
  expect(half.items).toBe(65_536);
  expect(half.items * 2).toBe(MAX_RECORD_CBOR_ITEMS);
  expect(inspectRecordCborBounds(nullArray(65_535), half.items)).toEqual(half);
  expect(inspectRecordCborBounds(nullArray(65_535), half.items - 1)).toEqual({ tag: 'unsupported' });
  expect(inspectRecordCborBounds(Uint8Array.of(0xf6), 0)).toEqual({ tag: 'unsupported' });
  for (const limit of [-1, MAX_RECORD_CBOR_ITEMS + 1, NaN]) {
    expect(inspectRecordCborBounds(Uint8Array.of(0xf6), limit)).toEqual({ tag: 'invalid' });
  }
  const full = inspectRecordCborBounds(nullArray(MAX_RECORD_CBOR_ITEMS - 1));
  expect(full).toEqual({ tag: 'valid', items: MAX_RECORD_CBOR_ITEMS });
  const over = nullArray(MAX_RECORD_CBOR_ITEMS);
  expect(inspectRecordCborBounds(over)).toEqual({ tag: 'unsupported' });
  expect(checkRecordCborBounds(over)).toBe('unsupported');
});

Deno.test('record CBOR inspection preserves invalid and unsupported classification', () => {
  for (const bytes of [
    Uint8Array.of(), Uint8Array.of(0xc1, 0x00), Uint8Array.of(0x58, 0x02, 0x00),
    Uint8Array.of(0x01, 0x02), Uint8Array.of(0xf7), Uint8Array.of(0xff),
  ]) {
    expect(inspectRecordCborBounds(bytes)).toEqual({ tag: 'invalid' });
    expect(checkRecordCborBounds(bytes)).toBe('invalid');
  }
  let nested: unknown = null;
  for (let index = 0; index < 110; index++) nested = [nested];
  const deep = dagCbor.encode(nested);
  expect(inspectRecordCborBounds(deep)).toEqual({ tag: 'unsupported' });
  expect(checkRecordCborBounds(deep)).toBe('unsupported');
});
