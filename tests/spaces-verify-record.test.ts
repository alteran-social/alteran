import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { encode } from '@atproto/lex-cbor';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { verifySpaceRecordBlock } from '../src/db/space-verify-record';

const collection = 'com.example.note';

function cidFor(bytes: Uint8Array): string {
  return CID.createV1(0x71, createDigest(0x12, sha256(bytes))).toString();
}

function verify(bytes: Uint8Array) {
  return verifySpaceRecordBlock(collection, 'a', cidFor(bytes), bytes);
}

describe('legacy space record verification', () => {
  it('accepts canonical records with bounded bytes and valid CID links', () => {
    const link = CID.createV1(0x55, createDigest(0x12, sha256(new Uint8Array([1, 2]))));
    const bytes = encode({ $type: collection, nested: [{ text: 'hello', link, bytes: new Uint8Array([1, 2]) }] });
    expect(verify(bytes)).toBe('valid');
    expect(verifySpaceRecordBlock(collection, 'a', cidFor(bytes), Uint8Array.from(bytes, (byte, index) => index === bytes.length - 1 ? byte ^ 1 : byte)))
      .toBe('invalid');
    expect(verifySpaceRecordBlock(collection, 'bad/key', cidFor(bytes), bytes)).toBe('invalid');
  });

  it('rejects noncanonical CBOR, floats, bad links and wrong record types', () => {
    const noncanonical = Uint8Array.from([
      0xa2, ...dagCbor.encode('$type'), ...dagCbor.encode(collection), ...dagCbor.encode('x'), ...dagCbor.encode(1),
    ]);
    expect(verify(noncanonical)).toBe('invalid');
    expect(verify(dagCbor.encode({ $type: collection, value: 1.5 }))).toBe('invalid');
    const badLink = CID.createV1(0x55, createDigest(0x13, new Uint8Array(64)));
    expect(verify(encode({ $type: collection, link: badLink }))).toBe('invalid');
    expect(verify(encode({ $type: 'com.example.other' }))).toBe('invalid');
    expect(verify(encode({ $type: collection, value: { $link: 'not-a-cid' } }))).toBe('invalid');
    expect(verify(encode({ $type: collection, value: { $type: 'not an nsid' } }))).toBe('valid');
    expect(verify(encode({ $type: collection, value: { $type: '' } }))).toBe('invalid');
    expect(verify(encode({ $type: collection, value: { $type: 'com.example.types#part' } }))).toBe('valid');
    expect(verify(encode({ $type: collection, value: { $type: 'com.example.types#main' } }))).toBe('valid');
  });

  it('keeps blob-bearing and excessively complex records unavailable', () => {
    const link = CID.createV1(0x55, createDigest(0x12, sha256(new Uint8Array([1]))));
    expect(verify(encode({ $type: collection, blob: { $type: 'blob', ref: link, mimeType: 'text/plain', size: 1 } })))
      .toBe('unsupported');
    expect(verify(encode({ $type: collection, legacy: { cid: link.toString(), mimeType: 'text/plain' } })))
      .toBe('unsupported');
    expect(verify(encode({ $type: collection, values: Array(131_072).fill(null) }))).toBe('unsupported');
  });

  it('does not accept a missing record type from a polluted prototype', () => {
    const bytes = encode({ text: 'missing type' });
    const original = Object.getOwnPropertyDescriptor(Object.prototype, '$type');
    try {
      Object.defineProperty(Object.prototype, '$type', { value: collection, configurable: true });
      expect(verify(bytes)).toBe('invalid');
    } finally {
      if (original) Object.defineProperty(Object.prototype, '$type', original);
      else Reflect.deleteProperty(Object.prototype, '$type');
    }
  });
});
