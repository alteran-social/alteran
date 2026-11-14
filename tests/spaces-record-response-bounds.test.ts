import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { P256Keypair } from '@atproto/crypto-spaces';
import { encode } from '@atproto/lex-cbor';
import { decapsulate, encapsulate, formatMacRequest, RECORD_MAC_PROFILE } from '@atproto/space';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { createSpaceRecordResponse, SpaceRecordResponseError, verifySpaceRecordResponseMac } from '../src/lib/spaces/record-response';

const identity = { space: 'at://did:example:authority/space/com.example.forum/topic', repo: 'did:example:writer',
  collection: 'com.example.post', rkey: 'one' };
const unsigned = { acceptSignature: null, kemKey: null, requireMac: false };
function block(bytes: Uint8Array) { return { value: bytes, cid: CID.createV1(0x71, createDigest(0x12, sha256(bytes))).toString() }; }
function record(value: unknown) { return block(encode(value as never)); }
const valid = () => record({ $type: identity.collection, text: 'example' });

describe('bounded Space record responses', () => {
  it('rejects invalid identities, mismatched CIDs, malformed CBOR and wrong record types', () => {
    const good = valid();
    expect(() => createSpaceRecordResponse({ ...identity, space: `${identity.space}/` }, good, unsigned)).toThrow();
    expect(() => createSpaceRecordResponse({ ...identity, repo: 'not-a-did' }, good, unsigned)).toThrow();
    expect(() => createSpaceRecordResponse({ ...identity, collection: 'bad' }, good, unsigned)).toThrow();
    expect(() => createSpaceRecordResponse({ ...identity, rkey: '..' }, good, unsigned)).toThrow();
    expect(() => createSpaceRecordResponse(identity, { ...good, cid: record({ $type: identity.collection, text: 'other' }).cid }, unsigned)).toThrow();
    expect(() => createSpaceRecordResponse(identity, record({ $type: 'com.example.other' }), unsigned)).toThrow();
    const trailing = new Uint8Array(good.value.length + 1); trailing.set(good.value);
    expect(() => createSpaceRecordResponse(identity, block(trailing), unsigned)).toThrow();
    expect(() => createSpaceRecordResponse(identity, { ...good, value: new Uint8Array(1024 * 1024 + 1) }, unsigned)).toThrow();
  });
  it('rejects floats, unsafe integers and ambiguous Lex JSON before returning a body', () => {
    const float = dagCbor.encode({ $type: identity.collection, value: 1.5 });
    const unsafe = record({ $type: identity.collection, value: 9007199254740992n });
    const ambiguous = record({ $type: identity.collection, value: { $link: 'not-a-cid', extra: 'value' } });
    for (const input of [block(float), unsafe, ambiguous]) expect(() => createSpaceRecordResponse(identity, input, unsigned)).toThrow();
  });
  it('rejects CBOR exceeding the item or nesting budget before decode', () => {
    const many = record({ $type: identity.collection, values: Array.from({ length: 131_072 }, () => null) });
    expect(() => createSpaceRecordResponse(identity, many, unsigned)).toThrow();
    let nested: unknown = null;
    for (let i = 0; i < 101; i++) nested = [nested];
    expect(() => createSpaceRecordResponse(identity, record({ $type: identity.collection, nested }), unsigned)).toThrow();
  });
  it('bounds worst-case JSON escaping and preserves the value exactly', () => {
    const text = '\0'.repeat(1_000_000);
    const response = createSpaceRecordResponse(identity, record({ $type: identity.collection, text }), unsigned);
    expect(new TextEncoder().encode(response.body).byteLength).toBeLessThan(16 * 1024 * 1024);
    expect(response.body.length).toBeGreaterThan(5_000_000);
    expect(JSON.parse(response.body).value.text).toBe(text);
  });
  it('copies intrinsic byte views before signing and rejects detached or shared backing', async () => {
    const original = valid();
    class OddBytes extends Uint8Array {
      override get byteLength(): number { throw new Error('overridden byteLength'); }
      override [Symbol.iterator](): ReturnType<Uint8Array[typeof Symbol.iterator]> { throw new Error('overridden iterator'); }
    }
    const odd = new OddBytes(original.value.length);
    Uint8Array.prototype.set.call(odd, original.value);
    expect(JSON.parse(createSpaceRecordResponse(identity, { cid: original.cid, value: odd }, unsigned).body).value.text).toBe('example');
    const detached = Uint8Array.from(original.value);
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    expect(() => createSpaceRecordResponse(identity, { cid: original.cid, value: detached }, unsigned)).toThrow();
    if (typeof SharedArrayBuffer !== 'undefined') {
      const sharedBytes = new Uint8Array(new SharedArrayBuffer(original.value.length)); sharedBytes.set(original.value);
      expect(() => createSpaceRecordResponse(identity, { cid: original.cid, value: sharedBytes }, unsigned)).toThrow();
    }
    const keypair = await P256Keypair.create(), shared = await encapsulate(keypair.did() as `did:${string}:${string}`);
    const mutable = valid();
    const mutatingKey = { publicDidKey: keypair.did(), deriveSharedSecret: (keyShare: string) => {
      mutable.value.fill(0); return decapsulate(keypair, keyShare as `did:${string}:${string}`);
    } };
    const response = createSpaceRecordResponse(identity, mutable, { acceptSignature: formatMacRequest(RECORD_MAC_PROFILE, shared.keyShare),
      kemKey: mutatingKey, requireMac: true });
    expect(JSON.parse(response.body).value.text).toBe('example');
    expect(verifySpaceRecordResponseMac(identity, mutable.cid, new Headers(response.headers), shared)).toBe(true);
  });
  it('rejects accessors, oversized response headers and shared verification secrets', async () => {
    const good = valid();
    const unsafe = { ...good, get value(): Uint8Array { throw new Error('must not evaluate'); } };
    expect(() => createSpaceRecordResponse(identity, unsafe, unsigned)).toThrow();
    const keypair = await P256Keypair.create(), shared = await encapsulate(keypair.did() as `did:${string}:${string}`);
    const kemKey = { publicDidKey: keypair.did(), deriveSharedSecret: (keyShare: string) => decapsulate(keypair, keyShare as `did:${string}:${string}`) };
    const response = createSpaceRecordResponse(identity, good, { acceptSignature: formatMacRequest(RECORD_MAC_PROFILE, shared.keyShare), kemKey, requireMac: true });
    const headers = new Headers(response.headers); headers.set('signature', 'x'.repeat(8193));
    expect(verifySpaceRecordResponseMac(identity, good.cid, headers, shared)).toBe(false);
    if (typeof SharedArrayBuffer !== 'undefined') {
      const secret = new Uint8Array(new SharedArrayBuffer(32)); secret.set(shared.sharedSecret);
      expect(verifySpaceRecordResponseMac(identity, good.cid, new Headers(response.headers), { ...shared, sharedSecret: secret })).toBe(false);
    }
  });
  it('rejects invalid KEM capability output without mutating a borrowed secret', async () => {
    const keypair = await P256Keypair.create(), shared = await encapsulate(keypair.did() as `did:${string}:${string}`);
    const acceptSignature = formatMacRequest(RECORD_MAC_PROFILE, shared.keyShare);
    const detached = new Uint8Array(32);
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    const invalid: Array<() => Uint8Array> = [
      () => new Uint8Array(31),
      () => new Uint8Array(33),
      () => detached,
      () => { throw new Error('private capability error'); },
    ];
    if (typeof SharedArrayBuffer !== 'undefined') invalid.push(() => new Uint8Array(new SharedArrayBuffer(32)));
    for (const deriveSharedSecret of invalid) {
      let failure: unknown;
      try {
        createSpaceRecordResponse(identity, valid(), {
          acceptSignature, kemKey: { publicDidKey: keypair.did(), deriveSharedSecret }, requireMac: true,
        });
      } catch (error) { failure = error; }
      expect(failure).toBeInstanceOf(SpaceRecordResponseError);
      if (!(failure instanceof SpaceRecordResponseError)) throw new Error('Expected a sanitized MAC error');
      expect(failure.code).toBe('InvalidSpaceMac');
      expect(failure.message).not.toContain('private capability error');
    }
    const borrowed = Uint8Array.from(shared.sharedSecret);
    const response = createSpaceRecordResponse(identity, valid(), {
      acceptSignature, kemKey: { publicDidKey: keypair.did(), deriveSharedSecret: () => borrowed }, requireMac: true,
    });
    expect([...borrowed]).toEqual([...shared.sharedSecret]);
    expect(verifySpaceRecordResponseMac(identity, valid().cid, new Headers(response.headers), shared)).toBe(true);
  });
});
