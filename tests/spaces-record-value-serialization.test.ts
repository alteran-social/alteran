import { expect } from '@std/expect';
import { P256Keypair } from '@atproto/crypto-spaces';
import { encode } from '@atproto/lex-cbor';
import { decapsulate, encapsulate, formatMacRequest, RECORD_MAC_PROFILE, verifyRecordMac } from '@atproto/space';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { createSpaceRecordResponse, serializeSpaceRecordValue } from '../src/lib/spaces/record-response';

const identity = {
  space: 'at://did:example:authority/space/com.example.notes/room',
  repo: 'did:example:writer', collection: 'com.example.note', rkey: 'one',
};
const uri = `${identity.space}/${identity.repo}/${identity.collection}/${identity.rkey}`;
const unsigned = { acceptSignature: null, kemKey: null, requireMac: false };

function record(value: unknown) {
  const bytes = encode(value as never);
  return { value: bytes, cid: CID.createV1(0x71, createDigest(0x12, sha256(bytes))).toString() };
}

Deno.test('record value serializer produces the existing unsigned response bytes', () => {
  const input = record({ $type: identity.collection, text: 'example' });
  const serialized = serializeSpaceRecordValue(identity, input);
  expect(serialized).toEqual({
    uri, cid: input.cid, valueJson: '{"text":"example","$type":"com.example.note"}',
  });
  const expected = `{"uri":${JSON.stringify(uri)},"cid":${JSON.stringify(input.cid)},"value":${serialized.valueJson}}`;
  const response = createSpaceRecordResponse(identity, input, unsigned);
  expect(response.body).toBe(expected);
  expect(response.headers).toEqual({
    'content-type': 'application/json', 'cache-control': 'private, no-store', vary: 'Accept-Signature',
  });
  expect(serializeSpaceRecordValue(identity, { ...input, rev: '3n2a5tw2wd22l' })).toEqual(serialized);
});

Deno.test('record value serializer preserves Lex links, bytes and signed response identity', async () => {
  const link = CID.parse('bafkreigh2akiscaildcw453tj2mzyv4eicv7yqmx26iubepzwcndhy6eyu');
  const input = record({ $type: identity.collection, nested: { link }, bytes: new Uint8Array([0, 255]) });
  const serialized = serializeSpaceRecordValue(identity, input);
  expect(JSON.parse(serialized.valueJson)).toEqual({
    $type: identity.collection, nested: { link: { $link: link.toString() } }, bytes: { $bytes: 'AP8' },
  });
  const keypair = await P256Keypair.create();
  const shared = await encapsulate(keypair.did() as `did:${string}:${string}`);
  const acceptSignature = formatMacRequest(RECORD_MAC_PROFILE, shared.keyShare);
  const kemKey = { publicDidKey: keypair.did(), deriveSharedSecret: (share: string) =>
    decapsulate(keypair, share as `did:${string}:${string}`) };
  const signed = createSpaceRecordResponse(identity, input, { acceptSignature, kemKey, requireMac: true });
  const plain = createSpaceRecordResponse(identity, input, unsigned);
  expect(signed.body).toBe(plain.body);
  expect(JSON.parse(signed.body).value).toEqual(JSON.parse(serialized.valueJson));
  verifyRecordMac(serialized.uri, CID.parse(serialized.cid), { ...shared, headers: new Headers(signed.headers) });
});

Deno.test('record value serializer validates identity, CID, type and Lex JSON round-trip', () => {
  const input = record({ $type: identity.collection, text: 'example' });
  const other = record({ $type: identity.collection, text: 'different' });
  expect(() => serializeSpaceRecordValue({ ...identity, rkey: '..' }, input)).toThrow();
  expect(() => serializeSpaceRecordValue(identity, { ...input, cid: other.cid })).toThrow();
  expect(() => serializeSpaceRecordValue(identity, { ...input, rev: 'bad' })).toThrow();
  expect(() => serializeSpaceRecordValue(identity, record({ $type: 'com.example.other' }))).toThrow();
  expect(() => serializeSpaceRecordValue(identity, record({ $type: identity.collection, n: 9007199254740992n }))).toThrow();
  expect(() => serializeSpaceRecordValue(identity, record({ $type: identity.collection, nested: { $link: 'bad' } }))).toThrow();
});

Deno.test('record value serializer preserves bounded worst-case JSON escaping', () => {
  const text = '\0'.repeat(1_000_000);
  const input = record({ $type: identity.collection, text });
  const serialized = serializeSpaceRecordValue(identity, input);
  expect(serialized.valueJson.length).toBeGreaterThan(5_000_000);
  expect(new TextEncoder().encode(serialized.valueJson).byteLength).toBeLessThan(16 * 1024 * 1024);
  expect((JSON.parse(serialized.valueJson) as { text: string }).text).toBe(text);
  expect(createSpaceRecordResponse(identity, input, unsigned).body).toContain(serialized.valueJson);
});
