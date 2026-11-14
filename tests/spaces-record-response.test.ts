import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { P256Keypair } from '@atproto/crypto-spaces';
import { encode } from '@atproto/lex-cbor';
import { lexParse } from '@atproto/lex-json';
import { COMMIT_MAC_PROFILE, encapsulate, formatMacRequest, RECORD_MAC_PROFILE, verifyRecord, verifyRecordMac } from '@atproto/space';
import { isSpaceAtUriString, SpaceRef } from '@atproto/syntax-spaces';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { createSpaceRecordResponse, verifySpaceRecordResponseMac } from '../src/lib/spaces/record-response';
import { loadSpaceKemKey } from '../src/lib/spaces/kem-key';
import type { Env } from '../src/env';

const IDENTITY = { space: 'at://did:example:authority/space/com.example.forum/topic', repo: 'did:example:writer',
  collection: 'com.example.post', rkey: 'one' } as const;
const LINK = CID.parse('bafkreigh2akiscaildcw453tj2mzyv4eicv7yqmx26iubepzwcndhy6eyu');
const value = { $type: IDENTITY.collection, text: 'example', bytes: new Uint8Array([0, 255]),
  nested: [{ link: LINK }], blob: { $type: 'blob', ref: LINK, mimeType: 'application/octet-stream', size: 2 } };
function block(input: unknown = value) {
  const bytes = encode(input as never);
  return { value: bytes, cid: CID.createV1(0x71, createDigest(0x12, sha256(bytes))).toString() };
}
const unsigned = { acceptSignature: null, kemKey: null, requireMac: false };
async function fixture() {
  const privateKey = await (await P256Keypair.create({ exportable: true })).export();
  const configured = [...privateKey].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  privateKey.fill(0);
  const loaded = await loadSpaceKemKey({ PDS_SPACE_KEM_KEY: configured } as Env);
  if (loaded.tag !== 'ready') throw new Error('KEM capability unavailable');
  const keypair = loaded.key;
  const shared = await encapsulate(keypair.publicDidKey as `did:${string}:${string}`);
  const request = formatMacRequest(RECORD_MAC_PROFILE, shared.keyShare);
  return { keypair, shared, request };
}

describe('Space record response and MAC', () => {
  it('emits reference Lex JSON and a MAC verifiable by the official client', async () => {
    const { keypair, shared, request } = await fixture(), record = block();
    const response = createSpaceRecordResponse(IDENTITY, record, { acceptSignature: request, kemKey: keypair, requireMac: false });
    const readerShape = createSpaceRecordResponse(IDENTITY, { ...record, rev: '3n2a5tw2wd22l' }, unsigned);
    expect(JSON.parse(readerShape.body)).toEqual(JSON.parse(response.body));
    const uri = SpaceRef.parse(IDENTITY.space).recordUri(IDENTITY.repo, IDENTITY.collection, IDENTITY.rkey).toString();
    if (!isSpaceAtUriString(uri)) throw new Error('Invalid record URI');
    const body = JSON.parse(response.body);
    expect(body.uri).toBe(uri);
    expect(body.cid).toBe(record.cid);
    expect(body.value.bytes).toEqual({ $bytes: 'AP8' });
    expect(body.value.nested[0].link).toEqual({ $link: LINK.toString() });
    expect(body.value.blob.ref).toEqual({ $link: LINK.toString() });
    expect(response.headers['content-type']).toBe('application/json');
    expect(response.headers['cache-control']).toBe('private, no-store');
    expect(response.headers.vary).toBe('Accept-Signature');
    expect(response.headers['access-control-expose-headers']).toBe('atproto-space-record, signature-input, signature');
    const headers = new Headers(response.headers);
    const secretBefore = Uint8Array.from(shared.sharedSecret);
    expect(verifySpaceRecordResponseMac(IDENTITY, record.cid, headers, shared)).toBe(true);
    expect([...shared.sharedSecret]).toEqual([...secretBefore]);
    verifyRecordMac(uri, CID.parse(record.cid), { ...shared, headers });
    await verifyRecord(lexParse(response.body, { strict: true }) as never, { ...shared, headers, uri });
  });
  it('matches reference absence and unrelated-profile behavior and requires a MAC when requested by the caller', async () => {
    const { keypair, shared, request } = await fixture(), record = block();
    const response = createSpaceRecordResponse(IDENTITY, record, unsigned);
    expect(response.headers.vary).toBe('Accept-Signature');
    expect(response.headers.signature).toBeUndefined();
    expect(response.headers['access-control-expose-headers']).toBeUndefined();
    const unrelated = formatMacRequest(COMMIT_MAC_PROFILE, shared.keyShare);
    expect(createSpaceRecordResponse(IDENTITY, record, { acceptSignature: unrelated, kemKey: null, requireMac: false }).headers.signature).toBeUndefined();
    expect(() => createSpaceRecordResponse(IDENTITY, record, { acceptSignature: null, kemKey: null, requireMac: true })).toThrow();
    expect(() => createSpaceRecordResponse(IDENTITY, record, { acceptSignature: unrelated, kemKey: keypair, requireMac: true })).toThrow();
    expect(() => createSpaceRecordResponse(IDENTITY, record, { acceptSignature: request, kemKey: null, requireMac: false })).toThrow();
    const withTab = createSpaceRecordResponse(IDENTITY, record, { acceptSignature: `other=?1,\t${request}`, kemKey: keypair, requireMac: true });
    expect(verifySpaceRecordResponseMac(IDENTITY, record.cid, new Headers(withTab.headers), shared)).toBe(true);
    const sameLabel = createSpaceRecordResponse(IDENTITY, record, { acceptSignature: `${request}, ${request}`, kemKey: keypair, requireMac: true });
    expect(verifySpaceRecordResponseMac(IDENTITY, record.cid, new Headers(sameLabel.headers), shared)).toBe(true);
  });
  it('rejects malformed, duplicate, incompatible and oversized signature requests', async () => {
    const { keypair, shared, request } = await fixture(), record = block();
    const part = `("atproto-space-record";sf);keyid="${shared.keyShare}";tag="atproto-space-record"`;
    const invalid = ['???', `a=${part}, b=${part}`, `${request};created=1`, `${request};alg="ecdsa-p256-sha256"`,
      `mac=("atproto-space-record");keyid="${shared.keyShare}";tag="atproto-space-record"`,
      'mac=("atproto-space-record";sf);keyid="did:example:other";tag="atproto-space-record"',
      'x'.repeat(8193), `${request}\n`];
    for (const acceptSignature of invalid) {
      expect(() => createSpaceRecordResponse(IDENTITY, record, { acceptSignature, kemKey: keypair, requireMac: false })).toThrow();
    }
  });
  it('rejects wrong URI, CID, key, signature and covered headers', async () => {
    const { keypair, shared, request } = await fixture(), record = block();
    const response = createSpaceRecordResponse(IDENTITY, record, { acceptSignature: request, kemKey: keypair, requireMac: true });
    const headers = new Headers(response.headers), other = block({ $type: IDENTITY.collection, text: 'different' });
    expect(verifySpaceRecordResponseMac({ ...IDENTITY, rkey: 'other' }, record.cid, headers, shared)).toBe(false);
    expect(verifySpaceRecordResponseMac(IDENTITY, other.cid, headers, shared)).toBe(false);
    const wrongSecret = { ...shared, sharedSecret: new Uint8Array(32) };
    expect(verifySpaceRecordResponseMac(IDENTITY, record.cid, headers, wrongSecret)).toBe(false);
    const badHeader = new Headers(headers);
    badHeader.set('atproto-space-record', `uri="${IDENTITY.space}", cid="${record.cid}"`);
    expect(verifySpaceRecordResponseMac(IDENTITY, record.cid, badHeader, shared)).toBe(false);
    const badSignature = new Headers(headers); badSignature.set('signature', 'mac=:AAAAAAAA:');
    expect(verifySpaceRecordResponseMac(IDENTITY, record.cid, badSignature, shared)).toBe(false);
    const wrongKey = await fixture();
    expect(verifySpaceRecordResponseMac(IDENTITY, record.cid, headers, wrongKey.shared)).toBe(false);
    expect(verifySpaceRecordResponseMac(IDENTITY, record.cid, headers, { ...shared, sharedSecret: new Uint8Array(31) })).toBe(false);
  });
});
