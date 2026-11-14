import { expect } from '@std/expect';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { checkRecordCborBounds } from '../src/lib/spaces/record-cbor-bounds';
import { validSpaceRecordBlock } from '../src/db/space-record-block';
import { createLocalSpace } from '../src/db/space-store';
import { commitSpaceWrites, loadSpaceSnapshot } from '../src/db/space-mutation';
import { parseSpaceRef } from '../src/db/space-ref';

const DID = 'did:example:test';
const COLLECTION = 'com.example.note';
const SPACE = `at://${DID}/space/com.example.notes/cbor-bounds`;
const cid = (bytes: Uint8Array) => CID.createV1(0x71, createDigest(0x12, sha256(bytes))).toString();

describe('bounded Space record CBOR', () => {
  it('accepts ordinary canonical records and rejects floats with otherwise correct CIDs', () => {
    const valid = dagCbor.encode({ $type: COLLECTION, flag: true, data: [null, 2, 'hello'] });
    expect(checkRecordCborBounds(valid)).toBe('valid');
    expect(validSpaceRecordBlock(COLLECTION, cid(valid), valid)).toBe(true);
    const floating = dagCbor.encode({ $type: COLLECTION, n: 1.5 });
    expect(checkRecordCborBounds(floating)).toBe('invalid');
    expect(validSpaceRecordBlock(COLLECTION, cid(floating), floating)).toBe(false);
    // A float-valued 1.0 must not be accepted as an integer either.
    expect(checkRecordCborBounds(Uint8Array.from([0xf9, 0x3c, 0x00]))).toBe('invalid');
  });

  it('rejects wide and deeply nested data before decoding', () => {
    const wide = dagCbor.encode({ $type: COLLECTION, values: Array(131_072).fill(null) });
    expect(checkRecordCborBounds(wide)).toBe('unsupported');
    expect(validSpaceRecordBlock(COLLECTION, cid(wide), wide)).toBe(false);
    let nested: unknown = null;
    for (let index = 0; index < 110; index++) nested = [nested];
    const deep = dagCbor.encode({ $type: COLLECTION, nested });
    expect(checkRecordCborBounds(deep)).toBe('unsupported');
    expect(validSpaceRecordBlock(COLLECTION, cid(deep), deep)).toBe(false);
  });

  it('rejects invalid tags, truncated values, trailing data and unsupported simple values', () => {
    for (const bytes of [
      [0xc1, 0x00], [0x58, 0x02, 0x00], [0x01, 0x02], [0xf7], [0xff],
    ]) expect(checkRecordCborBounds(Uint8Array.from(bytes))).toBe('invalid');
  });

  it('rejects malformed special Lexicon values despite canonical encoding and a matching CID', () => {
    for (const malformed of [{ $link: 'not-a-cid' }, { $bytes: 'not-base64' }, { $type: '' }, { '': 1 }]) {
      const bytes = dagCbor.encode({ $type: COLLECTION, nested: malformed });
      expect(checkRecordCborBounds(bytes)).toBe('valid');
      expect(validSpaceRecordBlock(COLLECTION, cid(bytes), bytes)).toBe(false);
    }
  });

  it('refuses a complex pre-encoded write without changing the Space repo', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, SPACE);
    const bytes = dagCbor.encode({ $type: COLLECTION, values: Array(131_072).fill(null) });
    const write = { action: 'create' as const, collection: COLLECTION, rkey: 'one',
      cid: cid(bytes), value: bytes, blobs: [] };
    const ref = parseSpaceRef(SPACE);
    const snapshot = await loadSpaceSnapshot(env, ref, DID, [write]);
    await expect(commitSpaceWrites(env, ref, DID, [write], snapshot)).rejects.toThrow('overly complex');
    const malformed = dagCbor.encode({ $type: COLLECTION, nested: { $link: 'not-a-cid' } });
    await expect(commitSpaceWrites(env, ref, DID, [{ ...write, value: malformed, cid: cid(malformed) }], snapshot))
      .rejects.toThrow('data model');
    const count = await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS n FROM space_repo').first<{ n: number }>();
    expect(count?.n).toBe(0);
  });
});
