import { describe, it as test, beforeAll } from "./helpers/bdd";
import { expect } from "@std/expect";
import { MST, Leaf, D1Blockstore } from '../src/lib/mst';
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';

describe('MST (Merkle Search Tree)', () => {
  let mockEnv: any;
  let blockstore: D1Blockstore;

  beforeAll(() => {
    // Mock environment for testing
    mockEnv = {
      ALTERAN_DB: {
        // Mock D1 database
        prepare: () => ({
          bind: () => ({
            run: async () => ({ success: true }),
            all: async () => ({ results: [] }),
            first: async () => null,
          }),
        }),
        exec: async () => {},
      },
    };
    blockstore = new D1Blockstore(mockEnv);
  });

  test('should create empty MST', async () => {
    const mst = await MST.create(blockstore, []);
    const entries = await mst.getEntries();
    expect(entries).toEqual([]);
  });

  test('should add a leaf to empty MST', async () => {
    const mst = await MST.create(blockstore, []);
    const testCid = CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua');

    const updated = await mst.add('app.bsky.feed.post/abc123', testCid);
    const value = await updated.get('app.bsky.feed.post/abc123');

    expect(value?.toString()).toBe(testCid.toString());
  });

  test('should maintain sorted order', async () => {
    const mst = await MST.create(blockstore, []);
    const cid1 = CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua');
    const cid2 = CID.parse('bafyreibvjvcv745gig4mvqs4hctx4zfkono4rjejm2ta6gtyzkqxfjeily');

    let updated = await mst.add('app.bsky.feed.post/zzz', cid1);
    updated = await updated.add('app.bsky.feed.post/aaa', cid2);

    const leaves = await updated.list();
    expect(leaves[0].key).toBe('app.bsky.feed.post/aaa');
    expect(leaves[1].key).toBe('app.bsky.feed.post/zzz');
  });

  test('should delete a leaf', async () => {
    const mst = await MST.create(blockstore, []);
    const testCid = CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua');

    let updated = await mst.add('app.bsky.feed.post/abc123', testCid);
    updated = await updated.delete('app.bsky.feed.post/abc123');

    const value = await updated.get('app.bsky.feed.post/abc123');
    expect(value).toBeNull();
  });

  test('should update a leaf', async () => {
    const mst = await MST.create(blockstore, []);
    const cid1 = CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua');
    const cid2 = CID.parse('bafyreibvjvcv745gig4mvqs4hctx4zfkono4rjejm2ta6gtyzkqxfjeily');

    let updated = await mst.add('app.bsky.feed.post/abc123', cid1);
    updated = await updated.update('app.bsky.feed.post/abc123', cid2);

    const value = await updated.get('app.bsky.feed.post/abc123');
    expect(value?.toString()).toBe(cid2.toString());
  });

  test('should list with prefix', async () => {
    const mst = await MST.create(blockstore, []);
    const testCid = CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua');

    let updated = await mst.add('app.bsky.feed.post/1', testCid);
    updated = await updated.add('app.bsky.feed.post/2', testCid);
    updated = await updated.add('app.bsky.feed.like/1', testCid);

    const posts = await updated.listWithPrefix('app.bsky.feed.post/');
    expect(posts.length).toBe(2);
    expect(posts[0].key).toBe('app.bsky.feed.post/1');
    expect(posts[1].key).toBe('app.bsky.feed.post/2');
  });

  test('should calculate deterministic CID', async () => {
    const mst1 = await MST.create(blockstore, []);
    const mst2 = await MST.create(blockstore, []);
    const testCid = CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua');

    const updated1 = await mst1.add('app.bsky.feed.post/abc', testCid);
    const updated2 = await mst2.add('app.bsky.feed.post/abc', testCid);

    const cid1 = await updated1.getPointer();
    const cid2 = await updated2.getPointer();

    expect(cid1.toString()).toBe(cid2.toString());
  });
});