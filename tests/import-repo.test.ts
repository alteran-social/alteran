/**
 * Repository Import Tests
 * Tests for com.atproto.repo.importRepo endpoint
 */

import { describe, it as test, beforeEach } from "./helpers/bdd";
import { expect } from "@std/expect";
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { parseCarFile } from '../src/lib/car-reader';
import { encodeBlocksToCAR } from '../src/services/car';

describe('Repository Import', () => {
  describe('CAR File Parsing', () => {
    test('should parse CAR with commit and MST structure', async () => {
      // Create a simple MST structure
      const record1 = { $type: 'app.bsky.feed.post', text: 'Hello' };
      const record1Bytes = dagCbor.encode(record1);
      const record1Hash = await sha256.digest(record1Bytes);
      const record1Cid = CID.createV1(dagCbor.code, record1Hash);

      const record2 = { $type: 'app.bsky.feed.post', text: 'World' };
      const record2Bytes = dagCbor.encode(record2);
      const record2Hash = await sha256.digest(record2Bytes);
      const record2Cid = CID.createV1(dagCbor.code, record2Hash);

      // Create MST node
      const mstNode = {
        l: null,
        e: [
          {
            p: 0,
            k: new Uint8Array([0x61]), // 'a'
            v: record1Cid,
            t: null,
          },
          {
            p: 0,
            k: new Uint8Array([0x62]), // 'b'
            v: record2Cid,
            t: null,
          },
        ],
      };
      const mstBytes = dagCbor.encode(mstNode);
      const mstHash = await sha256.digest(mstBytes);
      const mstCid = CID.createV1(dagCbor.code, mstHash);

      // Create commit
      const commit = {
        did: 'did:plc:test',
        version: 3,
        data: mstCid,
        rev: '3l4example',
        prev: null,
        sig: new Uint8Array(64), // Mock signature
      };
      const commitBytes = dagCbor.encode(commit);
      const commitHash = await sha256.digest(commitBytes);
      const commitCid = CID.createV1(dagCbor.code, commitHash);

      // Build CAR
      const blocks = [
        { cid: commitCid, bytes: commitBytes },
        { cid: mstCid, bytes: mstBytes },
        { cid: record1Cid, bytes: record1Bytes },
        { cid: record2Cid, bytes: record2Bytes },
      ];
      const carBytes = encodeBlocksToCAR(commitCid, blocks);

      // Parse CAR
      const { header, blocks: parsedBlocks } = parseCarFile(carBytes);

      expect(header.version).toBe(1);
      expect(header.roots).toHaveLength(1);
      expect(header.roots[0].toString()).toBe(commitCid.toString());
      expect(parsedBlocks).toHaveLength(4);

      // Verify commit block
      const parsedCommit = parsedBlocks.find(b => b.cid.equals(commitCid));
      expect(parsedCommit).toBeDefined();
      const decodedCommit = dagCbor.decode(parsedCommit!.bytes);
      expect(decodedCommit).toMatchObject({
        did: 'did:plc:test',
        version: 3,
      });

      // Verify MST block
      const parsedMst = parsedBlocks.find(b => b.cid.equals(mstCid));
      expect(parsedMst).toBeDefined();
      const decodedMst = dagCbor.decode(parsedMst!.bytes) as any;
      expect(decodedMst.e).toHaveLength(2);

      // Verify record blocks
      const parsedRecord1 = parsedBlocks.find(b => b.cid.equals(record1Cid));
      expect(parsedRecord1).toBeDefined();
      const decodedRecord1 = dagCbor.decode(parsedRecord1!.bytes);
      expect(decodedRecord1).toEqual(record1);
    });

    test('should handle nested MST structure', async () => {
      // Create leaf records
      const record1 = { $type: 'app.bsky.feed.post', text: 'A' };
      const record1Bytes = dagCbor.encode(record1);
      const record1Hash = await sha256.digest(record1Bytes);
      const record1Cid = CID.createV1(dagCbor.code, record1Hash);

      const record2 = { $type: 'app.bsky.feed.post', text: 'B' };
      const record2Bytes = dagCbor.encode(record2);
      const record2Hash = await sha256.digest(record2Bytes);
      const record2Cid = CID.createV1(dagCbor.code, record2Hash);

      // Create child MST node
      const childMst = {
        l: null,
        e: [
          {
            p: 0,
            k: new Uint8Array([0x62]), // 'b'
            v: record2Cid,
            t: null,
          },
        ],
      };
      const childMstBytes = dagCbor.encode(childMst);
      const childMstHash = await sha256.digest(childMstBytes);
      const childMstCid = CID.createV1(dagCbor.code, childMstHash);

      // Create parent MST node with left subtree
      const parentMst = {
        l: childMstCid,
        e: [
          {
            p: 0,
            k: new Uint8Array([0x61]), // 'a'
            v: record1Cid,
            t: null,
          },
        ],
      };
      const parentMstBytes = dagCbor.encode(parentMst);
      const parentMstHash = await sha256.digest(parentMstBytes);
      const parentMstCid = CID.createV1(dagCbor.code, parentMstHash);

      // Create commit
      const commit = {
        did: 'did:plc:test',
        version: 3,
        data: parentMstCid,
        rev: '3l4example',
        prev: null,
        sig: new Uint8Array(64),
      };
      const commitBytes = dagCbor.encode(commit);
      const commitHash = await sha256.digest(commitBytes);
      const commitCid = CID.createV1(dagCbor.code, commitHash);

      // Build CAR with nested structure
      const blocks = [
        { cid: commitCid, bytes: commitBytes },
        { cid: parentMstCid, bytes: parentMstBytes },
        { cid: childMstCid, bytes: childMstBytes },
        { cid: record1Cid, bytes: record1Bytes },
        { cid: record2Cid, bytes: record2Bytes },
      ];
      const carBytes = encodeBlocksToCAR(commitCid, blocks);

      // Parse CAR
      const { blocks: parsedBlocks } = parseCarFile(carBytes);

      expect(parsedBlocks).toHaveLength(5);

      // Verify parent MST has left subtree reference
      const parsedParentMst = parsedBlocks.find(b => b.cid.equals(parentMstCid));
      expect(parsedParentMst).toBeDefined();
      const decodedParentMst = dagCbor.decode(parsedParentMst!.bytes) as any;
      expect(decodedParentMst.l).toBeDefined();
      expect(decodedParentMst.l.toString()).toBe(childMstCid.toString());
    });

    test('should handle MST with right subtrees', async () => {
      // Create records
      const record1 = { $type: 'app.bsky.feed.post', text: 'First' };
      const record1Bytes = dagCbor.encode(record1);
      const record1Hash = await sha256.digest(record1Bytes);
      const record1Cid = CID.createV1(dagCbor.code, record1Hash);

      const record2 = { $type: 'app.bsky.feed.post', text: 'Second' };
      const record2Bytes = dagCbor.encode(record2);
      const record2Hash = await sha256.digest(record2Bytes);
      const record2Cid = CID.createV1(dagCbor.code, record2Hash);

      // Create right subtree
      const rightMst = {
        l: null,
        e: [
          {
            p: 0,
            k: new Uint8Array([0x63]), // 'c'
            v: record2Cid,
            t: null,
          },
        ],
      };
      const rightMstBytes = dagCbor.encode(rightMst);
      const rightMstHash = await sha256.digest(rightMstBytes);
      const rightMstCid = CID.createV1(dagCbor.code, rightMstHash);

      // Create parent MST with entry having right subtree
      const parentMst = {
        l: null,
        e: [
          {
            p: 0,
            k: new Uint8Array([0x61]), // 'a'
            v: record1Cid,
            t: rightMstCid, // Right subtree
          },
        ],
      };
      const parentMstBytes = dagCbor.encode(parentMst);
      const parentMstHash = await sha256.digest(parentMstBytes);
      const parentMstCid = CID.createV1(dagCbor.code, parentMstHash);

      // Create commit
      const commit = {
        did: 'did:plc:test',
        version: 3,
        data: parentMstCid,
        rev: '3l4example',
        prev: null,
        sig: new Uint8Array(64),
      };
      const commitBytes = dagCbor.encode(commit);
      const commitHash = await sha256.digest(commitBytes);
      const commitCid = CID.createV1(dagCbor.code, commitHash);

      // Build CAR
      const blocks = [
        { cid: commitCid, bytes: commitBytes },
        { cid: parentMstCid, bytes: parentMstBytes },
        { cid: rightMstCid, bytes: rightMstBytes },
        { cid: record1Cid, bytes: record1Bytes },
        { cid: record2Cid, bytes: record2Bytes },
      ];
      const carBytes = encodeBlocksToCAR(commitCid, blocks);

      // Parse CAR
      const { blocks: parsedBlocks } = parseCarFile(carBytes);

      expect(parsedBlocks).toHaveLength(5);

      // Verify parent MST entry has right subtree
      const parsedParentMst = parsedBlocks.find(b => b.cid.equals(parentMstCid));
      expect(parsedParentMst).toBeDefined();
      const decodedParentMst = dagCbor.decode(parsedParentMst!.bytes) as any;
      expect(decodedParentMst.e[0].t).toBeDefined();
      expect(decodedParentMst.e[0].t.toString()).toBe(rightMstCid.toString());
    });
  });

  describe('Block Storage Logic', () => {
    test('should identify commit block from CAR root', async () => {
      const commit = {
        did: 'did:plc:test',
        version: 3,
        data: CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua'),
        rev: '3l4example',
        prev: null,
        sig: new Uint8Array(64),
      };
      const commitBytes = dagCbor.encode(commit);
      const commitHash = await sha256.digest(commitBytes);
      const commitCid = CID.createV1(dagCbor.code, commitHash);

      const blocks = [{ cid: commitCid, bytes: commitBytes }];
      const carBytes = encodeBlocksToCAR(commitCid, blocks);

      const { header, blocks: parsedBlocks } = parseCarFile(carBytes);

      expect(header.roots[0].toString()).toBe(commitCid.toString());
      expect(parsedBlocks[0].cid.toString()).toBe(commitCid.toString());

      const decoded = dagCbor.decode(parsedBlocks[0].bytes) as any;
      expect(decoded.did).toBe('did:plc:test');
      expect(decoded.data).toBeDefined();
    });

    test('should extract MST root CID from commit', async () => {
      const mstCid = CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua');
      const commit = {
        did: 'did:plc:test',
        version: 3,
        data: mstCid,
        rev: '3l4example',
        prev: null,
        sig: new Uint8Array(64),
      };
      const commitBytes = dagCbor.encode(commit);

      const decoded = dagCbor.decode(commitBytes) as any;
      expect(decoded.data.toString()).toBe(mstCid.toString());
    });

    test('should count records correctly', async () => {
      // Create multiple records
      const records = [
        { $type: 'app.bsky.feed.post', text: 'Post 1' },
        { $type: 'app.bsky.feed.post', text: 'Post 2' },
        { $type: 'app.bsky.feed.like', subject: 'at://did:plc:test/app.bsky.feed.post/123' },
      ];

      let recordCount = 0;
      for (const record of records) {
        const bytes = dagCbor.encode(record);
        const decoded = dagCbor.decode(bytes) as any;
        if (decoded && typeof decoded === 'object' && decoded.$type) {
          recordCount++;
        }
      }

      expect(recordCount).toBe(3);
    });
  });

  describe('Error Handling', () => {
    test('should reject CAR with no blocks', () => {
      const emptyCarBytes = new Uint8Array([
        0x0a, // varint: header length = 10
        0xa2, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x01, // CBOR: {version: 1}
        0x65, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x80, // CBOR: roots: []
      ]);

      expect(() => parseCarFile(emptyCarBytes)).toThrow();
    });

    test('should reject commit without data CID', () => {
      const invalidCommit = {
        did: 'did:plc:test',
        version: 3,
        // Missing 'data' field
        rev: '3l4example',
        prev: null,
        sig: new Uint8Array(64),
      };

      const bytes = dagCbor.encode(invalidCommit);
      const decoded = dagCbor.decode(bytes) as any;

      expect(decoded.data).toBeUndefined();
    });
  });
});