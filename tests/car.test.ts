/**
 * CAR (Content Addressable aRchive) Tests
 * Tests for CAR v1 encoding, decoding, and spec compliance
 */

import { describe, it as test } from "./helpers/bdd";
import { expect } from "@std/expect";
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';

describe('CAR Implementation', () => {
  describe('CAR Encoding', () => {
    test('should encode record block with CIDv1', async () => {
      const { encodeRecordBlock } = await import('../src/services/car');

      const value = { text: 'Hello, world!', createdAt: new Date().toISOString() };
      const { cid, bytes } = await encodeRecordBlock(value);

      expect(cid).toBeDefined();
      expect(cid.version).toBe(1);
      expect(cid.code).toBe(dagCbor.code); // 0x71
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBeGreaterThan(0);
    });

    test('should produce deterministic CIDs for same content', async () => {
      const { encodeRecordBlock } = await import('../src/services/car');

      const value = { text: 'test', num: 42 };
      const block1 = await encodeRecordBlock(value);
      const block2 = await encodeRecordBlock(value);

      expect(block1.cid.toString()).toBe(block2.cid.toString());
      expect(block1.bytes).toEqual(block2.bytes);
    });

    test('should encode CAR header with version and roots', async () => {
      const { buildBlocksCar } = await import('../src/services/car');

      const values = [{ test: 'data' }];
      const car = await buildBlocksCar(values);

      expect(car.bytes).toBeInstanceOf(Uint8Array);
      expect(car.root).toBeDefined();
      expect(car.blocks).toHaveLength(1);
    });

    test('should encode multiple blocks in CAR', async () => {
      const { buildBlocksCar } = await import('../src/services/car');

      const values = [
        { text: 'first' },
        { text: 'second' },
        { text: 'third' },
      ];
      const car = await buildBlocksCar(values);

      expect(car.blocks).toHaveLength(3);
      expect(car.bytes.length).toBeGreaterThan(0);
    });
  });

  describe('CAR Reader', () => {
    test('should parse CAR header', async () => {
      const { parseCarHeader } = await import('../src/lib/car-reader');
      const { buildBlocksCar } = await import('../src/services/car');

      const values = [{ test: 'data' }];
      const car = await buildBlocksCar(values);

      const { header, offset } = parseCarHeader(car.bytes);

      expect(header.version).toBe(1);
      expect(header.roots).toHaveLength(1);
      expect(header.roots[0]).toBeInstanceOf(CID);
      expect(offset).toBeGreaterThan(0);
    });

    test('should parse CAR blocks', async () => {
      const { parseCarFile } = await import('../src/lib/car-reader');
      const { buildBlocksCar } = await import('../src/services/car');

      const values = [
        { text: 'first' },
        { text: 'second' },
      ];
      const car = await buildBlocksCar(values);

      const { header, blocks } = parseCarFile(car.bytes);

      expect(header.version).toBe(1);
      expect(blocks).toHaveLength(2);
      expect(blocks[0].cid).toBeInstanceOf(CID);
      expect(blocks[0].bytes).toBeInstanceOf(Uint8Array);
    });

    test('should validate block CID matches content', async () => {
      const { validateBlock } = await import('../src/lib/car-reader');
      const { encodeRecordBlock } = await import('../src/services/car');

      const value = { test: 'validation' };
      const block = await encodeRecordBlock(value);

      const isValid = await validateBlock(block);
      expect(isValid).toBe(true);
    });

    test('should detect invalid block CID', async () => {
      const { validateBlock } = await import('../src/lib/car-reader');
      const { encodeRecordBlock } = await import('../src/services/car');

      const value = { test: 'data' };
      const block = await encodeRecordBlock(value);

      // Create a different CID
      const wrongValue = { test: 'different' };
      const wrongBlock = await encodeRecordBlock(wrongValue);

      // Mix CID and bytes
      const invalidBlock = {
        cid: wrongBlock.cid,
        bytes: block.bytes,
      };

      const isValid = await validateBlock(invalidBlock);
      expect(isValid).toBe(false);
    });

    test('should round-trip encode and decode', async () => {
      const { parseCarFile } = await import('../src/lib/car-reader');
      const { buildBlocksCar } = await import('../src/services/car');

      const originalValues = [
        { text: 'hello', num: 1 },
        { text: 'world', num: 2 },
      ];

      // Encode
      const car = await buildBlocksCar(originalValues);

      // Decode
      const { blocks } = parseCarFile(car.bytes);

      // Verify
      expect(blocks).toHaveLength(2);

      const decoded0 = dagCbor.decode(blocks[0].bytes);
      const decoded1 = dagCbor.decode(blocks[1].bytes);

      expect(decoded0).toEqual(originalValues[0]);
      expect(decoded1).toEqual(originalValues[1]);
    });
  });

  describe('CAR Spec Compliance', () => {
    test('should use varint for length encoding', async () => {
      const { buildBlocksCar } = await import('../src/services/car');

      const values = [{ test: 'data' }];
      const car = await buildBlocksCar(values);

      // First byte should be a varint (header length)
      expect(car.bytes[0]).toBeLessThan(0x80); // Single-byte varint for small header
    });

    test('should encode header as dag-cbor', async () => {
      const { parseCarHeader } = await import('../src/lib/car-reader');
      const { buildBlocksCar } = await import('../src/services/car');

      const values = [{ test: 'data' }];
      const car = await buildBlocksCar(values);

      const { header } = parseCarHeader(car.bytes);

      // Header should have version 1 and roots array
      expect(header).toHaveProperty('version', 1);
      expect(header).toHaveProperty('roots');
      expect(Array.isArray(header.roots)).toBe(true);
    });

    test('should use CIDv1 with dag-cbor codec', async () => {
      const { encodeRecordBlock } = await import('../src/services/car');

      const value = { test: 'cid-version' };
      const { cid } = await encodeRecordBlock(value);

      expect(cid.version).toBe(1);
      expect(cid.code).toBe(0x71); // dag-cbor codec
    });

    test('should use sha2-256 hash', async () => {
      const { encodeRecordBlock } = await import('../src/services/car');

      const value = { test: 'hash-function' };
      const { cid } = await encodeRecordBlock(value);

      expect(cid.multihash.code).toBe(0x12); // sha2-256
    });
  });

  describe('CAR Memory Usage', () => {
    test('should handle large number of blocks', async () => {
      const { buildBlocksCar } = await import('../src/services/car');

      // Create 100 blocks
      const values = Array.from({ length: 100 }, (_, i) => ({
        index: i,
        text: `Block ${i}`,
        data: 'x'.repeat(100),
      }));

      const car = await buildBlocksCar(values);

      expect(car.blocks).toHaveLength(100);
      expect(car.bytes.length).toBeGreaterThan(0);

      // Verify memory usage is reasonable (< 1MB for this test)
      expect(car.bytes.length).toBeLessThan(1024 * 1024);
    });
  });

  describe('Repo CAR Building', () => {
    test('should build repo CAR with commit', async () => {
      // This would require mocking D1 database
      // Placeholder for integration test
      const { buildRepoCar } = await import('../src/services/car');
      expect(buildRepoCar).toBeDefined();
    });

    test('should build repo CAR range', async () => {
      // This would require mocking D1 database
      // Placeholder for integration test
      const { buildRepoCarRange } = await import('../src/services/car');
      expect(buildRepoCarRange).toBeDefined();
    });
  });
});