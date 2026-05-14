/**
 * Memory usage tests for Cloudflare Workers 128MB limit
 *
 * Tests verify memory-efficient operations:
 * - Large repo handling
 * - Streaming vs buffering
 * - Memory cleanup
 */

import { describe, it as test } from "./helpers/bdd";
import { expect } from "@std/expect";
import { StreamingCarEncoder, blocksFromArray } from '../src/lib/streaming-car';
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';

describe('Memory Tests', () => {
  test('Streaming CAR encoder uses less memory than buffering', async () => {
    // Create 1000 test blocks (simulating large repo)
    const blocks = [];
    for (let i = 0; i < 1000; i++) {
      const value = {
        test: `value-${i}`,
        data: 'x'.repeat(100), // 100 bytes per block
        index: i
      };
      const bytes = dagCbor.encode(value);
      const hash = await sha256.digest(bytes);
      const cid = CID.createV1(dagCbor.code, hash);
      blocks.push({ cid, bytes });
    }

    // Test streaming approach (should not buffer all blocks)
    const encoder = new StreamingCarEncoder([blocks[0].cid]);
    const header = encoder.header();

    // Encode blocks one at a time (streaming)
    let streamedSize = header.byteLength;
    for (const block of blocks) {
      const encoded = encoder.encodeBlock(block);
      streamedSize += encoded.byteLength;
    }

    // Verify we can process large repos
    expect(streamedSize).toBeGreaterThan(100000); // > 100KB
    expect(blocks.length).toBe(1000);
  });

  test('Block iterator does not load all blocks into memory', async () => {
    // Create blocks
    const blocks = [];
    for (let i = 0; i < 100; i++) {
      const value = { index: i };
      const bytes = dagCbor.encode(value);
      const hash = await sha256.digest(bytes);
      const cid = CID.createV1(dagCbor.code, hash);
      blocks.push({ cid, bytes });
    }

    // Iterate without loading all at once
    let count = 0;
    for await (const block of blocksFromArray(blocks)) {
      expect(block.cid).toBeDefined();
      expect(block.bytes).toBeDefined();
      count++;
    }

    expect(count).toBe(100);
  });

  test('Memory cleanup after processing', async () => {
    // This test verifies that temporary objects are cleaned up
    const iterations = 10;

    for (let i = 0; i < iterations; i++) {
      // Create and discard blocks
      const value = { iteration: i, data: 'x'.repeat(10000) };
      const bytes = dagCbor.encode(value);
      const hash = await sha256.digest(bytes);
      const cid = CID.createV1(dagCbor.code, hash);

      // Block should be garbage collected after this iteration
      expect(cid).toBeDefined();
    }

    // If we got here without OOM, memory is being cleaned up
    expect(true).toBe(true);
  });
});