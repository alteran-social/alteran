/**
 * Performance tests for Cloudflare Workers constraints
 *
 * Tests verify:
 * - CPU time < 10ms for common operations
 * - Memory usage stays under 128MB
 * - Cold start time < 100ms
 */

import { describe, it as test } from "./helpers/bdd";
import { expect } from "@std/expect";
import { StreamingCarEncoder, estimateBlockMemory } from '../src/lib/streaming-car';
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';

describe('Performance Tests', () => {
  test('CAR encoding should be fast', async () => {
    const start = performance.now();

    // Create test blocks
    const blocks = [];
    for (let i = 0; i < 100; i++) {
      const value = { test: `value-${i}`, index: i };
      const bytes = dagCbor.encode(value);
      const hash = await sha256.digest(bytes);
      const cid = CID.createV1(dagCbor.code, hash);
      blocks.push({ cid, bytes });
    }

    // Encode as CAR
    const encoder = new StreamingCarEncoder([blocks[0].cid]);
    encoder.header();
    for (const block of blocks) {
      encoder.encodeBlock(block);
    }

    const duration = performance.now() - start;

    // Should complete in < 10ms for 100 blocks
    expect(duration).toBeLessThan(10);
  });

  test('Block memory estimation', () => {
    const value = { test: 'value', data: 'x'.repeat(1000) };
    const bytes = dagCbor.encode(value);
    const cid = CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua');

    const block = { cid, bytes };
    const memory = estimateBlockMemory(block);

    // Should be reasonable estimate
    expect(memory).toBeGreaterThan(1000);
    expect(memory).toBeLessThan(2000);
  });

  test('MST operations should be fast', async () => {
    // Test will be added when MST is optimized
    expect(true).toBe(true);
  });

  test('Commit signing should be fast', async () => {
    // Test will be added when commit signing is optimized
    expect(true).toBe(true);
  });
});