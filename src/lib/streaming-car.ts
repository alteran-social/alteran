/**
 * Streaming CAR encoder for Cloudflare Workers
 *
 * This module provides memory-efficient streaming CAR encoding to stay within
 * the 128MB memory limit. Instead of buffering entire CAR files in memory,
 * blocks are streamed as they're read from storage.
 */

import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';

export interface Block {
  cid: CID;
  bytes: Uint8Array;
}

/**
 * Encode a varint (variable-length integer)
 */
function encodeVarint(n: number): Uint8Array {
  const bytes: number[] = [];
  while (n >= 0x80) {
    bytes.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  bytes.push(n);
  return new Uint8Array(bytes);
}

/**
 * Concatenate Uint8Arrays efficiently
 */
function concat(parts: Uint8Array[]): Uint8Array {
  const size = parts.reduce((n, p) => n + p.byteLength, 0);
  const buf = new Uint8Array(size);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.byteLength;
  }
  return buf;
}

/**
 * Create a streaming CAR encoder
 *
 * Usage:
 * ```typescript
 * const stream = createStreamingCarEncoder([rootCid]);
 * const readable = new ReadableStream({
 *   async start(controller) {
 *     controller.enqueue(stream.header());
 *     for await (const block of blocks) {
 *       controller.enqueue(stream.encodeBlock(block));
 *     }
 *     controller.close();
 *   }
 * });
 * ```
 */
// StreamingCarEncoder is a class because it caches the encoded header
// once and then writes one block at a time; the cache state plus the
// per-block writeBlock() method belong on the same object.
export class StreamingCarEncoder {
  private headerBytes: Uint8Array;

  constructor(roots: CID[]) {
    // Encode header once
    const header = dagCbor.encode({ version: 1, roots });
    const headerLength = encodeVarint(header.byteLength);
    this.headerBytes = concat([headerLength, header]);
  }

  /**
   * Get the CAR header bytes
   */
  header(): Uint8Array {
    return this.headerBytes;
  }

  /**
   * Encode a single block for streaming
   */
  encodeBlock(block: Block): Uint8Array {
    const blockData = concat([block.cid.bytes, block.bytes]);
    const blockLength = encodeVarint(blockData.byteLength);
    return concat([blockLength, blockData]);
  }
}

/**
 * Create a ReadableStream that encodes blocks as CAR format
 *
 * @param roots - Root CIDs for the CAR file
 * @param blockIterator - Async iterator that yields blocks
 * @returns ReadableStream of CAR-encoded bytes
 */
export function createCarStream(
  roots: CID[],
  blockIterator: AsyncIterable<Block>
): ReadableStream<Uint8Array> {
  const encoder = new StreamingCarEncoder(roots);
  let headerSent = false;

  return new ReadableStream({
    async start(controller) {
      try {
        // Send header first
        controller.enqueue(encoder.header());
        headerSent = true;

        // Stream blocks
        for await (const block of blockIterator) {
          controller.enqueue(encoder.encodeBlock(block));
        }

        controller.close();
      } catch (error) {
        controller.error(error);
      }
    },
  });
}

/**
 * Create a block iterator from an array (for compatibility)
 */
export async function* blocksFromArray(blocks: Block[]): AsyncIterable<Block> {
  for (const block of blocks) {
    yield block;
  }
}

/**
 * Estimate memory usage for a block
 */
export function estimateBlockMemory(block: Block): number {
  // CID bytes + block bytes + overhead
  return block.cid.bytes.byteLength + block.bytes.byteLength + 100;
}