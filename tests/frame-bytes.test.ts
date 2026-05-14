import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { createInfoFrame, createCommitFrame } from '../src/lib/firehose/frames';
import { CID } from 'multiformats/cid';

describe('Firehose framed bytes', () => {
  it('prefixes frames with 4-byte big-endian length', () => {
    const frame = createInfoFrame('hello', 'world');
    const bytes = frame.toFramedBytes();
    expect(bytes.byteLength).toBeGreaterThan(4);
    const len = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    expect(len).toBe(bytes.byteLength - 4);
  });
});

