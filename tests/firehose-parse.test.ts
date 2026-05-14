import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { createCommitFrame, createErrorFrame } from '../src/lib/firehose/frames';
import { parseFramedFrame } from '../src/lib/firehose/parse';
import { CID } from 'multiformats/cid';

describe('parseFramedFrame', () => {
  it('parses a framed #commit', () => {
    const frame = createCommitFrame({
      seq: 42,
      rebase: false,
      tooBig: false,
      repo: 'did:plc:test',
      commit: CID.parse('bafyreihdwdce3xg3zj5h5r3d2p7k2m2vfsw4gcyvsa3tqv5n3n3kvtvpfy'),
      prev: null,
      rev: 'r42',
      since: 'r41',
      blocks: new Uint8Array(),
      ops: [],
      blobs: [],
      time: new Date(0).toISOString(),
    }).toFramedBytes();

    const { header, body } = parseFramedFrame<any>(frame);
    expect(header.op).toBe(1);
    expect(header.t).toBe('#commit');
    expect(body.seq).toBe(42);
    expect(String(body.commit)).toContain('bafy');
  });

  it('parses a framed #error', () => {
    const frame = createErrorFrame('FutureCursor', 'oops').toFramedBytes();
    const { header, body } = parseFramedFrame<any>(frame);
    expect(header.op).toBe(-1);
    expect(body.error).toBe('FutureCursor');
  });
});

