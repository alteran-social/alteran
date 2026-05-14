import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { createCommitFrame, type CommitMessage } from '../src/lib/firehose/frames';
import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';

function decodeFramedCommit(bytes: Uint8Array): { header: any; body: CommitMessage } {
  // 4-byte big-endian total length prefix
  const payload = bytes.slice(4);
  // Our header is dag-cbor encoded { op: 1, t: '#commit' }
  const headerBytes = dagCbor.encode({ op: 1, t: '#commit' });
  // Verify prefix
  const isHeaderPrefix = headerBytes.every((b, i) => payload[i] === b);
  expect(isHeaderPrefix).toBe(true);
  const bodyBytes = payload.slice(headerBytes.length);
  const body = dagCbor.decode(bodyBytes) as CommitMessage;
  return { header: { op: 1, t: '#commit' }, body };
}

describe('Framed #commit decoding (lightweight)', () => {
  it('extracts seq and verifies prev/since presence', () => {
    const cid1 = CID.parse('bafyreihdwdce3xg3zj5h5r3d2p7k2m2vfsw4gcyvsa3tqv5n3n3kvtvpfy');
    const cid0 = CID.parse('bafyreibvjvcv745gig4mvqs4hctx4zfkono4rjejm2ta6gtyzkqxfjeily');

    const frame1 = createCommitFrame({
      seq: 1,
      rebase: false,
      tooBig: false,
      repo: 'did:plc:test',
      commit: cid1,
      prev: null,
      rev: 'r1',
      since: null,
      blocks: new Uint8Array(),
      ops: [],
      blobs: [],
      time: '2024-01-01T00:00:00.000Z',
    }).toFramedBytes();

    const frame2 = createCommitFrame({
      seq: 2,
      rebase: false,
      tooBig: false,
      repo: 'did:plc:test',
      commit: cid0,
      prev: cid1,
      rev: 'r2',
      since: 'r1',
      blocks: new Uint8Array(),
      ops: [],
      blobs: [],
      time: '2024-01-01T00:00:01.000Z',
    }).toFramedBytes();

    const d1 = decodeFramedCommit(frame1);
    const d2 = decodeFramedCommit(frame2);

    expect(d1.body.seq).toBe(1);
    expect(d2.body.seq).toBe(2);
    expect(d2.body.seq).toBeGreaterThan(d1.body.seq);
    expect(d2.body.prev?.toString()).toBe(cid1.toString());
    expect(d2.body.since).toBe('r1');
  });
});

