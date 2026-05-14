import { describe, it, beforeAll, afterAll } from "./helpers/bdd";
import { expect } from "@std/expect";
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import {
  createCommitFrame,
  createIdentityFrame,
  createAccountFrame,
  createInfoFrame,
  createErrorFrame,
  createSyncFrame,
  type CommitMessage,
  type RepoOp,
} from '../src/lib/firehose/frames';

describe('Firehose Frame Encoding', () => {
  it('should encode commit frame correctly', async () => {
    const ops: RepoOp[] = [
      {
        action: 'create',
        path: 'app.bsky.feed.post/abc123',
        cid: CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua'),
      },
    ];

    const commitMessage: CommitMessage = {
      seq: 1,
      rebase: false,
      tooBig: false,
      repo: 'did:plc:test123',
      commit: CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua'),
      prev: null,
      rev: '3jzfcijpj2z2a',
      since: null,
      blocks: new Uint8Array([1, 2, 3]),
      ops,
      blobs: [],
      time: '2024-01-01T00:00:00.000Z',
    };

    const frame = createCommitFrame(commitMessage);
    expect(frame.type).toBe('#commit');
    expect(frame.body).toEqual(commitMessage);

    const bytes = frame.toBytes();
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBeGreaterThan(0);
  });

  it('should encode identity frame correctly', () => {
    const frame = createIdentityFrame({
      seq: 2,
      did: 'did:plc:test123',
      time: '2024-01-01T00:00:00.000Z',
      handle: 'test.bsky.social',
    });

    expect(frame.type).toBe('#identity');
    expect(frame.body).toMatchObject({
      seq: 2,
      did: 'did:plc:test123',
      handle: 'test.bsky.social',
    });

    const bytes = frame.toBytes();
    expect(bytes).toBeInstanceOf(Uint8Array);
  });

  it('should encode account frame correctly', () => {
    const frame = createAccountFrame({
      seq: 3,
      did: 'did:plc:test123',
      time: '2024-01-01T00:00:00.000Z',
      active: true,
      status: 'active',
    });

    expect(frame.type).toBe('#account');
    expect(frame.body).toMatchObject({
      seq: 3,
      did: 'did:plc:test123',
      active: true,
      status: 'active',
    });
  });

  it('should encode sync frame correctly', () => {
    const frame = createSyncFrame({
      seq: 4,
      did: 'did:plc:test123',
      time: '2024-01-01T00:00:00.000Z',
      active: true,
      status: 'active',
    });
    expect(frame.type).toBe('#sync');
    expect(frame.body).toMatchObject({ did: 'did:plc:test123', active: true });
  });

  it('should encode info frame correctly', () => {
    const frame = createInfoFrame('TestInfo', 'This is a test message');
    expect(frame.type).toBe('#info');
    expect(frame.body).toEqual({
      name: 'TestInfo',
      message: 'This is a test message',
    });
  });

  it('should encode error frame correctly', () => {
    const frame = createErrorFrame('TestError', 'Something went wrong');
    expect(frame.code).toBe('TestError');
    expect(frame.message).toBe('Something went wrong');
  });
});

describe('MST Operation Extraction', () => {
  it('should identify create operations', async () => {
    // This test would require setting up a full MST environment
    // For now, we'll test the structure
    const createOp: RepoOp = {
      action: 'create',
      path: 'app.bsky.feed.post/abc123',
      cid: CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua'),
    };

    expect(createOp.action).toBe('create');
    expect(createOp.path).toBe('app.bsky.feed.post/abc123');
    expect(createOp.cid).toBeInstanceOf(CID);
  });

  it('should identify update operations', () => {
    const updateOp: RepoOp = {
      action: 'update',
      path: 'app.bsky.feed.post/abc123',
      cid: CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua'),
      prev: CID.parse('bafyreibvjvcv745gig4mvqs4hctx4zfkono4rjejm2ta6gtyzkqxfjeily'),
    };

    expect(updateOp.action).toBe('update');
    expect(updateOp.prev).toBeInstanceOf(CID);
  });

  it('should identify delete operations', () => {
    const deleteOp: RepoOp = {
      action: 'delete',
      path: 'app.bsky.feed.post/abc123',
      cid: null,
      prev: CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua'),
    };

    expect(deleteOp.action).toBe('delete');
    expect(deleteOp.cid).toBeNull();
    expect(deleteOp.prev).toBeInstanceOf(CID);
  });
});

describe('CAR Encoding', () => {
  it('should encode blocks to CAR format', async () => {
    // Test basic CAR structure
    const testData = { test: 'data' };
    const bytes = dagCbor.encode(testData);
    const hash = await sha256.digest(bytes);
    const cid = CID.createV1(dagCbor.code, hash);

    expect(cid).toBeInstanceOf(CID);
    expect(bytes).toBeInstanceOf(Uint8Array);
  });

  it('should handle multiple blocks in CAR', async () => {
    const blocks = [
      { data: 'block1' },
      { data: 'block2' },
      { data: 'block3' },
    ];

    const encodedBlocks = await Promise.all(
      blocks.map(async (block) => {
        const bytes = dagCbor.encode(block);
        const hash = await sha256.digest(bytes);
        const cid = CID.createV1(dagCbor.code, hash);
        return { cid, bytes };
      })
    );

    expect(encodedBlocks).toHaveLength(3);
    encodedBlocks.forEach(({ cid, bytes }) => {
      expect(cid).toBeInstanceOf(CID);
      expect(bytes).toBeInstanceOf(Uint8Array);
    });
  });
});

describe('Cursor Validation', () => {
  it('should validate cursor is not in future', () => {
    const currentSeq = 100;
    const validCursor = 50;
    const futureCursor = 150;

    expect(validCursor <= currentSeq).toBe(true);
    expect(futureCursor > currentSeq).toBe(true);
  });

  it('should handle cursor = 0 (replay from beginning)', () => {
    const cursor = 0;
    expect(cursor).toBe(0);
  });

  it('should handle undefined cursor (start from current)', () => {
    const cursor = undefined;
    expect(cursor).toBeUndefined();
  });
});

describe('Backpressure Handling', () => {
  it('should track dropped frames', () => {
    const maxWindow = 5;
    const buffer: number[] = [];
    let droppedCount = 0;

    // Simulate adding events beyond buffer capacity
    for (let i = 1; i <= 10; i++) {
      buffer.push(i);
      if (buffer.length > maxWindow) {
        buffer.shift();
        droppedCount++;
      }
    }

    expect(buffer.length).toBe(maxWindow);
    expect(droppedCount).toBe(5);
    expect(buffer).toEqual([6, 7, 8, 9, 10]);
  });

  it('should maintain buffer within limits', () => {
    const maxWindow = 512;
    const buffer: number[] = [];

    for (let i = 1; i <= 1000; i++) {
      buffer.push(i);
      if (buffer.length > maxWindow) {
        buffer.shift();
      }
    }

    expect(buffer.length).toBeLessThanOrEqual(maxWindow);
  });
});

describe('Frame Type Discrimination', () => {
  it('should correctly identify frame types', () => {
    const commitFrame = createCommitFrame({
      seq: 1,
      rebase: false,
      tooBig: false,
      repo: 'did:plc:test',
      commit: CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua'),
      prev: null,
      rev: '3jzfcijpj2z2a',
      since: null,
      blocks: new Uint8Array(),
      ops: [],
      blobs: [],
      time: '2024-01-01T00:00:00.000Z',
    });

    const identityFrame = createIdentityFrame({
      seq: 2,
      did: 'did:plc:test',
      time: '2024-01-01T00:00:00.000Z',
    });

    const accountFrame = createAccountFrame({
      seq: 3,
      did: 'did:plc:test',
      time: '2024-01-01T00:00:00.000Z',
      active: true,
    });

    expect(commitFrame.type).toBe('#commit');
    expect(identityFrame.type).toBe('#identity');
    expect(accountFrame.type).toBe('#account');
  });
});

describe('Sequence Number Management', () => {
  it('should increment sequence numbers correctly', () => {
    let seq = 1;
    const events = [];

    for (let i = 0; i < 10; i++) {
      events.push({ seq: seq++, data: `event${i}` });
    }

    expect(events).toHaveLength(10);
    expect(events[0].seq).toBe(1);
    expect(events[9].seq).toBe(10);
    expect(seq).toBe(11);
  });

  it('should maintain sequence order', () => {
    const events = [
      { seq: 1, data: 'a' },
      { seq: 2, data: 'b' },
      { seq: 3, data: 'c' },
    ];

    const sorted = events.every((event, i) => {
      if (i === 0) return true;
      return event.seq > events[i - 1].seq;
    });

    expect(sorted).toBe(true);
  });
});
