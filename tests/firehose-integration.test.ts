import { describe, it, expect } from 'bun:test';
import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import {
  encodeAccountFrame,
  encodeCommitFrame,
  encodeErrorFrame,
  encodeIdentityFrame,
  encodeInfoFrame,
  FrameType,
  type AccountMessage,
  type CommitMessage,
  type IdentityMessage,
  type RepoOp,
} from '../src/lib/firehose/frames';
import { reviveCid, reviveOps, base64ToBytes } from '../src/worker/sequencer/cid-helpers';
import { broadcastAccount, broadcastIdentity } from '../src/worker/sequencer/broadcast';
import type { AccountEvent, IdentityEvent } from '../src/worker/sequencer/types';

// Each frame written by the sequencer is a single WebSocket message
// containing CBOR(header) || CBOR(body). Decode-then-decode-rest by
// re-encoding the header to compute the boundary; the dag-cbor decoder is
// strict about trailing bytes so we slice deliberately.
function decodeFrame(bytes: Uint8Array): { header: unknown; body: unknown } {
  // dag-cbor decode is strict — re-encode the decoded header to find where the
  // body block starts.
  let headerLen = 0;
  for (let i = 1; i <= bytes.byteLength; i++) {
    try {
      dagCbor.decode(bytes.slice(0, i));
      headerLen = i;
      break;
    } catch {
      // try the next byte length
    }
  }
  if (headerLen === 0) throw new Error('could not find header boundary');
  const header = dagCbor.decode(bytes.slice(0, headerLen));
  const body = dagCbor.decode(bytes.slice(headerLen));
  return { header, body };
}

// Minimal fake WebSocket that captures sent bytes. The real DurableObjectState
// hands these to clients; for tests we only need to observe what would be sent.
function fakeSocket(opts: { failOnSend?: boolean } = {}): {
  send: (bytes: Uint8Array | string) => void;
  sent: Uint8Array[];
  socket: WebSocket;
} {
  const sent: Uint8Array[] = [];
  const send = (bytes: Uint8Array | string) => {
    if (opts.failOnSend) throw new Error('send failed');
    if (typeof bytes !== 'string') sent.push(bytes);
  };
  return { send, sent, socket: { send } as unknown as WebSocket };
}

const SAMPLE_CID = 'bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua';
const OTHER_CID = 'bafyreibvjvcv745gig4mvqs4hctx4zfkono4rjejm2ta6gtyzkqxfjeily';

describe('cid-helpers', () => {
  describe('reviveCid', () => {
    it('parses a string CID', () => {
      const cid = reviveCid(SAMPLE_CID);
      expect(cid).toBeInstanceOf(CID);
      expect(cid?.toString()).toBe(SAMPLE_CID);
    });

    it('passes through a CID instance', () => {
      const cid = CID.parse(SAMPLE_CID);
      expect(reviveCid(cid)?.toString()).toBe(SAMPLE_CID);
    });

    it('unwraps an IPLD link object {"/" : cid}', () => {
      expect(reviveCid({ '/': SAMPLE_CID })?.toString()).toBe(SAMPLE_CID);
    });

    it('returns null for null / undefined', () => {
      expect(reviveCid(null)).toBeNull();
      expect(reviveCid(undefined)).toBeNull();
    });

    it('returns null for garbage strings', () => {
      expect(reviveCid('not-a-cid')).toBeNull();
    });
  });

  describe('reviveOps', () => {
    it('revives an array of ops with CID strings', () => {
      const ops = reviveOps([
        { action: 'create', path: 'app.bsky.feed.post/abc', cid: SAMPLE_CID },
        { action: 'update', path: 'app.bsky.feed.post/def', cid: SAMPLE_CID, prev: OTHER_CID },
        { action: 'delete', path: 'app.bsky.feed.post/ghi', cid: null },
      ]);
      expect(ops).toHaveLength(3);
      expect(ops?.[0].cid).toBeInstanceOf(CID);
      expect(ops?.[1].prev?.toString()).toBe(OTHER_CID);
      expect(ops?.[2].cid).toBeNull();
    });

    it('returns undefined for non-arrays', () => {
      expect(reviveOps(null)).toBeUndefined();
      expect(reviveOps('nope')).toBeUndefined();
    });

    it('drops prev when missing', () => {
      const ops = reviveOps([{ action: 'create', path: 'p', cid: SAMPLE_CID }]);
      expect(ops?.[0].prev).toBeUndefined();
    });
  });

  describe('base64ToBytes', () => {
    it('round-trips through btoa', () => {
      const bytes = new Uint8Array([0, 1, 2, 254, 255]);
      const base64 = btoa(String.fromCharCode(...bytes));
      expect(Array.from(base64ToBytes(base64))).toEqual(Array.from(bytes));
    });
  });
});

describe('frame encoders', () => {
  it('encodes #info as decodable CBOR', () => {
    const bytes = encodeInfoFrame('OutdatedCursor', 'Cursor is too old for backfill');
    const { header, body } = decodeFrame(bytes);
    expect(header).toEqual({ op: FrameType.Message, t: '#info' });
    expect(body).toEqual({ name: 'OutdatedCursor', message: 'Cursor is too old for backfill' });
  });

  it('encodes FutureCursor errors as decodable CBOR', () => {
    const bytes = encodeErrorFrame('FutureCursor', 'Cursor is ahead of current sequence');
    const { header, body } = decodeFrame(bytes);
    expect(header).toEqual({ op: FrameType.Error });
    expect(body).toEqual({
      error: 'FutureCursor',
      message: 'Cursor is ahead of current sequence',
    });
  });

  it('encodes #account', () => {
    const message: AccountMessage = {
      seq: 42,
      did: 'did:plc:test',
      time: '2026-05-11T00:00:00.000Z',
      active: false,
      status: 'suspended',
    };
    const bytes = encodeAccountFrame(message);
    const { header, body } = decodeFrame(bytes);
    expect(header).toEqual({ op: FrameType.Message, t: '#account' });
    expect(body).toEqual(message);
  });

  it('encodes #identity', () => {
    const message: IdentityMessage = {
      seq: 7,
      did: 'did:plc:test',
      time: '2026-05-11T00:00:00.000Z',
      handle: 'new.example',
    };
    const bytes = encodeIdentityFrame(message);
    const { header, body } = decodeFrame(bytes);
    expect(header).toEqual({ op: FrameType.Message, t: '#identity' });
    expect(body).toEqual(message);
  });

  it('encodes #commit and preserves CIDs through CBOR', () => {
    const commit = CID.parse(SAMPLE_CID);
    const mstRoot = CID.parse(OTHER_CID);
    const op: RepoOp = { action: 'create', path: 'app.bsky.feed.post/abc', cid: commit };
    const message: CommitMessage = {
      seq: 1,
      rebase: false,
      tooBig: false,
      repo: 'did:plc:test',
      commit,
      prev: null,
      rev: '3jzfcijpj2z2a',
      since: null,
      blocks: new Uint8Array([1, 2, 3]),
      ops: [op],
      blobs: [],
      time: '2026-05-11T00:00:00.000Z',
      prevData: mstRoot,
    };
    const bytes = encodeCommitFrame(message);
    const { header, body } = decodeFrame(bytes);
    expect(header).toEqual({ op: FrameType.Message, t: '#commit' });
    const decoded = body as CommitMessage;
    expect(decoded.seq).toBe(1);
    expect(decoded.repo).toBe('did:plc:test');
    expect(decoded.commit.toString()).toBe(SAMPLE_CID);
    expect(decoded.prevData?.toString()).toBe(OTHER_CID);
    expect(decoded.ops).toHaveLength(1);
    expect(decoded.ops[0].cid?.toString()).toBe(SAMPLE_CID);
  });
});

describe('broadcastAccount', () => {
  function makeEvent(state: AccountEvent['state']): AccountEvent {
    return {
      seq: 9,
      did: 'did:plc:test',
      ts: Date.parse('2026-05-11T00:00:00.000Z'),
      state,
    };
  }

  it('emits an #account frame derived from AccountState (active)', () => {
    const client = fakeSocket();
    broadcastAccount([client.socket], makeEvent({ tag: 'active' }));
    // Two frames per call: #account + legacy #sync.
    expect(client.sent.length).toBe(2);
    const account = decodeFrame(client.sent[0]);
    expect(account.header).toEqual({ op: FrameType.Message, t: '#account' });
    expect((account.body as AccountMessage).active).toBe(true);
    expect((account.body as AccountMessage).status).toBeUndefined();
  });

  it('emits status="suspended" for a suspended FSM state', () => {
    const client = fakeSocket();
    broadcastAccount(
      [client.socket],
      makeEvent({ tag: 'suspended', until: '2026-12-31T00:00:00.000Z' }),
    );
    const account = decodeFrame(client.sent[0]).body as AccountMessage;
    expect(account.active).toBe(false);
    expect(account.status).toBe('suspended');
    // Wire format intentionally drops `until` — toRow/fromRow preserve it
    // separately for persistence. This test pins the spec-compliant behavior.
    expect('until' in account).toBe(false);
  });

  it('fans out to every client and tolerates one failing send', () => {
    const good1 = fakeSocket();
    const bad = fakeSocket({ failOnSend: true });
    const good2 = fakeSocket();
    broadcastAccount(
      [good1.socket, bad.socket, good2.socket],
      makeEvent({ tag: 'takendown' }),
    );
    expect(good1.sent.length).toBe(2);
    expect(bad.sent.length).toBe(0);
    expect(good2.sent.length).toBe(2);
  });
});

describe('broadcastIdentity', () => {
  it('emits an #identity frame with the new handle', () => {
    const client = fakeSocket();
    const event: IdentityEvent = {
      seq: 11,
      did: 'did:plc:test',
      ts: Date.parse('2026-05-11T00:00:00.000Z'),
      handle: 'changed.example',
    };
    broadcastIdentity([client.socket], event);
    expect(client.sent.length).toBe(1);
    const { header, body } = decodeFrame(client.sent[0]);
    expect(header).toEqual({ op: FrameType.Message, t: '#identity' });
    expect((body as IdentityMessage).handle).toBe('changed.example');
  });

  it('tolerates a failing client without throwing', () => {
    const bad = fakeSocket({ failOnSend: true });
    expect(() =>
      broadcastIdentity([bad.socket], {
        seq: 1,
        did: 'did:plc:test',
        ts: Date.now(),
        handle: 'h.example',
      }),
    ).not.toThrow();
  });
});
