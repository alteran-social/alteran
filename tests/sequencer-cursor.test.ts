import { describe, it, expect } from 'bun:test';
import * as dagCbor from '@ipld/dag-cbor';
import { FrameType } from '../src/lib/firehose/frames';
import { InvalidRequest } from '../src/lib/errors';
import {
  handleUpgrade,
  parseCursorParam,
  type HibernatableState,
} from '../src/worker/sequencer/upgrade';

function decodeFrame(bytes: Uint8Array): { header: unknown; body: unknown } {
  let headerLen = 0;
  for (let i = 1; i <= bytes.byteLength; i++) {
    try {
      dagCbor.decode(bytes.slice(0, i));
      headerLen = i;
      break;
    } catch {
      // keep scanning for the first complete CBOR item
    }
  }
  if (headerLen === 0) throw new Error('could not find header boundary');
  return {
    header: dagCbor.decode(bytes.slice(0, headerLen)),
    body: dagCbor.decode(bytes.slice(headerLen)),
  };
}

describe('parseCursorParam', () => {
  it('distinguishes missing param from explicit zero', () => {
    expect(parseCursorParam(null)).toBeNull();
    expect(parseCursorParam('0')).toBe(0);
  });

  it('parses a non-negative integer', () => {
    expect(parseCursorParam('42')).toBe(42);
  });

  it('rejects non-numeric values', () => {
    expect(() => parseCursorParam('abc')).toThrow(InvalidRequest);
    expect(() => parseCursorParam('')).toThrow(InvalidRequest);
  });

  it('rejects negatives', () => {
    expect(() => parseCursorParam('-1')).toThrow(InvalidRequest);
  });

  it('rejects floats', () => {
    expect(() => parseCursorParam('1.5')).toThrow(InvalidRequest);
  });

  it('rejects Infinity', () => {
    expect(() => parseCursorParam('Infinity')).toThrow(InvalidRequest);
  });
});

describe('handleUpgrade cursor handling', () => {
  it('sends a FutureCursor error frame and closes when cursor is ahead of current seq', () => {
    const sent: Uint8Array[] = [];
    const closed: Array<{ code: number; reason: string }> = [];
    const server = {
      accept: () => {},
      send: (data: string | ArrayBuffer | Uint8Array) => {
        if (data instanceof Uint8Array) sent.push(data);
      },
      close: (code: number, reason: string) => {
        closed.push({ code, reason });
      },
    } as unknown as WebSocket;
    const client = {} as WebSocket;
    const originalWebSocketPair = (globalThis as { WebSocketPair?: unknown }).WebSocketPair;

    class FakeWebSocketPair {
      0 = client;
      1 = server;
    }

    (globalThis as { WebSocketPair?: unknown }).WebSocketPair = FakeWebSocketPair;

    try {
      const url = new URL('https://pds.example/xrpc/com.atproto.sync.subscribeRepos?cursor=11');
      const response = handleUpgrade(new Request(url), url, {
        state: {} as HibernatableState,
        nextSeq: 10,
        hibernate: false,
        onClient: () => {
          throw new Error('future cursor should not register a client');
        },
      });

      expect(response.status).toBe(101);
      expect(sent).toHaveLength(1);
      expect(decodeFrame(sent[0])).toEqual({
        header: { op: FrameType.Error },
        body: { error: 'FutureCursor', message: 'Cursor is ahead of current sequence' },
      });
      expect(closed).toEqual([{ code: 1008, reason: 'FutureCursor' }]);
    } finally {
      if (originalWebSocketPair === undefined) {
        delete (globalThis as { WebSocketPair?: unknown }).WebSocketPair;
      } else {
        (globalThis as { WebSocketPair?: unknown }).WebSocketPair = originalWebSocketPair;
      }
    }
  });
});
