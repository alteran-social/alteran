import { describe, expect, it } from 'bun:test';
import * as dagCbor from '@ipld/dag-cbor';
import { drizzle } from 'drizzle-orm/d1';
import { commit_log } from '../src/db/schema';
import { FrameType } from '../src/lib/firehose/frames';
import { Sequencer } from '../src/worker/sequencer';
import { createPdsFetchHandler } from '../src/worker/runtime';
import {
  classifyCursor,
  handleUpgrade,
  isWebSocketUpgrade,
  type HibernatableSocket,
} from '../src/worker/sequencer/upgrade';
import { ctx, makeEnv } from './helpers/env';

const SAMPLE_CID = 'bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua';

function decodeFrame(bytes: Uint8Array): { header: any; body: any } {
  let headerLen = 0;
  for (let i = 1; i <= bytes.byteLength; i++) {
    try {
      dagCbor.decode(bytes.slice(0, i));
      headerLen = i;
      break;
    } catch {
      // keep scanning for the first complete DAG-CBOR object
    }
  }
  if (headerLen === 0) throw new Error('could not find header boundary');
  return {
    header: dagCbor.decode(bytes.slice(0, headerLen)),
    body: dagCbor.decode(bytes.slice(headerLen)),
  };
}

function withFakeWebSocketPair<T>(
  run: (server: HibernatableSocket & {
    accepted: boolean;
    attachment: unknown;
    closed: { code: number; reason: string } | null;
    sent: Uint8Array[];
  }) => T,
): T {
  const original = (globalThis as any).WebSocketPair;
  const client = {} as WebSocket;
  let accepted = false;
  let attachment: unknown;
  let closed: { code: number; reason: string } | null = null;
  const sent: Uint8Array[] = [];
  const server = {
    get accepted() {
      return accepted;
    },
    get attachment() {
      return attachment;
    },
    get closed() {
      return closed;
    },
    sent,
    accept() {
      accepted = true;
    },
    serializeAttachment(value: unknown) {
      attachment = value;
    },
    send(bytes: string | ArrayBuffer | Uint8Array) {
      if (typeof bytes !== 'string') sent.push(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
    },
    close(code: number, reason: string) {
      closed = { code, reason };
    },
    addEventListener() {},
  } as unknown as HibernatableSocket & {
    accepted: boolean;
    attachment: unknown;
    closed: { code: number; reason: string } | null;
    sent: Uint8Array[];
  };

  (globalThis as any).WebSocketPair = function WebSocketPair() {
    return { 0: client, 1: server };
  };

  try {
    return run(server);
  } finally {
    (globalThis as any).WebSocketPair = original;
  }
}

describe('subscribeRepos cursor and upgrade behavior', () => {
  it('accepts WebSocket upgrades case-insensitively', () => {
    expect(isWebSocketUpgrade(new Request('https://pds.example/xrpc', {
      headers: { Upgrade: 'WebSocket' },
    }))).toBe(true);
    expect(isWebSocketUpgrade(new Request('https://pds.example/xrpc', {
      headers: { Upgrade: 'websocket' },
    }))).toBe(true);
    expect(isWebSocketUpgrade(new Request('https://pds.example/xrpc'))).toBe(false);
  });

  it('classifies cursors using effective replay positions', () => {
    expect(classifyCursor(null, 10, 5)).toEqual({
      type: 'accept',
      cursor: 9,
      replay: false,
    });
    expect(classifyCursor('0', 10, 5)).toEqual({
      type: 'accept',
      cursor: 4,
      replay: true,
    });
    expect(classifyCursor('2', 10, 5)).toEqual({
      type: 'accept',
      cursor: 4,
      replay: true,
      info: {
        name: 'OutdatedCursor',
        message: 'Cursor is older than the oldest available sequence',
      },
    });
    expect(classifyCursor('7', 10, 5)).toEqual({
      type: 'accept',
      cursor: 6,
      replay: true,
    });
    expect(classifyCursor('11', 10, 5)).toEqual({
      type: 'future',
      cursor: 11,
      error: 'FutureCursor',
      message: 'Cursor is ahead of current sequence',
    });
    expect(() => classifyCursor('-1', 10, 5)).toThrow('cursor must be a non-negative integer');
    expect(() => classifyCursor('', 10, 5)).toThrow('cursor must be a non-negative integer');
  });

  it('sends FutureCursor as an error frame and closes', () => withFakeWebSocketPair((server) => {
    let onClientCalled = false;
    const response = handleUpgrade(
      new Request('https://pds.example/xrpc/com.atproto.sync.subscribeRepos?cursor=11'),
      new URL('https://pds.example/xrpc/com.atproto.sync.subscribeRepos?cursor=11'),
      {
        state: {} as any,
        nextSeq: 10,
        oldestAvailableSeq: 5,
        hibernate: false,
        onClient: () => {
          onClientCalled = true;
        },
      },
    );

    expect(response.status).toBe(101);
    expect(onClientCalled).toBe(false);
    expect(server.closed).toEqual({ code: 1008, reason: 'FutureCursor' });
    const decoded = decodeFrame(server.sent[0]);
    expect(decoded.header).toEqual({ op: FrameType.Error });
    expect(decoded.body).toEqual({
      error: 'FutureCursor',
      message: 'Cursor is ahead of current sequence',
    });
  }));

  it('sends OutdatedCursor info for too-old cursors and keeps the socket open', () => withFakeWebSocketPair((server) => {
    let client: { cursor: number; replay: boolean } | null = null;
    const response = handleUpgrade(
      new Request('https://pds.example/xrpc/com.atproto.sync.subscribeRepos?cursor=2'),
      new URL('https://pds.example/xrpc/com.atproto.sync.subscribeRepos?cursor=2'),
      {
        state: {} as any,
        nextSeq: 10,
        oldestAvailableSeq: 5,
        hibernate: false,
        onClient: (_id, cursor, replay) => {
          client = { cursor, replay };
        },
      },
    );

    expect(response.status).toBe(101);
    const observedClient = client as { cursor: number; replay: boolean } | null;
    expect(observedClient).toEqual({ cursor: 4, replay: true });
    expect(server.closed).toBeNull();
    const decoded = decodeFrame(server.sent[0]);
    expect(decoded.header).toEqual({ op: FrameType.Message, t: '#info' });
    expect(decoded.body).toEqual({
      name: 'OutdatedCursor',
      message: 'Cursor is older than the oldest available sequence',
    });
  }));

  it('forwards mixed-case Worker subscribeRepos upgrades to the sequencer binding', async () => {
    const forwarded: Request[] = [];
    const env = await makeEnv({
      ALTERAN_SEQUENCER: {
        idFromName(name: string) {
          expect(name).toBe('default');
          return 'default-id';
        },
        get(id: string) {
          expect(id).toBe('default-id');
          return {
            async fetch(request: Request) {
              forwarded.push(request);
              return new Response('forwarded', { status: 204 });
            },
          };
        },
      } as any,
    });

    const response = await createPdsFetchHandler()(
      new Request('https://pds.example/xrpc/com.atproto.sync.subscribeRepos', {
        headers: { Upgrade: 'WebSocket' },
      }) as any,
      env,
      ctx as any,
    );

    expect(response.status).toBe(204);
    expect(forwarded).toHaveLength(1);
    expect(forwarded[0].headers.get('upgrade')).toBe('WebSocket');
  });

  it('rejects non-GET Worker subscribeRepos requests before forwarding', async () => {
    for (const request of [
      new Request('https://pds.example/xrpc/com.atproto.sync.subscribeRepos', {
        method: 'POST',
        headers: { Upgrade: 'WebSocket' },
      }),
      new Request('https://pds.example/xrpc/com.atproto.sync.subscribeRepos', {
        method: 'POST',
      }),
    ]) {
      let forwarded = false;
      const env = await makeEnv({
        ALTERAN_SEQUENCER: {
          idFromName() {
            return 'default-id';
          },
          get() {
            return {
              async fetch() {
                forwarded = true;
                return new Response('unexpected', { status: 500 });
              },
            };
          },
        } as any,
      });

      const response = await createPdsFetchHandler()(request as any, env, ctx as any);

      expect(response.status).toBe(405);
      expect(response.headers.get('allow')).toBe('GET');
      expect(forwarded).toBe(false);
    }
  });

  it('returns 426 before the sequencer binding for non-upgrade Worker requests', async () => {
    let forwarded = false;
    const env = await makeEnv({
      ALTERAN_SEQUENCER: {
        idFromName() {
          return 'default-id';
        },
        get() {
          return {
            async fetch() {
              forwarded = true;
              return new Response('unexpected', { status: 500 });
            },
          };
        },
      } as any,
    });

    const response = await createPdsFetchHandler()(
      new Request('https://pds.example/xrpc/com.atproto.sync.subscribeRepos') as any,
      env,
      ctx as any,
    );

    expect(response.status).toBe(426);
    expect(await response.text()).toContain('requires a WebSocket');
    expect(forwarded).toBe(false);
  });

  it('replays database rows before buffered rows for effective rollback cursors', async () => {
    const env = await makeEnv();
    const db = drizzle(env.ALTERAN_DB);
    const commitData = JSON.stringify({
      did: 'did:example:test',
      data: SAMPLE_CID,
      rev: 'rev',
      prev: null,
    });
    await db.insert(commit_log).values([
      { seq: 5, cid: SAMPLE_CID, rev: 'rev5', data: commitData, sig: 'sig', ts: 1 },
      { seq: 6, cid: SAMPLE_CID, rev: 'rev6', data: commitData, sig: 'sig', ts: 2 },
    ]).run();

    const sequencer = new Sequencer({
      storage: {
        async get() {
          return undefined;
        },
        async put() {},
      },
      blockConcurrencyWhile(callback: () => Promise<void>) {
        return callback();
      },
      getWebSockets() {
        return [];
      },
    } as any, env);
    (sequencer as any).buffer = [{
      seq: 7,
      did: 'did:example:test',
      commitCid: SAMPLE_CID,
      rev: 'rev7',
      data: commitData,
      sig: 'sig',
      ts: 3,
    }];

    const sent: Uint8Array[] = [];
    await (sequencer as any).replayFromCursor({
      send(bytes: Uint8Array) {
        sent.push(bytes);
      },
    }, 4);

    const seqs = sent.map((bytes) => (decodeFrame(bytes).body as any).seq);
    expect(seqs).toEqual([5, 6, 7]);
  });
});
