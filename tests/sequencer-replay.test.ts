import { describe, expect, it } from 'bun:test';
import * as dagCbor from '@ipld/dag-cbor';
import { drizzle } from 'drizzle-orm/d1';
import { eq } from 'drizzle-orm';
import { commit_log, firehose_event } from '../src/db/schema';
import { FrameType, encodeIdentityFrame, type CommitMessage } from '../src/lib/firehose/frames';
import { Sequencer } from '../src/worker/sequencer';
import { bytesToBase64 } from '../src/worker/sequencer/cid-helpers';
import { makeEnv } from './helpers/env';

const CURRENT_CID = 'bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua';
const PREVIOUS_CID = 'bafyreibvjvcv745gig4mvqs4hctx4zfkono4rjejm2ta6gtyzkqxfjeily';

function decodeFrame(bytes: Uint8Array): { header: any; body: any } {
  let headerLen = 0;
  for (let i = 1; i <= bytes.byteLength; i++) {
    try {
      dagCbor.decode(bytes.slice(0, i));
      headerLen = i;
      break;
    } catch {
      // Keep scanning until the first CBOR object is complete.
    }
  }
  if (headerLen === 0) throw new Error('could not find header boundary');
  return {
    header: dagCbor.decode(bytes.slice(0, headerLen)),
    body: dagCbor.decode(bytes.slice(headerLen)),
  };
}

function fakeSocket(): { socket: WebSocket; sent: Uint8Array[] } {
  const sent: Uint8Array[] = [];
  return {
    sent,
    socket: {
      send(bytes: Uint8Array | string) {
        if (typeof bytes !== 'string') sent.push(bytes);
      },
    } as unknown as WebSocket,
  };
}

async function withFakeWebSocketPair<T>(run: (server: WebSocket & {
  sent: Uint8Array[];
  attachment: unknown;
  deserializeAttachment: () => unknown;
}) => T | Promise<T>): Promise<T> {
  const original = (globalThis as any).WebSocketPair;
  const client = {} as WebSocket;
  let attachment: unknown;
  const sent: Uint8Array[] = [];
  const server = {
    sent,
    get attachment() {
      return attachment;
    },
    serializeAttachment(value: unknown) {
      attachment = value;
    },
    deserializeAttachment() {
      return attachment;
    },
    send(bytes: Uint8Array | string) {
      if (typeof bytes !== 'string') sent.push(bytes);
    },
    addEventListener() {},
  } as unknown as WebSocket & {
    sent: Uint8Array[];
    attachment: unknown;
    deserializeAttachment: () => unknown;
  };

  (globalThis as any).WebSocketPair = function WebSocketPair() {
    return { 0: client, 1: server };
  };

  try {
    return await run(server);
  } finally {
    (globalThis as any).WebSocketPair = original;
  }
}

function makeState(sockets: WebSocket[] = []) {
  const storage = new Map<string, unknown>();
  const pending: Promise<unknown>[] = [];
  const state = {
    storage: {
      async get(key: string) {
        return storage.get(key);
      },
      async put(key: string, value: unknown) {
        storage.set(key, value);
      },
    },
    blockConcurrencyWhile(callback: () => Promise<unknown>) {
      const promise = callback();
      pending.push(promise);
      return promise;
    },
    getWebSockets() {
      return sockets;
    },
  };
  return { state, pending };
}

function commitData(did: string, data: string, rev: string, prev: string | null) {
  return JSON.stringify({
    did,
    version: 3,
    data,
    rev,
    prev,
  });
}

describe('sequencer durable replay', () => {
  it('persists complete commit frame bytes before live broadcast and replays the same bytes', async () => {
    const env = await makeEnv();
    const did = String(env.PDS_DID);
    const db = drizzle(env.ALTERAN_DB);
    await db.insert(commit_log).values({
      seq: 1,
      cid: PREVIOUS_CID,
      rev: 'prevrev',
      data: commitData(did, PREVIOUS_CID, 'prevrev', null),
      sig: 'sig',
      ts: Date.parse('2026-05-11T00:00:00.000Z'),
    }).run();
    await env.ALTERAN_DB
      .prepare("UPDATE firehose_sequence SET next_seq = 2 WHERE id = 'subscribeRepos'")
      .run();

    const live = fakeSocket();
    const { state, pending } = makeState([live.socket]);
    const sequencer = new Sequencer(state as any, env);
    await Promise.all(pending);

    const blocks = new Uint8Array([9, 8, 7, 6]);
    const response = await sequencer.fetch(new Request('https://sequencer/commit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        did: 'did:example:spoofed-notification',
        commitCid: CURRENT_CID,
        rev: 'newrev',
        data: commitData(did, CURRENT_CID, 'newrev', PREVIOUS_CID),
        sig: 'sig',
        ops: [{
          action: 'update',
          path: 'app.bsky.feed.post/abc',
          cid: CURRENT_CID,
          prev: PREVIOUS_CID,
        }],
        blocks: bytesToBase64(blocks),
      }),
    }));

    expect(response.status).toBe(200);
    expect(live.sent).toHaveLength(1);

    const stored = await db
      .select()
      .from(firehose_event)
      .where(eq(firehose_event.seq, 2))
      .get();
    expect(stored?.eventType).toBe('commit');
    expect(stored?.did).toBe(did);
    const storedBytes = atob(stored!.eventPayload);
    expect(Array.from(storedBytes, (char) => char.charCodeAt(0))).toEqual(Array.from(live.sent[0]));

    const decoded = decodeFrame(live.sent[0]);
    expect(decoded.header).toEqual({ op: FrameType.Message, t: '#commit' });
    const body = decoded.body as CommitMessage;
    expect(body.seq).toBe(2);
    expect(body.repo).toBe(did);
    expect(body.since).toBe('prevrev');
    expect(body.prevData?.toString()).toBe(PREVIOUS_CID);
    expect(Array.from(body.blocks)).toEqual(Array.from(blocks));
    expect(body.ops).toHaveLength(1);
    expect(body.ops[0].cid?.toString()).toBe(CURRENT_CID);
    expect(body.ops[0].prev?.toString()).toBe(PREVIOUS_CID);

    const replay = fakeSocket();
    const restartedState = makeState();
    const restarted = new Sequencer(restartedState.state as any, env);
    await Promise.all(restartedState.pending);
    await (restarted as any).replayFromCursor(replay.socket, 1);

    expect(replay.sent).toHaveLength(1);
    expect(Array.from(replay.sent[0])).toEqual(Array.from(live.sent[0]));
  });

  it('allocates one monotonic sequence across commit, identity, and account events', async () => {
    const env = await makeEnv();
    const did = String(env.PDS_DID);
    const live = fakeSocket();
    const { state, pending } = makeState([live.socket]);
    const sequencer = new Sequencer(state as any, env);
    await Promise.all(pending);

    await sequencer.fetch(new Request('https://sequencer/identity', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ did, handle: 'new.example' }),
    }));
    await sequencer.fetch(new Request('https://sequencer/account', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ did, active: false, status: 'suspended' }),
    }));
    await sequencer.fetch(new Request('https://sequencer/commit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        did,
        commitCid: CURRENT_CID,
        rev: 'newrev',
        data: commitData(did, CURRENT_CID, 'newrev', null),
        sig: 'sig',
        ops: [],
        blocks: bytesToBase64(new Uint8Array([1, 2, 3])),
      }),
    }));

    const rows = await drizzle(env.ALTERAN_DB)
      .select()
      .from(firehose_event)
      .orderBy(firehose_event.seq)
      .all();
    expect(rows.map((row) => [row.seq, row.eventType])).toEqual([
      [1, 'identity'],
      [2, 'account'],
      [3, 'commit'],
    ]);

    const replay = fakeSocket();
    await (sequencer as any).replayFromCursor(replay.socket, 0);
    const headers = replay.sent.map((bytes) => decodeFrame(bytes).header.t);
    expect(headers).toEqual(['#identity', '#account', '#commit']);
    expect(headers).not.toContain('#sync');
  });

  it('sends persisted rows before newer buffered rows without duplicates', async () => {
    const env = await makeEnv();
    const did = String(env.PDS_DID);
    const storedBytes = encodeIdentityFrame({
      seq: 5,
      did,
      time: '2026-05-11T00:00:00.000Z',
      handle: 'stored.example',
    });
    const duplicateBufferBytes = encodeIdentityFrame({
      seq: 5,
      did,
      time: '2026-05-11T00:00:01.000Z',
      handle: 'duplicate.example',
    });
    const bufferedBytes = encodeIdentityFrame({
      seq: 6,
      did,
      time: '2026-05-11T00:00:02.000Z',
      handle: 'buffered.example',
    });
    await env.ALTERAN_DB
      .prepare(
        `INSERT INTO firehose_event (seq, event_type, did, event_payload, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(5, 'identity', did, bytesToBase64(storedBytes), 1)
      .run();

    const { state, pending } = makeState();
    const sequencer = new Sequencer(state as any, env);
    await Promise.all(pending);
    (sequencer as any).buffer = [
      { seq: 5, eventType: 'identity', bytes: duplicateBufferBytes },
      { seq: 6, eventType: 'identity', bytes: bufferedBytes },
    ];

    const replay = fakeSocket();
    await (sequencer as any).replayFromCursor(replay.socket, 4);

    expect(replay.sent).toHaveLength(2);
    const bodies = replay.sent.map((bytes) => decodeFrame(bytes).body);
    expect(bodies.map((body) => body.seq)).toEqual([5, 6]);
    expect(bodies.map((body) => body.handle)).toEqual(['stored.example', 'buffered.example']);
  });

  it('does not replay malformed legacy commit_log rows that cannot reconstruct blocks', async () => {
    const env = await makeEnv();
    const did = String(env.PDS_DID);
    await drizzle(env.ALTERAN_DB).insert(commit_log).values({
      seq: 1,
      cid: CURRENT_CID,
      rev: 'legacyrev',
      data: commitData(did, CURRENT_CID, 'legacyrev', null),
      sig: 'sig',
      ts: Date.parse('2026-05-11T00:00:00.000Z'),
    }).run();

    const { state, pending } = makeState();
    const sequencer = new Sequencer(state as any, env);
    await Promise.all(pending);

    const replay = fakeSocket();
    const originalError = console.error;
    console.error = () => {};
    try {
      await (sequencer as any).replayFromCursor(replay.socket, 0);
    } finally {
      console.error = originalError;
    }

    expect(replay.sent).toHaveLength(0);
  });

  it('replays explicit cursor=0 through the WebSocket attachment path only', async () => {
    const env = await makeEnv();
    const did = String(env.PDS_DID);
    const storedBytes = encodeIdentityFrame({
      seq: 1,
      did,
      time: '2026-05-11T00:00:00.000Z',
      handle: 'stored.example',
    });
    await env.ALTERAN_DB
      .prepare(
        `INSERT INTO firehose_event (seq, event_type, did, event_payload, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(1, 'identity', did, bytesToBase64(storedBytes), 1)
      .run();

    const { state, pending } = makeState();
    const sequencer = new Sequencer(state as any, env);
    await Promise.all(pending);

    await withFakeWebSocketPair(async (server) => {
      const response = await sequencer.fetch(new Request(
        'https://sequencer/xrpc/com.atproto.sync.subscribeRepos?cursor=0',
        { headers: { Upgrade: 'websocket' } },
      ));
      expect(response.status).toBe(101);
      expect(server.attachment).toMatchObject({ cursor: 0, replay: true });
      await sequencer.webSocketOpen(server);
      expect(server.sent).toHaveLength(1);
      expect(decodeFrame(server.sent[0]).body.handle).toBe('stored.example');
    });

    await withFakeWebSocketPair(async (server) => {
      const response = await sequencer.fetch(new Request(
        'https://sequencer/xrpc/com.atproto.sync.subscribeRepos',
        { headers: { Upgrade: 'websocket' } },
      ));
      expect(response.status).toBe(101);
      expect(server.attachment).toMatchObject({ cursor: 0, replay: false });
      await sequencer.webSocketOpen(server);
      expect(server.sent).toHaveLength(0);
    });
  });
});
