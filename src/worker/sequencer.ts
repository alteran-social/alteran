import type { DurableObjectState, D1Database } from '@cloudflare/workers-types';
import { drizzle } from 'drizzle-orm/d1';
import { commit_log, firehose_event } from '../db/schema';
import { gt, eq, desc } from 'drizzle-orm';
import {
  encodeAccountFrame,
  encodeCommitFrame,
  encodeIdentityFrame,
  encodeInfoFrame,
} from '../lib/firehose/frames';
import type { Env } from '../env';
import { fromWireStatus, toWireStatus } from '../lib/account-state';
import { allocateFirehoseSeq } from '../db/firehose';
import { RepoManager } from '../services/repo-manager';
import { CID } from 'multiformats/cid';
import type {
  AccountEvent,
  BufferedFirehoseEvent,
  Client,
  CommitEvent,
  IdentityEvent,
} from './sequencer/types';
import { reviveOps, base64ToBytes, bytesToBase64 } from './sequencer/cid-helpers';
import { createCommitPayload } from './sequencer/payload';
import {
  handleUpgrade,
  type HibernatableSocket,
  type HibernatableState,
  type WebSocketAttachment,
} from './sequencer/upgrade';
import {
  broadcastAccount,
  broadcastCommit,
  broadcastIdentity,
} from './sequencer/broadcast';

export type {
  AccountEvent,
  BufferedFirehoseEvent,
  Client,
  CommitEvent,
  IdentityEvent,
  SequencerEvent,
} from './sequencer/types';

export class Sequencer {
  private readonly state: HibernatableState;
  private readonly env: Env;
  private readonly clients = new Map<string, Client>();
  private buffer: BufferedFirehoseEvent[] = [];
  private readonly db: D1Database;
  private maxWindow: number;
  private nextSeq = 1;
  private droppedFrameCount = 0;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state as HibernatableState;
    this.env = env;
    this.db = env.ALTERAN_DB;
    this.maxWindow = parseInt(env.PDS_SEQ_WINDOW || '512', 10);

    // Reconcile nextSeq with DB on construction so replay and append agree
    // after worker restarts or DO migrations.
    this.state.blockConcurrencyWhile(async () => {
      let base = 0;
      try {
        base = (await this.state.storage.get<number>('nextSeq')) || 0;
      } catch (storageError) {
        console.warn('Sequencer: storage.get(nextSeq) failed:', storageError);
      }
      try {
        const db = drizzle(this.db);
        const lastCommit = await db
          .select({ seq: commit_log.seq })
          .from(commit_log)
          .orderBy(desc(commit_log.seq))
          .limit(1)
          .get();
        const lastEvent = await db
          .select({ seq: firehose_event.seq })
          .from(firehose_event)
          .orderBy(desc(firehose_event.seq))
          .limit(1)
          .get();
        const dbNext = Math.max(Number(lastCommit?.seq ?? 0), Number(lastEvent?.seq ?? 0)) + 1;
        if (!base || dbNext > base) base = dbNext;
      } catch (dbError) {
        console.warn('Sequencer: firehose seq reconciliation failed:', dbError);
      }
      this.nextSeq = base > 0 ? base : 1;
      try {
        await this.state.storage.put('nextSeq', this.nextSeq);
      } catch (storageError) {
        console.warn('Sequencer: storage.put(nextSeq) failed:', storageError);
      }
    });
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'POST') {
      if (url.pathname === '/commit') return this.handleCommitNotification(request);
      if (url.pathname === '/identity') return this.handleIdentityNotification(request);
      if (url.pathname === '/account') return this.handleAccountNotification(request);
    }

    if (request.method === 'GET' && url.pathname === '/metrics') {
      return this.handleMetrics();
    }

    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader !== 'websocket') {
      return new Response('Expected websocket', { status: 426 });
    }

    return this.handleWebSocketUpgrade(request, url);
  }

  private async handleCommitNotification(request: Request): Promise<Response> {
    try {
      const body = (await request.json()) as {
        did: string;
        commitCid: string;
        rev: string;
        data: string;
        sig: string;
        ops?: unknown;
        blocks?: string;
      };

      const ops = reviveOps(body.ops);

      const db = drizzle(this.db);
      let seqForEvent: number | null = null;
      let tsForEvent = Date.now();
      try {
        const row = await db
          .select({
            seq: commit_log.seq,
            rev: commit_log.rev,
            data: commit_log.data,
            sig: commit_log.sig,
            ts: commit_log.ts,
          })
          .from(commit_log)
          .where(eq(commit_log.cid, body.commitCid))
          .limit(1)
          .get();
        if (row && typeof row.seq === 'number') {
          seqForEvent = row.seq;
          body.rev = row.rev;
          body.data = row.data;
          body.sig = row.sig;
          tsForEvent = row.ts ?? tsForEvent;
        }
      } catch (lookupError) {
        console.warn('commit_log lookup failed:', lookupError);
      }

      if (seqForEvent == null) {
        seqForEvent = await allocateFirehoseSeq(this.env);
        try {
          await db
            .insert(commit_log)
            .values({
              seq: seqForEvent,
              cid: body.commitCid,
              rev: body.rev,
              data: body.data,
              sig: body.sig,
              ts: tsForEvent,
            })
            .run();
        } catch (insertError) {
          console.warn('commit_log insert failed:', insertError);
        }
      }
      await this.advanceNextSeq(seqForEvent);

      const commitDid = (() => {
        try {
          const parsed = JSON.parse(body.data) as { did?: unknown };
          return typeof parsed.did === 'string' ? parsed.did : body.did;
        } catch {
          return body.did;
        }
      })();

      const event: CommitEvent = {
        seq: seqForEvent,
        did: commitDid,
        commitCid: body.commitCid,
        rev: body.rev,
        data: body.data,
        sig: body.sig,
        ts: tsForEvent,
        ops,
        blocks: body.blocks ? base64ToBytes(body.blocks) : undefined,
      };

      const message = await createCommitPayload(this.env, this.db, event);
      const frameBytes = encodeCommitFrame(message);
      await this.persistFirehoseEvent('commit', event.seq, event.did, frameBytes, event.ts);
      this.appendEvent({ seq: event.seq, eventType: 'commit', bytes: frameBytes });
      await this.broadcastCommit(event, frameBytes);

      return new Response('ok');
    } catch (error) {
      console.error('Failed to handle commit notification:', error);
      return new Response('bad request', { status: 400 });
    }
  }

  private async handleIdentityNotification(request: Request): Promise<Response> {
    try {
      const body = (await request.json()) as { did: string; handle?: string };
      const seq = await allocateFirehoseSeq(this.env);
      const event: IdentityEvent = {
        seq,
        did: body.did,
        handle: body.handle,
        ts: Date.now(),
      };
      await this.advanceNextSeq(event.seq);
      const frameBytes = this.encodeIdentityEvent(event);
      await this.persistFirehoseEvent('identity', event.seq, event.did, frameBytes, event.ts);
      this.appendEvent({ seq: event.seq, eventType: 'identity', bytes: frameBytes });
      await this.broadcastIdentity(event, frameBytes);
      return new Response('ok');
    } catch (error) {
      console.error('Failed to handle identity notification:', error);
      return new Response('bad request', { status: 400 });
    }
  }

  private async handleAccountNotification(request: Request): Promise<Response> {
    try {
      const body = (await request.json()) as { did: string; active: boolean; status?: string };
      const seq = await allocateFirehoseSeq(this.env);
      const event: AccountEvent = {
        seq,
        did: body.did,
        state: fromWireStatus({ active: body.active, status: body.status }),
        ts: Date.now(),
      };
      await this.advanceNextSeq(event.seq);
      const frameBytes = this.encodeAccountEvent(event);
      await this.persistFirehoseEvent('account', event.seq, event.did, frameBytes, event.ts);
      this.appendEvent({ seq: event.seq, eventType: 'account', bytes: frameBytes });
      await this.broadcastAccount(event, frameBytes);
      return new Response('ok');
    } catch (error) {
      console.error('Failed to handle account notification:', error);
      return new Response('bad request', { status: 400 });
    }
  }

  private handleWebSocketUpgrade(request: Request, url: URL): Response {
    const hibernate = String(this.env.PDS_WS_HIBERNATE ?? 'true').toLowerCase() !== 'false';
    return handleUpgrade(request, url, {
      state: this.state,
      nextSeq: this.nextSeq,
      hibernate,
      onClient: (id, cursor, replay, server) => {
        this.clients.set(id, { webSocket: server, id, cursor, replay });
      },
    });
  }

  private async replayFromCursor(ws: WebSocket, cursor: number): Promise<void> {
    let lastSentSeq = cursor;

    try {
      const db = drizzle(this.db);
      const replayEvents: BufferedFirehoseEvent[] = [];
      const storedEvents = await db
        .select()
        .from(firehose_event)
        .where(gt(firehose_event.seq, cursor))
        .orderBy(firehose_event.seq)
        .limit(this.maxWindow)
        .all();
      const storedSeqs = new Set<number>();

      for (const event of storedEvents) {
        try {
          if (event.seq == null) continue;
          storedSeqs.add(event.seq);
          replayEvents.push({
            seq: event.seq,
            eventType: event.eventType,
            bytes: base64ToBytes(event.eventPayload),
          });
        } catch (error) {
          console.error('Failed to decode stored firehose event:', error);
        }
      }

      const legacyCommits = await db
        .select()
        .from(commit_log)
        .where(gt(commit_log.seq, cursor))
        .orderBy(commit_log.seq)
        .limit(this.maxWindow)
        .all();

      for (const event of legacyCommits) {
        if (event.seq == null || storedSeqs.has(event.seq)) continue;
        try {
          const fallback = await this.reconstructLegacyCommit(event);
          if (fallback) replayEvents.push(fallback);
        } catch (error) {
          console.error('Failed to reconstruct legacy commit event:', error);
        }
      }

      replayEvents.sort((a, b) => a.seq - b.seq);
      for (const event of replayEvents.slice(0, this.maxWindow)) {
        try {
          ws.send(event.bytes);
          lastSentSeq = Math.max(lastSentSeq, event.seq);
        } catch (error) {
          console.error('Failed to send persisted event:', error);
        }
      }
    } catch (error) {
      console.error('Failed to fetch events from database:', error);
    }

    const bufferedEvents = this.buffer
      .filter((e) => e.seq > lastSentSeq)
      .sort((a, b) => a.seq - b.seq);

    for (const event of bufferedEvents) {
      try {
        ws.send(event.bytes);
      } catch (error) {
        console.error('Failed to send buffered event:', error);
      }
    }
  }

  private async reconstructLegacyCommit(
    row: typeof commit_log.$inferSelect,
  ): Promise<BufferedFirehoseEvent | null> {
    if (row.seq == null) return null;
    const commitData = JSON.parse(row.data) as { did?: string; data?: string; prev?: string | null };
    if (!commitData.did || !commitData.data) return null;

    const repoManager = new RepoManager(this.env);
    const newRoot = CID.parse(String(commitData.data));
    let prevRoot: CID | null = null;
    if (commitData.prev) {
      const previous = await drizzle(this.db)
        .select()
        .from(commit_log)
        .where(eq(commit_log.cid, String(commitData.prev)))
        .limit(1)
        .get();
      if (!previous?.data) return null;
      const previousData = JSON.parse(previous.data) as { data?: string };
      if (!previousData.data) return null;
      prevRoot = CID.parse(String(previousData.data));
    }

    const ops = await repoManager.extractOps(prevRoot, newRoot);
    const commitEvent: CommitEvent = {
      seq: row.seq,
      did: commitData.did,
      commitCid: row.cid,
      rev: row.rev,
      data: row.data,
      sig: row.sig,
      ts: row.ts,
      ops,
    };
    const message = await createCommitPayload(this.env, this.db, commitEvent);
    if (message.blocks.byteLength === 0) return null;
    if (commitData.prev && !message.prevData) return null;
    return {
      seq: row.seq,
      eventType: 'commit',
      bytes: encodeCommitFrame(message),
    };
  }

  private getSocketTargets(): WebSocket[] {
    let sockets: WebSocket[] = [];
    try {
      // workers-types WebSocket misses a few DOM-types members; the values
      // are wire-compatible at runtime, so widen through unknown.
      sockets = (this.state.getWebSockets?.() || []) as unknown as WebSocket[];
    } catch (error) {
      console.warn('Sequencer: getWebSockets failed:', error);
    }
    return sockets.length > 0
      ? sockets
      : Array.from(this.clients.values()).map((c) => c.webSocket);
  }

  private async advanceNextSeq(seq: number): Promise<void> {
    if (seq >= this.nextSeq) {
      this.nextSeq = seq + 1;
      try {
        await this.state.storage.put('nextSeq', this.nextSeq);
      } catch (putError) {
        console.warn('Sequencer: storage.put(nextSeq) failed:', putError);
      }
    }
  }

  private async persistFirehoseEvent(
    eventType: string,
    seq: number,
    did: string,
    frameBytes: Uint8Array,
    createdAt: number,
  ): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO firehose_event (seq, event_type, did, event_payload, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(seq) DO UPDATE SET
           event_type = excluded.event_type,
           did = excluded.did,
           event_payload = excluded.event_payload,
           created_at = excluded.created_at`,
      )
      .bind(seq, eventType, did, bytesToBase64(frameBytes), createdAt)
      .run();
  }

  private encodeIdentityEvent(event: IdentityEvent): Uint8Array {
    return encodeIdentityFrame({
      seq: event.seq,
      did: event.did,
      time: new Date(event.ts).toISOString(),
      handle: event.handle,
    });
  }

  private encodeAccountEvent(event: AccountEvent): Uint8Array {
    const time = new Date(event.ts).toISOString();
    const wire = toWireStatus(event.state);
    const base = { seq: event.seq, did: event.did, time, active: wire.active };
    return encodeAccountFrame(wire.status ? { ...base, status: wire.status } : base);
  }

  private broadcastCommit(event: CommitEvent, frameBytes: Uint8Array): Promise<void> {
    return broadcastCommit(this.env, this.db, this.getSocketTargets(), event, frameBytes);
  }

  private broadcastIdentity(event: IdentityEvent, frameBytes: Uint8Array): void {
    broadcastIdentity(this.getSocketTargets(), event, frameBytes);
  }

  private broadcastAccount(event: AccountEvent, frameBytes: Uint8Array): void {
    broadcastAccount(this.getSocketTargets(), event, frameBytes);
  }

  private appendEvent(event: BufferedFirehoseEvent): void {
    this.buffer.push(event);

    if (this.buffer.length > this.maxWindow) {
      const dropped = this.buffer.shift();
      this.droppedFrameCount++;
      console.warn(
        `Dropped event seq=${dropped?.seq} due to backpressure (total dropped: ${this.droppedFrameCount})`,
      );
      this.notifyFramesDropped();
    }
  }

  private notifyFramesDropped(): void {
    const bytes = encodeInfoFrame(
      'FramesDropped',
      `${this.droppedFrameCount} frame(s) dropped due to backpressure`,
    );

    for (const [id, client] of Array.from(this.clients.entries())) {
      try {
        client.webSocket.send(bytes);
      } catch (error) {
        console.error(`Failed to send info frame to client ${id}:`, error);
      }
    }
  }

  getMetrics(): {
    connectedClients: number;
    bufferSize: number;
    nextSeq: number;
    droppedFrames: number;
  } {
    return {
      connectedClients: this.clients.size,
      bufferSize: this.buffer.length,
      nextSeq: this.nextSeq,
      droppedFrames: this.droppedFrameCount,
    };
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const client = Array.from(this.clients.values()).find((c) => c.webSocket === ws);
    if (!client) {
      console.warn('Received message from unknown WebSocket');
      return;
    }

    try {
      const data = typeof message === 'string' ? message : new TextDecoder().decode(message);
      if (data === 'ping') ws.send('pong');
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  }

  private async handleMetrics(): Promise<Response> {
    const base = this.getMetrics();
    let sockets: WebSocket[] = [];
    try {
      // workers-types WebSocket misses a few DOM-types members; the values
      // are wire-compatible at runtime, so widen through unknown.
      sockets = (this.state.getWebSockets?.() || []) as unknown as WebSocket[];
    } catch (error) {
      console.warn('Sequencer: getWebSockets failed in metrics:', error);
    }
    const clients = sockets.map((ws) => {
      let attachment: WebSocketAttachment | undefined;
      try {
        attachment = (ws as HibernatableSocket).deserializeAttachment?.();
      } catch (attachError) {
        console.warn('Sequencer: deserializeAttachment failed in metrics:', attachError);
      }
      return { attachment: attachment ?? null };
    });
    const body = {
      ...base,
      hibernatedSockets: sockets.length,
      clients,
    };
    return new Response(JSON.stringify(body), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  async webSocketOpen(ws: WebSocket): Promise<void> {
    console.log(JSON.stringify({ level: 'info', type: 'ws_open', ts: new Date().toISOString() }));

    let cursor: number | undefined;
    let replay = false;
    try {
      const attachment = (ws as HibernatableSocket).deserializeAttachment?.();
      if (attachment && typeof attachment.cursor === 'number') {
        cursor = attachment.cursor;
        replay = attachment.replay === true;
      }
    } catch (attachError) {
      console.warn('Sequencer: deserializeAttachment failed on open:', attachError);
    }
    if (cursor == null) {
      const client = Array.from(this.clients.values()).find((c) => c.webSocket === ws);
      if (client) {
        cursor = client.cursor;
        replay = client.replay;
      }
    }
    if (replay && cursor != null) {
      await this.replayFromCursor(ws, cursor);
    }
  }

  async webSocketClose(
    ws: WebSocket,
    code: number,
    reason: string,
    wasClean: boolean,
  ): Promise<void> {
    const entry = Array.from(this.clients.entries()).find(([, c]) => c.webSocket === ws);
    if (entry) {
      this.clients.delete(entry[0]);
      console.log(
        `Client ${entry[0]} disconnected: code=${code} reason="${reason}" clean=${wasClean}`,
      );
    }
  }

  async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    const entry = Array.from(this.clients.entries()).find(([, c]) => c.webSocket === ws);
    if (entry) {
      this.clients.delete(entry[0]);
      console.error(`Client ${entry[0]} error:`, error);
    }
  }
}
