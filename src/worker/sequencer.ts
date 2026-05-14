import type { DurableObjectState, D1Database } from '@cloudflare/workers-types';
import { drizzle } from 'drizzle-orm/d1';
import { commit_log } from '../db/schema';
import { gte, eq, desc } from 'drizzle-orm';
import { encodeInfoFrame, encodeCommitFrame } from '../lib/firehose/frames';
import type { Env } from '../env';
import { fromWireStatus } from '../lib/account-state';
import type {
  AccountEvent,
  Client,
  CommitEvent,
  IdentityEvent,
} from './sequencer/types';
import { reviveOps, base64ToBytes } from './sequencer/cid-helpers';
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
  Client,
  CommitEvent,
  IdentityEvent,
  SequencerEvent,
} from './sequencer/types';

export class Sequencer {
  private readonly state: HibernatableState;
  private readonly env: Env;
  private readonly clients = new Map<string, Client>();
  private buffer: CommitEvent[] = [];
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
        const last = await db
          .select({ seq: commit_log.seq })
          .from(commit_log)
          .orderBy(desc(commit_log.seq))
          .limit(1)
          .get();
        const dbNext = last?.seq ? Number(last.seq) + 1 : 1;
        if (!base || dbNext > base) base = dbNext;
      } catch (dbError) {
        console.warn('Sequencer: commit_log max(seq) failed:', dbError);
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
        seqForEvent = this.nextSeq++;
        await this.state.storage.put('nextSeq', this.nextSeq);
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
      } else if (seqForEvent >= this.nextSeq) {
        this.nextSeq = seqForEvent + 1;
        try {
          await this.state.storage.put('nextSeq', this.nextSeq);
        } catch (putError) {
          console.warn('Sequencer: storage.put(nextSeq) failed:', putError);
        }
      }

      const event: CommitEvent = {
        seq: seqForEvent,
        did: body.did,
        commitCid: body.commitCid,
        rev: body.rev,
        data: body.data,
        sig: body.sig,
        ts: tsForEvent,
        ops,
        blocks: body.blocks ? base64ToBytes(body.blocks) : undefined,
      };

      this.appendCommit(event);
      await this.broadcastCommit(event);

      return new Response('ok');
    } catch (error) {
      console.error('Failed to handle commit notification:', error);
      return new Response('bad request', { status: 400 });
    }
  }

  private async handleIdentityNotification(request: Request): Promise<Response> {
    try {
      const body = (await request.json()) as { did: string; handle?: string };
      const event: IdentityEvent = {
        seq: this.nextSeq++,
        did: body.did,
        handle: body.handle,
        ts: Date.now(),
      };
      try {
        await this.state.storage.put('nextSeq', this.nextSeq);
      } catch (putError) {
        console.warn('Sequencer: storage.put(nextSeq) failed:', putError);
      }
      await this.broadcastIdentity(event);
      return new Response('ok');
    } catch (error) {
      console.error('Failed to handle identity notification:', error);
      return new Response('bad request', { status: 400 });
    }
  }

  private async handleAccountNotification(request: Request): Promise<Response> {
    try {
      const body = (await request.json()) as { did: string; active: boolean; status?: string };
      const event: AccountEvent = {
        seq: this.nextSeq++,
        did: body.did,
        state: fromWireStatus({ active: body.active, status: body.status }),
        ts: Date.now(),
      };
      try {
        await this.state.storage.put('nextSeq', this.nextSeq);
      } catch (putError) {
        console.warn('Sequencer: storage.put(nextSeq) failed:', putError);
      }
      await this.broadcastAccount(event);
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
      onClient: (id, cursor, server) => {
        this.clients.set(id, { webSocket: server, id, cursor });
      },
    });
  }

  private async replayFromCursor(ws: WebSocket, cursor: number): Promise<void> {
    const sentSeqs = new Set<number>();
    const sendCommitEvent = async (event: CommitEvent, source: string) => {
      try {
        const message = await createCommitPayload(this.env, this.db, event);
        ws.send(encodeCommitFrame(message));
        sentSeqs.add(event.seq);
      } catch (error) {
        console.error(`Failed to send ${source} event:`, error);
      }
    };

    try {
      const db = drizzle(this.db);
      const events = await db
        .select()
        .from(commit_log)
        .where(gte(commit_log.seq, cursor))
        .orderBy(commit_log.seq)
        .limit(100)
        .all();

      for (const event of events) {
        try {
          if (event.seq == null) continue;
          const commitEvent: CommitEvent = {
            seq: event.seq,
            did: JSON.parse(event.data).did,
            commitCid: event.cid,
            rev: event.rev,
            data: event.data,
            sig: event.sig,
            ts: event.ts,
          };
          await sendCommitEvent(commitEvent, 'database');
        } catch (error) {
          console.error('Failed to send database event:', error);
        }
      }
    } catch (error) {
      console.error('Failed to fetch events from database:', error);
    }

    const bufferedEvents = this.buffer.filter((e) => e.seq >= cursor && !sentSeqs.has(e.seq));
    for (const event of bufferedEvents) {
      await sendCommitEvent(event, 'buffered');
    }
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

  private broadcastCommit(event: CommitEvent): Promise<void> {
    return broadcastCommit(this.env, this.db, this.getSocketTargets(), event);
  }

  private broadcastIdentity(event: IdentityEvent): void {
    broadcastIdentity(this.getSocketTargets(), event);
  }

  private broadcastAccount(event: AccountEvent): void {
    broadcastAccount(this.getSocketTargets(), event);
  }

  private appendCommit(event: CommitEvent): void {
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

    let cursor: number | null | undefined;
    try {
      const attachment = (ws as HibernatableSocket).deserializeAttachment?.();
      if (attachment && (typeof attachment.cursor === 'number' || attachment.cursor === null)) {
        cursor = attachment.cursor;
      }
    } catch (attachError) {
      console.warn('Sequencer: deserializeAttachment failed on open:', attachError);
    }
    if (cursor == null) {
      const client = Array.from(this.clients.values()).find((c) => c.webSocket === ws);
      if (client) cursor = client.cursor;
    }
    if (typeof cursor === 'number') {
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
