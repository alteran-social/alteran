// Types via tsconfig

import type { DurableObjectState, D1Database } from '@cloudflare/workers-types';
import { drizzle } from 'drizzle-orm/d1';
import { commit_log } from '../db/schema';
import { gt, eq, desc } from 'drizzle-orm';
import {
  encodeInfoFrame,
  encodeCommitFrame,
  encodeIdentityFrame,
  encodeAccountFrame,
  encodeSyncFrame,
  type CommitMessage,
  type RepoOp,
} from '../lib/firehose/frames';
import { checkCursor } from '../lib/firehose/validation';
import { CID } from 'multiformats/cid';
import { encodeBlocksForCommit } from '../services/car';
import type { Env } from '../env';

interface Client {
  webSocket: WebSocket;
  id: string;
  cursor: number;
}

interface CommitEvent {
  seq: number;
  did: string;
  commitCid: string;
  rev: string;
  data: string; // JSON-encoded commit data
  sig: string; // base64 signature
  ts: number;
  ops?: RepoOp[];
  blocks?: Uint8Array;
}

interface IdentityEvent {
  seq: number;
  did: string;
  handle?: string;
  ts: number;
}

interface AccountEvent {
  seq: number;
  did: string;
  active: boolean;
  status?: string;
  ts: number;
}

type SequencerEvent = CommitEvent | IdentityEvent | AccountEvent;

/**
 * Sequencer Durable Object
 * Manages the firehose event stream for repository updates
 */
export class Sequencer {
  private readonly state: DurableObjectState;
  private readonly env: Env & { PDS_SEQ_WINDOW?: string };
  // NOTE: With hibernating WebSockets, do NOT rely on in-memory maps of clients.
  // Use state.getWebSockets() to fetch currently-connected sockets when broadcasting.
  private readonly clients = new Map<string, Client>();
  private buffer: CommitEvent[] = [];
  private readonly db: D1Database;
  private maxWindow: number;
  private nextSeq = 1;
  private droppedFrameCount = 0;

  constructor(state: DurableObjectState, env: Env & { PDS_SEQ_WINDOW?: string }) {
    this.state = state;
    this.env = env;
    this.db = env.DB;
    this.maxWindow = parseInt(env.PDS_SEQ_WINDOW || '512', 10);

    // Initialize from storage and align with DB max(seq).
    // Guard storage access to avoid errors during code upgrades on old instances.
    this.state.blockConcurrencyWhile(async () => {
      let base = 0;
      try {
        base = (await this.state.storage.get<number>('nextSeq')) || 0;
      } catch (e) {
        // Storage may be unavailable on outdated instances; ignore and derive from DB
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
      } catch {}
      this.nextSeq = base > 0 ? base : 1;
      try {
        await this.state.storage.put('nextSeq', this.nextSeq);
      } catch (e) {
        // Ignore if storage unavailable on this instance
      }
    });
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Handle event notifications from PDS
    if (request.method === 'POST') {
      if (url.pathname === '/commit') {
        return this.handleCommitNotification(request);
      } else if (url.pathname === '/identity') {
        return this.handleIdentityNotification(request);
      } else if (url.pathname === '/account') {
        return this.handleAccountNotification(request);
      }
    }

    // Debug metrics endpoint for observability
    if (request.method === 'GET' && url.pathname === '/metrics') {
      return this.handleMetrics();
    }

    // Handle WebSocket upgrade for firehose subscription
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader !== 'websocket') {
      return new Response('Expected websocket', { status: 426 });
    }

    return this.handleWebSocketUpgrade(request, url);
  }

  /**
   * Handle commit notification from PDS
   */
  private async handleCommitNotification(request: Request): Promise<Response> {
    try {
      const body = (await request.json()) as {
        did: string;
        commitCid: string;
        rev: string;
        data: string;
        sig: string;
        ops?: RepoOp[];
        blocks?: string; // base64-encoded CAR
      };

      // Revive CIDs inside ops (JSON -> CID)
      const reviveCid = (val: any): CID | null => {
        try {
          if (val == null) return null;
          // If already a CID instance
          const as = (CID as any).asCID?.(val);
          if (as) return as as CID;
          // If encoded as string
          if (typeof val === 'string') return CID.parse(val);
          // If dag-json style: { "/": "baf..." }
          if (val && typeof val === 'object' && typeof val['/'] === 'string') return CID.parse(val['/']);
        } catch {}
        return null;
      };

      if (Array.isArray(body.ops)) {
        body.ops = body.ops.map((op: any) => ({
          action: op.action,
          path: op.path,
          cid: reviveCid(op.cid),
          ...(op.prev != null ? { prev: reviveCid(op.prev) ?? undefined } : {}),
        })) as any;
      }

      // Helper: base64 to Uint8Array (workers-safe)
      const b64ToBytes = (b64: string): Uint8Array => {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
      };

      // Determine sequence for this commit based on DB, ensuring consistency with replay
      const db = drizzle(this.db);
      let seqForEvent: number | null = null;
      let tsForEvent = Date.now();
      try {
        const row = await db
          .select({ seq: commit_log.seq, rev: commit_log.rev, data: commit_log.data, sig: commit_log.sig, ts: commit_log.ts })
          .from(commit_log)
          .where(eq(commit_log.cid, body.commitCid))
          .limit(1)
          .get();
        if (row && typeof row.seq === 'number') {
          seqForEvent = row.seq;
          // Keep event fields aligned with DB if present
          body.rev = row.rev;
          body.data = row.data;
          body.sig = row.sig;
          tsForEvent = row.ts ?? tsForEvent;
        }
      } catch {}

      if (seqForEvent == null) {
        // No row yet: assign nextSeq and insert minimal row for replay
        seqForEvent = this.nextSeq++;
        await this.state.storage.put('nextSeq', this.nextSeq);
        try {
          await db
            .insert(commit_log)
            .values({ seq: seqForEvent, cid: body.commitCid, rev: body.rev, data: body.data, sig: body.sig, ts: tsForEvent })
            .run();
        } catch (e) {
          console.warn('commit_log insert failed:', e);
        }
      } else if (seqForEvent >= this.nextSeq) {
        // Ensure counter advances beyond DB
        this.nextSeq = seqForEvent + 1;
        try { await this.state.storage.put('nextSeq', this.nextSeq); } catch {}
      }

      const event: CommitEvent = {
        seq: seqForEvent,
        did: body.did,
        commitCid: body.commitCid,
        rev: body.rev,
        data: body.data,
        sig: body.sig,
        ts: tsForEvent,
        ops: body.ops,
        blocks: body.blocks ? b64ToBytes(body.blocks) : undefined,
      };

      // Add to buffer
      this.appendCommit(event);

      // Broadcast to all connected clients
      await this.broadcastCommit(event);

      return new Response('ok');
    } catch (error) {
      console.error('Failed to handle commit notification:', error);
      return new Response('bad request', { status: 400 });
    }
  }

  /**
   * Handle identity notification from PDS (handle changes)
   */
  private async handleIdentityNotification(request: Request): Promise<Response> {
    try {
      const body = (await request.json()) as {
        did: string;
        handle?: string;
      };

      const event: IdentityEvent = {
        seq: this.nextSeq++,
        did: body.did,
        handle: body.handle,
        ts: Date.now(),
      };

      // Persist sequence number
      try { await this.state.storage.put('nextSeq', this.nextSeq); } catch {}

      // Broadcast to all connected clients
      await this.broadcastIdentity(event);

      return new Response('ok');
    } catch (error) {
      console.error('Failed to handle identity notification:', error);
      return new Response('bad request', { status: 400 });
    }
  }

  /**
   * Handle account notification from PDS (account status changes)
   */
  private async handleAccountNotification(request: Request): Promise<Response> {
    try {
      const body = (await request.json()) as {
        did: string;
        active: boolean;
        status?: string;
      };

      const event: AccountEvent = {
        seq: this.nextSeq++,
        did: body.did,
        active: body.active,
        status: body.status,
        ts: Date.now(),
      };

      // Persist sequence number
      try { await this.state.storage.put('nextSeq', this.nextSeq); } catch {}

      // Broadcast to all connected clients
      await this.broadcastAccount(event);

      return new Response('ok');
    } catch (error) {
      console.error('Failed to handle account notification:', error);
      return new Response('bad request', { status: 400 });
    }
  }

  /**
   * Handle WebSocket upgrade for firehose subscription
   */
  private async handleWebSocketUpgrade(request: Request, url: URL): Promise<Response> {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const id = crypto.randomUUID();

    // Parse cursor parameter
    const cursorParam = url.searchParams.get('cursor');
    const cursor = cursorParam ? parseInt(cursorParam, 10) : 0;

    // If the client requested a subprotocol, remember the first value so we can echo it.
    // Some WebSocket clients will close immediately (1006) if the server does not
    // negotiate a requested subprotocol.
    const requestedProtoHeader = request.headers.get('Sec-WebSocket-Protocol') || request.headers.get('sec-websocket-protocol');
    const requestedProtocol = requestedProtoHeader
      ? requestedProtoHeader.split(',').map((s) => s.trim()).filter(Boolean)[0] || undefined
      : undefined;

    // Validate cursor
    if (cursor > this.nextSeq - 1) {
      // Future cursor requested: send an info event then close with 1008.
      // Use standard WebSocket accept for this short-lived connection to avoid
      // mixing hibernation API semantics.
      try { (server as any).accept?.(); } catch {}
      const info = encodeInfoFrame('OutdatedCursor', 'Cursor is ahead of current sequence');
      try { server.send(info); } catch {}
      try { server.close(1008, 'OutdatedCursor'); } catch {}
      const headers = new Headers();
      if (requestedProtocol) headers.set('Sec-WebSocket-Protocol', requestedProtocol);
      return new Response(null, { status: 101, webSocket: client, headers });
    }

    const hibernate = String((this.env as any).PDS_WS_HIBERNATE ?? 'true').toLowerCase() !== 'false';
    if (hibernate) {
      // Hibernation API
      this.state.acceptWebSocket(server as any);
      try { (server as any).serializeAttachment?.({ id, cursor }); } catch {}
      // Do not send an initial info frame; many clients expect first frame to be a real event.
    } else {
      // Standard WebSocket API fallback (no hibernation)
      (server as any).accept?.();
      // Minimal event listeners to keep the connection alive and observable
      (server as any).addEventListener?.('message', (evt: MessageEvent) => {
        try {
          const data = typeof evt.data === 'string' ? evt.data : new TextDecoder().decode(evt.data);
          if (data === 'ping') (server as any).send?.('pong');
        } catch {}
      });
      (server as any).addEventListener?.('close', (cls: any) => {
        try { console.log(`Client ${id} disconnected (std): code=${cls.code} reason=${cls.reason}`); } catch {}
      });
      // Do not send an initial info frame.
    }

    // Light-touch observability for upgrade events
    try {
      console.log(
        JSON.stringify({
          level: 'info',
          type: 'ws_upgrade',
          id,
          path: url.pathname,
          cursor,
          protocol: requestedProtocol || null,
          timestamp: new Date().toISOString(),
        }),
      );
    } catch {}

    const clientObj: Client = { webSocket: server as unknown as WebSocket, id, cursor };
    // Keep a best-effort in-memory record for same-isolate broadcasts.
    // Actual broadcasts will query state.getWebSockets() to handle hibernation/resumes.
    this.clients.set(id, clientObj);

    // Do not send or replay yet; wait for webSocketOpen to ensure handshake completed.
    // We'll send initial info and perform optional replay there.

    // Echo back the negotiated subprotocol if the client requested one.
    // Cloudflare will include standard Upgrade headers; we only add Sec-WebSocket-Protocol.
    const headers = new Headers();
    if (requestedProtocol) headers.set('Sec-WebSocket-Protocol', requestedProtocol);
    return new Response(null, { status: 101, webSocket: client, headers });
  }

  /**
   * Replay events from cursor
   */
  private async replayFromCursor(ws: WebSocket, cursor: number): Promise<void> {
    // First try from buffer
    const bufferedEvents = this.buffer.filter((e) => e.seq > cursor);

    if (bufferedEvents.length > 0) {
      for (const event of bufferedEvents) {
        try {
          const msg = await this.createCommitPayload(event);
          ws.send(encodeCommitFrame(msg));
        } catch (error) {
          console.error('Failed to send buffered event:', error);
        }
      }
    } else {
      // Fetch from database if not in buffer
      try {
        const db = drizzle(this.db);
        const events = await db
          .select()
          .from(commit_log)
          .where(gt(commit_log.seq, cursor))
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
            const message = await this.createCommitPayload(commitEvent);
            ws.send(encodeCommitFrame(message));
          } catch (error) {
            console.error('Failed to send database event:', error);
          }
        }
      } catch (error) {
        console.error('Failed to fetch events from database:', error);
      }
    }
  }

  /**
   * Broadcast commit event to all connected clients
   */
  private async broadcastCommit(event: CommitEvent): Promise<void> {
    const msg = await this.createCommitPayload(event);
    const bytes = encodeCommitFrame(msg);

    // Use hibernation-aware API to fetch sockets; do not rely on in-memory maps.
    let sockets: WebSocket[] = [];
    try {
      sockets = (this.state as any).getWebSockets?.() || [];
    } catch {}

    try {
      console.log(
        JSON.stringify({
          level: 'info',
          type: 'firehose_broadcast_start',
          seq: event.seq,
          clients: sockets.length || this.clients.size,
          ops: (event.ops || []).length,
          ts: new Date().toISOString(),
        }),
      );
    } catch {}

    const targets = sockets.length > 0 ? sockets : Array.from(this.clients.values()).map((c) => c.webSocket);
    let dropped = 0;
    for (const ws of targets) {
      try {
        ws.send(bytes);
      } catch (error) {
        dropped++;
      }
    }

    try {
      console.log(
        JSON.stringify({
          level: 'info',
          type: 'firehose_broadcast_end',
          seq: event.seq,
          clients: targets.length,
          dropped,
          ts: new Date().toISOString(),
        }),
      );
    } catch {}
  }

  /**
   * Broadcast identity event to all connected clients
   */
  private async broadcastIdentity(event: IdentityEvent): Promise<void> {
    const bytes = encodeIdentityFrame({
      seq: event.seq,
      did: event.did,
      time: new Date(event.ts).toISOString(),
      handle: event.handle,
    });
    let sockets: WebSocket[] = [];
    try { sockets = (this.state as any).getWebSockets?.() || []; } catch {}
    const targets = sockets.length > 0 ? sockets : Array.from(this.clients.values()).map((c) => c.webSocket);
    for (const ws of targets) {
      try { ws.send(bytes); } catch {}
    }
  }

  /**
   * Broadcast account event to all connected clients
   */
  private async broadcastAccount(event: AccountEvent): Promise<void> {
    const bytesAccount = encodeAccountFrame({
      seq: event.seq,
      did: event.did,
      time: new Date(event.ts).toISOString(),
      active: event.active,
      status: event.status,
    });
    // Emit compatibility #sync event as well
    const bytesSync = encodeSyncFrame({
      seq: event.seq,
      did: event.did,
      time: new Date(event.ts).toISOString(),
      active: event.active,
      status: event.status,
    });
    let sockets: WebSocket[] = [];
    try { sockets = (this.state as any).getWebSockets?.() || []; } catch {}
    const targets = sockets.length > 0 ? sockets : Array.from(this.clients.values()).map((c) => c.webSocket);
    for (const ws of targets) {
      try {
        ws.send(bytesAccount);
        ws.send(bytesSync);
      } catch {}
    }
  }

  /**
   * Create a #commit frame from event
   */
  private async createCommitPayload(event: CommitEvent): Promise<CommitMessage> {
    const commitData = JSON.parse(event.data);

    // If blocks weren't provided, encode them now
    let blocks = event.blocks;
    if (!blocks && event.ops && event.ops.length > 0) {
      try {
        const commitCid = CID.parse(event.commitCid);
        // Extract MST root from commit data
        const mstRoot = commitData.data ? CID.parse(commitData.data) : commitCid;
        blocks = await encodeBlocksForCommit(
          this.env as Env,
          commitCid,
          mstRoot,
          event.ops,
        );
      } catch (error) {
        console.error('Failed to encode blocks for commit:', error);
        blocks = new Uint8Array();
      }
    }

    // Resolve prev commit and since (previous rev) when available
    let prevCid: CID | null = null;
    let prevDataCid: CID | null = null;
    try {
      if (commitData.prev) prevCid = CID.parse(String(commitData.prev));
    } catch {}

    let since: string | null = null;
    try {
      const db = drizzle(this.db);
      if (prevCid) {
        const prev = await db.select().from(commit_log).where(eq(commit_log.cid, prevCid.toString())).get();
        since = prev?.rev ?? null;
        if (prev?.data) {
          try { prevDataCid = CID.parse(String(JSON.parse(prev.data).data)); } catch {}
        }
      } else {
        const row = await db.select().from(commit_log).where(gt(commit_log.seq, 0 as any)).orderBy(desc(commit_log.seq)).limit(1).get();
        since = row?.rev ?? null;
      }
    } catch {}

    const message: CommitMessage = {
      seq: event.seq,
      rebase: false,
      tooBig: false,
      repo: event.did,
      commit: CID.parse(event.commitCid),
      prev: prevCid,
      rev: event.rev,
      since,
      blocks: blocks || new Uint8Array(),
      ops: event.ops || [],
      blobs: [],
      time: new Date(event.ts).toISOString(),
      ...(prevDataCid ? { prevData: prevDataCid } : {}),
    };

    return message;
  }

  /**
   * Append commit event to buffer with backpressure
   */
  private appendCommit(event: CommitEvent): void {
    this.buffer.push(event);

    // Implement backpressure: drop oldest events if buffer is full
    if (this.buffer.length > this.maxWindow) {
      const dropped = this.buffer.shift();
      this.droppedFrameCount++;
      console.warn(`Dropped event seq=${dropped?.seq} due to backpressure (total dropped: ${this.droppedFrameCount})`);

      // Send #info frame to all clients about dropped frames
      this.notifyFramesDropped();
    }
  }

  /**
   * Notify all clients that frames were dropped
   */
  private notifyFramesDropped(): void {
    const bytes = encodeInfoFrame('FramesDropped', `${this.droppedFrameCount} frame(s) dropped due to backpressure`);

    for (const [id, client] of Array.from(this.clients.entries())) {
      try {
        client.webSocket.send(bytes);
      } catch (error) {
        console.error(`Failed to send info frame to client ${id}:`, error);
      }
    }
  }

  /**
   * Get metrics
   */
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

  /**
   * WebSocket hibernation handler: called when a message is received
   * This is required for Cloudflare's hibernatable WebSocket API
   */
  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    // Find client by WebSocket instance
    const client = Array.from(this.clients.values()).find((c) => c.webSocket === ws);
    if (!client) {
      console.warn('Received message from unknown WebSocket');
      return;
    }

    try {
      const data = typeof message === 'string' ? message : new TextDecoder().decode(message);
      if (data === 'ping') {
        ws.send('pong');
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  }

  /**
   * Return current metrics + attachments for debugging
   */
  private async handleMetrics(): Promise<Response> {
    const base = this.getMetrics();
    let sockets: WebSocket[] = [];
    try { sockets = (this.state as any).getWebSockets?.() || []; } catch {}
    const clients = sockets.map((ws) => {
      let att: any = null;
      try { att = (ws as any).deserializeAttachment?.(); } catch {}
      return {
        attachment: att,
      };
    });
    const body = {
      ...base,
      hibernatedSockets: sockets.length,
      clients,
    };
    return new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
  }

  /**
   * WebSocket hibernation handler: called when the connection is established or resumed
   */
  async webSocketOpen(ws: WebSocket): Promise<void> {
    try {
      console.log(JSON.stringify({ level: 'info', type: 'ws_open', ts: new Date().toISOString() }));
    } catch {}

    // Do not send an initial info frame.

    // Best-effort: if this socket has an associated cursor, replay.
    // Prefer durable attachment; fall back to in-memory map if present.
    let cursor: number | undefined;
    try {
      const att = (ws as any).deserializeAttachment?.();
      if (att && typeof att.cursor === 'number') cursor = att.cursor;
    } catch {}
    if (cursor == null) {
      const client = Array.from(this.clients.values()).find((c) => c.webSocket === ws);
      if (client) cursor = client.cursor;
    }
    if (cursor && cursor > 0) {
      await this.replayFromCursor(ws, cursor);
    }
  }

  /**
   * WebSocket hibernation handler: called when connection closes
   * This is required for Cloudflare's hibernatable WebSocket API
   */
  async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean): Promise<void> {
    // Find and remove client
    const entry = Array.from(this.clients.entries()).find(([_, c]) => c.webSocket === ws);
    if (entry) {
      this.clients.delete(entry[0]);
      console.log(`Client ${entry[0]} disconnected: code=${code} reason="${reason}" clean=${wasClean}`);
    }
  }

  /**
   * WebSocket hibernation handler: called when an error occurs
   * This is required for Cloudflare's hibernatable WebSocket API
   */
  async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    // Find and remove client
    const entry = Array.from(this.clients.entries()).find(([_, c]) => c.webSocket === ws);
    if (entry) {
      this.clients.delete(entry[0]);
      console.error(`Client ${entry[0]} error:`, error);
    }
  }
}
