import type { DurableObjectState } from '@cloudflare/workers-types';
import { encodeInfoFrame } from '../../lib/firehose/frames';

export interface WebSocketAttachment {
  id: string;
  cursor: number;
}

export type HibernatableSocket = WebSocket & {
  serializeAttachment?: (value: WebSocketAttachment) => void;
  deserializeAttachment?: () => WebSocketAttachment | undefined;
  accept?: () => void;
  addEventListener?: (
    type: 'message' | 'close',
    handler: (event: MessageEvent | { code: number; reason: string }) => void,
  ) => void;
  send?: (data: string | ArrayBuffer | Uint8Array) => void;
};

export type HibernatableState = DurableObjectState & {
  acceptWebSocket?: (ws: WebSocket) => void;
  getWebSockets?: () => WebSocket[];
};

export interface UpgradeContext {
  readonly state: HibernatableState;
  readonly nextSeq: number;
  readonly hibernate: boolean;
  readonly onClient: (id: string, cursor: number, server: HibernatableSocket) => void;
}

export function handleUpgrade(
  request: Request,
  url: URL,
  context: UpgradeContext,
): Response {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair) as [WebSocket, HibernatableSocket];
  const id = crypto.randomUUID();

  const cursorParam = url.searchParams.get('cursor');
  const cursor = cursorParam ? parseInt(cursorParam, 10) : 0;

  const requestedProtoHeader =
    request.headers.get('Sec-WebSocket-Protocol') ||
    request.headers.get('sec-websocket-protocol');
  const requestedProtocol = requestedProtoHeader
    ? requestedProtoHeader.split(',').map((s) => s.trim()).filter(Boolean)[0] || undefined
    : undefined;

  if (cursor > context.nextSeq - 1) {
    // Future cursor: send an info frame then 1008-close. Use the standard
    // WebSocket accept path rather than hibernation for this short-lived case.
    try {
      server.accept?.();
    } catch (acceptError) {
      console.warn('Sequencer: server.accept failed for OutdatedCursor:', acceptError);
    }
    try {
      server.send?.(encodeInfoFrame('OutdatedCursor', 'Cursor is ahead of current sequence'));
    } catch (sendError) {
      console.warn('Sequencer: send(info) failed for OutdatedCursor:', sendError);
    }
    try {
      server.close(1008, 'OutdatedCursor');
    } catch (closeError) {
      console.warn('Sequencer: close failed for OutdatedCursor:', closeError);
    }
    return buildUpgradeResponse(client, requestedProtocol);
  }

  if (context.hibernate) {
    context.state.acceptWebSocket?.(server);
    try {
      server.serializeAttachment?.({ id, cursor });
    } catch (attachError) {
      console.warn('Sequencer: serializeAttachment failed:', attachError);
    }
  } else {
    server.accept?.();
    server.addEventListener?.('message', (event) => {
      const evt = event as MessageEvent;
      try {
        const data =
          typeof evt.data === 'string' ? evt.data : new TextDecoder().decode(evt.data);
        if (data === 'ping') server.send?.('pong');
      } catch (messageError) {
        console.warn('Sequencer: ping handler failed:', messageError);
      }
    });
    server.addEventListener?.('close', (event) => {
      const cls = event as { code: number; reason: string };
      console.log(`Client ${id} disconnected (std): code=${cls.code} reason=${cls.reason}`);
    });
  }

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

  context.onClient(id, cursor, server);

  return buildUpgradeResponse(client, requestedProtocol);
}

function buildUpgradeResponse(client: WebSocket, requestedProtocol: string | undefined): Response {
  const headers = new Headers();
  if (requestedProtocol) headers.set('Sec-WebSocket-Protocol', requestedProtocol);
  return new Response(null, { status: 101, webSocket: client, headers });
}
