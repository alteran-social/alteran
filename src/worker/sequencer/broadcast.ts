import type { D1Database } from '@cloudflare/workers-types';
import {
  encodeAccountFrame,
  encodeCommitFrame,
  encodeIdentityFrame,
  encodeSyncFrame,
} from '../../lib/firehose/frames';
import type { Env } from '../../env';
import { toWireStatus } from '../../lib/account-state';
import type { AccountEvent, CommitEvent, IdentityEvent } from './types';
import { createCommitPayload } from './payload';

export async function broadcastCommit(
  env: Env,
  db: D1Database,
  targets: WebSocket[],
  event: CommitEvent,
): Promise<void> {
  const message = await createCommitPayload(env, db, event);
  const bytes = encodeCommitFrame(message);

  console.log(
    JSON.stringify({
      level: 'info',
      type: 'firehose_broadcast_start',
      seq: event.seq,
      clients: targets.length,
      ops: (event.ops || []).length,
      ts: new Date().toISOString(),
    }),
  );

  let dropped = 0;
  for (const ws of targets) {
    try {
      ws.send(bytes);
    } catch {
      dropped++;
    }
  }

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
}

export function broadcastIdentity(targets: WebSocket[], event: IdentityEvent): void {
  const bytes = encodeIdentityFrame({
    seq: event.seq,
    did: event.did,
    time: new Date(event.ts).toISOString(),
    handle: event.handle,
  });
  for (const ws of targets) {
    try {
      ws.send(bytes);
    } catch (sendError) {
      console.warn('Sequencer: identity send failed:', sendError);
    }
  }
}

export function broadcastAccount(targets: WebSocket[], event: AccountEvent): void {
  const time = new Date(event.ts).toISOString();
  const wire = toWireStatus(event.state);
  const accountBytes = encodeAccountFrame({
    seq: event.seq,
    did: event.did,
    time,
    active: wire.active,
    status: wire.status,
  });
  // Compatibility #sync emission for clients on the legacy topic.
  const syncBytes = encodeSyncFrame({
    seq: event.seq,
    did: event.did,
    time,
    active: wire.active,
    status: wire.status,
  });
  for (const ws of targets) {
    try {
      ws.send(accountBytes);
      ws.send(syncBytes);
    } catch (sendError) {
      console.warn('Sequencer: account/sync send failed:', sendError);
    }
  }
}
