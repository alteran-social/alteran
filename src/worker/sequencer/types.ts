import type { RepoOp } from '../../lib/firehose/frames';
import type { AccountState } from '../../lib/account-state';

export interface Client {
  webSocket: WebSocket;
  id: string;
  cursor: number;
  replay: boolean;
}

export interface CommitEvent {
  seq: number;
  did: string;
  commitCid: string;
  rev: string;
  data: string;
  sig: string;
  ts: number;
  ops?: RepoOp[];
  blocks?: Uint8Array;
}

export interface IdentityEvent {
  seq: number;
  did: string;
  handle?: string;
  ts: number;
}

export interface AccountEvent {
  seq: number;
  did: string;
  state: AccountState;
  ts: number;
}

export type SequencerEvent = CommitEvent | IdentityEvent | AccountEvent;
