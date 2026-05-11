import * as dagCbor from '@ipld/dag-cbor';
import * as uint8arrays from 'uint8arrays';
import { CID } from 'multiformats/cid';

/**
 * Frame types for AT Protocol firehose
 */
export const FrameType = {
  Message: 1,
  Error: -1,
} as const;
export type FrameType = (typeof FrameType)[keyof typeof FrameType];

/**
 * Frame header structure
 */
export interface FrameHeader {
  op: FrameType;
  t?: string; // Message type discriminator
}

/**
 * Error frame body
 */
export interface ErrorFrameBody {
  error: string;
  message?: string;
}

/**
 * Base frame class
 */
export abstract class Frame {
  abstract header: FrameHeader;
  abstract body: unknown;

  get op(): FrameType {
    return this.header.op;
  }

  /**
   * Encode frame to bytes (header + body as CBOR)
   * Deprecated for WS firehose: upstream expects a single CBOR object per message.
   */
  toBytes(): Uint8Array {
    const headerBytes = dagCbor.encode(this.header);
    const bodyBytes = dagCbor.encode(this.body);
    return uint8arrays.concat([headerBytes, bodyBytes]);
  }

  /**
   * Encode with 4-byte big-endian length prefix (payload = header||body encoded as dag-cbor)
   * Deprecated for WS firehose: kept for tests/back-compat only.
   */
  toFramedBytes(): Uint8Array {
    const payload = this.toBytes();
    const prefix = new Uint8Array(4);
    const len = payload.byteLength >>> 0;
    prefix[0] = (len >>> 24) & 0xff;
    prefix[1] = (len >>> 16) & 0xff;
    prefix[2] = (len >>> 8) & 0xff;
    prefix[3] = len & 0xff;
    return uint8arrays.concat([prefix, payload]);
  }

  isMessage(): this is MessageFrame {
    return this.op === FrameType.Message;
  }

  isError(): this is ErrorFrame {
    return this.op === FrameType.Error;
  }
}

/**
 * Message frame for firehose events
 */
export class MessageFrame<T = unknown> extends Frame {
  header: FrameHeader;
  body: T;

  constructor(body: T, type?: string) {
    super();
    this.header = type ? { op: FrameType.Message, t: type } : { op: FrameType.Message };
    this.body = body;
  }

  get type(): string | undefined {
    return this.header.t;
  }
}

/**
 * Error frame
 */
export class ErrorFrame extends Frame {
  header: FrameHeader;
  body: ErrorFrameBody;

  constructor(error: string, message?: string) {
    super();
    this.header = { op: FrameType.Error };
    this.body = { error, message };
  }

  get code(): string {
    return this.body.error;
  }

  get message(): string | undefined {
    return this.body.message;
  }
}

/**
 * Firehose message types
 */

export interface InfoMessage {
  name: string;
  message?: string;
}

export interface RepoOp {
  action: 'create' | 'update' | 'delete';
  path: string;
  cid: CID | null;
  prev?: CID;
}

export interface CommitMessage {
  seq: number;
  rebase: boolean;
  tooBig: boolean;
  repo: string; // DID
  commit: CID;
  prev: CID | null;
  rev: string; // TID
  since: string | null; // Previous TID
  blocks: Uint8Array; // CAR bytes
  ops: RepoOp[];
  blobs: CID[];
  time: string; // ISO 8601
  prevData?: CID; // Previous MST root
}

export interface IdentityMessage {
  seq: number;
  did: string;
  time: string;
  handle?: string;
}

export interface AccountMessage {
  seq: number;
  did: string;
  time: string;
  active: boolean;
  status?: string;
}

export interface SyncMessage {
  seq: number;
  did: string;
  time: string;
  active: boolean;
  status?: string;
}

/**
 * Legacy helpers (frames) — kept for tests/back-compat only.
 * Upstream subscribeRepos expects a single CBOR object with $type.
 */
export function createInfoFrame(name: string, message?: string): MessageFrame<InfoMessage> {
  return new MessageFrame({ name, message }, '#info');
}

/**
 * Create a #commit frame
 */
export function createCommitFrame(data: CommitMessage): MessageFrame<CommitMessage> {
  return new MessageFrame(data, '#commit');
}

/**
 * Create an #identity frame
 */
export function createIdentityFrame(data: IdentityMessage): MessageFrame<IdentityMessage> {
  return new MessageFrame(data, '#identity');
}

/**
 * Create an #account frame
 */
export function createAccountFrame(data: AccountMessage): MessageFrame<AccountMessage> {
  return new MessageFrame(data, '#account');
}

/**
 * Create a #sync frame (alias/compat for account-status changes)
 */
export function createSyncFrame(data: SyncMessage): MessageFrame<SyncMessage> {
  return new MessageFrame(data, '#sync');
}

/**
 * Create an error frame
 */
export function createErrorFrame(error: string, message?: string): ErrorFrame {
  return new ErrorFrame(error, message);
}

// Binary encoders (with 4-byte length prefix)
export function encodeInfoFrame(name: string, message?: string): Uint8Array {
  // Send as a single WebSocket message containing CBOR(header)||CBOR(body)
  return createInfoFrame(name, message).toBytes();
}

export function encodeCommitFrame(data: CommitMessage): Uint8Array {
  return createCommitFrame(data).toBytes();
}

export function encodeIdentityFrame(data: IdentityMessage): Uint8Array {
  return createIdentityFrame(data).toBytes();
}

export function encodeAccountFrame(data: AccountMessage): Uint8Array {
  return createAccountFrame(data).toBytes();
}

// Alias for TODO nomenclature (#sync)
export function encodeSyncFrame(data: SyncMessage): Uint8Array {
  return createSyncFrame(data).toBytes();
}

// ----------------------------------------------------------------------------
// Spec-compliant builders for subscribeRepos WS messages
// Each message is a single CBOR object with a $type field
// ----------------------------------------------------------------------------

export type CommitEventObj = CommitMessage & { $type: '#commit' };
export type InfoEventObj = InfoMessage & { $type: '#info' };
export type IdentityEventObj = IdentityMessage & { $type: '#identity' };
export type AccountEventObj = AccountMessage & { $type: '#account' };
export type SyncEventObj = SyncMessage & { $type: '#sync' };

export function createCommitEvent(data: CommitMessage): CommitEventObj {
  return { $type: '#commit', ...data };
}

export function createInfoEvent(name: string, message?: string): InfoEventObj {
  return { $type: '#info', name, ...(message ? { message } : {}) };
}

export function createIdentityEvent(data: IdentityMessage): IdentityEventObj {
  return { $type: '#identity', ...data };
}

export function createAccountEvent(data: AccountMessage): AccountEventObj {
  return { $type: '#account', ...data };
}

export function createSyncEvent(data: SyncMessage): SyncEventObj {
  return { $type: '#sync', ...data };
}

export function encodeEvent(obj: object): Uint8Array {
  return dagCbor.encode(obj);
}
