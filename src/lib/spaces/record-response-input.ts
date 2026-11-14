import { SpaceRef, isValidNsid, isValidRecordKey } from '@atproto/syntax-spaces';
import { copyPlainRecord } from './plain-values';
import { isSpaceDid } from './space-did';
import { parseCanonicalRepoCid } from './repo-cid';

export type SpaceRecordResponseIdentity = {
  readonly space: string;
  readonly repo: string;
  readonly collection: string;
  readonly rkey: string;
};

export class SpaceRecordResponseError extends Error {
  constructor(readonly code: 'InvalidRecord' | 'InvalidSpaceMac' | 'ResponseTooLarge', message: string) {
    super(message);
    this.name = 'SpaceRecordResponseError';
  }
}

export function captureRecordIdentity(value: SpaceRecordResponseIdentity) {
  const fields = copyPlainRecord(value, ['space', 'repo', 'collection', 'rkey']);
  if (!fields || typeof fields.space !== 'string' || fields.space.length > 8192 ||
    !isSpaceDid(fields.repo) || !isValidNsid(fields.collection) || !isValidRecordKey(fields.rkey)) {
    throw invalidRecord();
  }
  try {
    const ref = SpaceRef.parse(fields.space);
    if (!isSpaceDid(ref.spaceDid) || ref.toString() !== fields.space) throw invalidRecord();
    return {
      collection: fields.collection,
      uri: ref.recordUri(fields.repo, fields.collection, fields.rkey).toString(),
    };
  } catch {
    throw invalidRecord();
  }
}

export function captureRecordCid(value: unknown) {
  const cid = parseCanonicalRepoCid(value);
  if (typeof value !== 'string' || !cid || cid.toString() !== value) throw invalidRecord();
  return cid;
}

/** Capture only an ordinary, attached ArrayBuffer-backed byte view. */
export function copyResponseBytes(value: unknown, maximum: number, exact?: number): Uint8Array {
  if (!ArrayBuffer.isView(value) || !(value instanceof Uint8Array)) throw invalidRecord();
  try {
    const prototype = Object.getPrototypeOf(Uint8Array.prototype);
    const getLength = Object.getOwnPropertyDescriptor(prototype, 'byteLength')?.get;
    const getOffset = Object.getOwnPropertyDescriptor(prototype, 'byteOffset')?.get;
    const getBuffer = Object.getOwnPropertyDescriptor(prototype, 'buffer')?.get;
    if (!getLength || !getOffset || !getBuffer) throw invalidRecord();
    const length = getLength.call(value) as number;
    const offset = getOffset.call(value) as number;
    const buffer = getBuffer.call(value) as ArrayBuffer;
    if (!Number.isSafeInteger(length) || length < 1 || length > maximum ||
      (exact !== undefined && length !== exact) || !(buffer instanceof ArrayBuffer)) throw invalidRecord();
    return new Uint8Array(buffer, offset, length).slice();
  } catch {
    throw invalidRecord();
  }
}

export function invalidRecord(): SpaceRecordResponseError {
  return new SpaceRecordResponseError('InvalidRecord', 'Invalid Space record response');
}

export function invalidMac(): SpaceRecordResponseError {
  return new SpaceRecordResponseError('InvalidSpaceMac', 'Invalid Space record MAC request');
}
