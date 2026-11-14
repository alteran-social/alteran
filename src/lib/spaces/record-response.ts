import { MAX_RECORD_SIZE } from '@atproto/space';
import { decode, encode, type LexValue } from '@atproto/lex-cbor';
import { lexParse, lexStringify } from '@atproto/lex-json';
import { isValidTid } from '@atproto/syntax-spaces';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { inspectRecordCborDetails } from './record-cbor-bounds';
import { integerBudgetExceeded, MAX_INTEGER_JSON_BYTES } from './record-integer-budget';
import { parseIntegerLex, stringifyIntegerLex } from './record-integer-json';
import { copyPlainRecord } from './plain-values';
import {
  captureRecordCid, captureRecordIdentity, copyResponseBytes, invalidRecord,
  SpaceRecordResponseError, type SpaceRecordResponseIdentity,
} from './record-response-input';
import { recordResponseMacHeaders, type SpaceRecordMacOptions } from './record-response-mac';

export { SpaceRecordResponseError, type SpaceRecordResponseIdentity } from './record-response-input';
export { verifySpaceRecordResponseMac, type SpaceRecordMacOptions } from './record-response-mac';

const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

export class SpaceIntegerResponseTooLarge extends SpaceRecordResponseError {
  constructor() { super('ResponseTooLarge', 'Space record response is too large'); }
}

type RecordToSerialize = { readonly cid: string; readonly value: Uint8Array; readonly rev?: string };
export type SerializedSpaceRecordValue = {
  readonly uri: ReturnType<typeof captureRecordIdentity>['uri']; readonly cid: string; readonly valueJson: string;
  readonly hasBigint?: true;
};

/**
 * Validate a record's identity and bytes and produce its Lex JSON value.
 * This does not establish access, key identity or storage-policy compliance.
 */
export function serializeSpaceRecordValue(
  identity: SpaceRecordResponseIdentity,
  record: RecordToSerialize,
): SerializedSpaceRecordValue {
  const captured = captureRecordIdentity(identity);
  const fields = copyPlainRecord(record, ['cid', 'value']) ?? copyPlainRecord(record, ['cid', 'value', 'rev']);
  if (!fields || (fields.rev !== undefined && !isValidTid(fields.rev))) throw invalidRecord();
  const cid = captureRecordCid(fields.cid);
  const bytes = copyResponseBytes(fields.value, MAX_RECORD_SIZE);
  const inspected = inspectRecordCborDetails(bytes);
  if (inspected.tag !== 'valid') throw invalidRecord();
  const hasBigint = inspected.bigints > 0;
  if (integerBudgetExceeded({ bytes: bytes.byteLength, items: inspected.items, bigints: inspected.bigints })) {
    throw new SpaceIntegerResponseTooLarge();
  }
  const expected = CID.createV1(0x71, createDigest(0x12, sha256(bytes))).toString();
  if (expected !== cid.toString()) throw invalidRecord();

  let json: string;
  try {
    const value = decode(bytes);
    if (!value || typeof value !== 'object' || Array.isArray(value) || value instanceof Uint8Array ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
      !Object.hasOwn(value, '$type') || (value as Record<string, unknown>).$type !== captured.collection ||
      !equalBytes(encode(value), bytes)) throw invalidRecord();
    // The preflight caps CBOR at 1 MiB and 131,072 items: JSON escaping expands
    // input by at most 6x, with at most 32 extra bytes per item and 16 KiB for
    // the response wrapper. This keeps allocation below the 16 MiB limit.
    json = hasBigint ? stringifyIntegerLex(value) : lexStringify(value as LexValue);
    if (hasBigint && (json.length > MAX_INTEGER_JSON_BYTES ||
      new TextEncoder().encode(json).byteLength > MAX_INTEGER_JSON_BYTES)) throw new SpaceIntegerResponseTooLarge();
    if (json.length > MAX_RESPONSE_BYTES) throw responseTooLarge();
    const restored = hasBigint ? parseIntegerLex(json) : lexParse(json, { strict: true });
    if (!equalBytes(encode(restored as LexValue), bytes)) throw invalidRecord();
  } catch (error) {
    if (error instanceof SpaceRecordResponseError) throw error;
    throw invalidRecord();
  }
  return { uri: captured.uri, cid: cid.toString(), valueJson: json, ...(hasBigint ? { hasBigint: true } : {}) };
}

/** Serialize a response from the verified, authorized record reader. */
export function createSpaceRecordResponse(
  identity: SpaceRecordResponseIdentity,
  record: RecordToSerialize,
  mac: SpaceRecordMacOptions,
): { readonly body: string; readonly headers: Readonly<Record<string, string>> } {
  const serialized = serializeSpaceRecordValue(identity, record);
  const body = `{"uri":${JSON.stringify(serialized.uri)},"cid":${JSON.stringify(serialized.cid)},"value":${serialized.valueJson}}`;
  if (serialized.hasBigint && (body.length > MAX_INTEGER_JSON_BYTES ||
    new TextEncoder().encode(body).byteLength > MAX_INTEGER_JSON_BYTES)) throw new SpaceIntegerResponseTooLarge();
  if (body.length > MAX_RESPONSE_BYTES || new TextEncoder().encode(body).byteLength > MAX_RESPONSE_BYTES) {
    throw responseTooLarge();
  }
  const headers = recordResponseMacHeaders(serialized.uri, captureRecordCid(serialized.cid), mac);
  return { body, headers: Object.freeze({ 'content-type': 'application/json', 'cache-control': 'private, no-store', ...headers }) };
}

function responseTooLarge(): SpaceRecordResponseError {
  return new SpaceRecordResponseError('ResponseTooLarge', 'Space record response is too large');
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}
