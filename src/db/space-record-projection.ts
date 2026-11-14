import { MAX_RECORD_SIZE } from '@atproto/space';
import { isValidTid } from '@atproto/syntax-spaces';
import { parseCanonicalRepoCid } from '../lib/spaces/repo-cid';
import { addIntegerRecord, integerBudgetExceeded } from '../lib/spaces/record-integer-budget';
import { validSpaceRecordBlock } from './space-record-block';
import { SpaceStorageError } from './space-types';

// The aliases are shared by authorized and internal readers. Both size
// parameters must be bound before the row can cross the D1 boundary.
export const SPACE_RECORD_COLUMNS = `CASE WHEN typeof(record.cid) = 'text' AND length(CAST(record.cid AS BLOB)) <= 128
    THEN record.cid END AS cid,
  CASE WHEN typeof(record.value_cbor) = 'blob' AND length(record.value_cbor) BETWEEN 1 AND ?
    THEN record.value_cbor END AS value_cbor,
  CASE WHEN typeof(record.repo_rev) = 'text' AND length(CAST(record.repo_rev AS BLOB)) = 13
    THEN record.repo_rev END AS repo_rev,
  CASE WHEN typeof(h.rev) = 'text' AND length(CAST(h.rev AS BLOB)) = 13 THEN h.rev END AS head_rev,
  CASE WHEN typeof(record.value_cbor) <> 'blob' THEN 0
    WHEN length(record.value_cbor) NOT BETWEEN 1 AND ? THEN 0
    WHEN v.epoch_id IS NOT NULL AND v.cid IS record.cid AND v.value_cbor IS record.value_cbor
      AND v.repo_rev IS record.repo_rev AND typeof(v.value_size) = 'integer'
      AND v.value_size = length(record.value_cbor) AND typeof(h.generation) = 'integer'
      AND h.generation BETWEEN 1 AND 9007199254740991
      AND typeof(v.from_generation) = 'integer' AND v.from_generation BETWEEN 1 AND h.generation
      THEN 1 ELSE 0 END AS consistent`;

export const SPACE_RECORD_TABLES = `FROM space_record record
  JOIN space ON space.space_ref = record.space_ref AND space.deleted_at IS NULL
  JOIN space_repo h ON h.space_ref = record.space_ref AND h.repo_did = record.repo_did
  JOIN space_epoch e ON e.id = h.active_epoch_id AND e.space_ref = h.space_ref
    AND e.repo_did = h.repo_did AND e.state = 'active'
  LEFT JOIN space_record_version v ON v.epoch_id = e.id AND v.space_ref = record.space_ref
    AND v.repo_did = record.repo_did AND v.path = record.collection || '/' || record.rkey
    AND v.until_generation IS NULL`;

export type SpaceRecordRow = {
  readonly cid: string | null;
  readonly value_cbor: number[] | null;
  readonly repo_rev: string | null;
  readonly head_rev: string | null;
  readonly consistent: number;
};

export type StoredSpaceRecord = {
  readonly cid: string;
  readonly value: Uint8Array;
  readonly rev: string;
};

type RecordWithHeader = SpaceRecordRow & { readonly cid: string; readonly value_cbor: number[];
  readonly repo_rev: string; readonly head_rev: string };

function validRecordHeader(row: SpaceRecordRow): row is RecordWithHeader {
  return row.consistent === 1 && !!row.cid && parseCanonicalRepoCid(row.cid)?.toString() === row.cid &&
    !!row.repo_rev && isValidTid(row.repo_rev) && !!row.head_rev && isValidTid(row.head_rev) &&
    row.repo_rev <= row.head_rev && Array.isArray(row.value_cbor) &&
    row.value_cbor.length >= 1 && row.value_cbor.length <= MAX_RECORD_SIZE;
}

/** Inspect a D1 record before allocating a decoded value for its response. */
export function inspectRecordIntegerBudget(row: SpaceRecordRow): 'valid' | 'invalid' | 'tooLarge' {
  if (!validRecordHeader(row)) return 'invalid';
  const source = row.value_cbor;
  const bytes = new Uint8Array(source.length);
  for (let index = 0; index < source.length; index++) {
    const byte: unknown = source[index];
    if (!Object.hasOwn(source, index) || typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 255) {
      return 'invalid';
    }
    bytes[index] = byte;
  }
  const budget = { bytes: 0, items: 0, bigints: 0 };
  const status = addIntegerRecord(budget, bytes);
  if (status !== 'valid') return 'invalid';
  return integerBudgetExceeded(budget) ? 'tooLarge' : 'valid';
}

export function decodeSpaceRecord(row: SpaceRecordRow, collection: string): StoredSpaceRecord {
  if (!validRecordHeader(row) ||
    !row.value_cbor.every((byte: unknown) => typeof byte === 'number' && Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
    throw new SpaceStorageError('InvalidRepoState', 'Invalid Space record');
  }
  const value = Uint8Array.from(row.value_cbor);
  if (!validSpaceRecordBlock(collection, row.cid, value)) {
    throw new SpaceStorageError('InvalidRepoState', 'Invalid Space record');
  }
  return { cid: row.cid, value, rev: row.repo_rev };
}
