import { isValidNsid, isValidRecordKey } from '@atproto/syntax-spaces';
import { collectBlobRefs, validateRawRecord, type BlobReference } from '../lib/repo-write-data';
import { RepoWriteError } from '../lib/repo-write-error';
import { MAX_SPACE_WRITE_BYTES, MAX_SPACE_WRITES, SpaceStorageError, type SpaceWrite } from './space-types';

const MAX_INPUT_UNITS = MAX_SPACE_WRITE_BYTES * 4;
const MAX_INPUT_NODES = 200_000;
const MAX_DEPTH = 100;

type Budget = { units: number; nodes: number };

export function captureSpaceWrites(writes: readonly SpaceWrite[]): SpaceWrite[] {
  try {
    return copySpaceWrites(writes);
  } catch (error) {
    if (error instanceof SpaceStorageError || error instanceof RepoWriteError) throw error;
    throw invalid();
  }
}

function copySpaceWrites(writes: readonly SpaceWrite[]): SpaceWrite[] {
  const length = spaceWriteArrayLength(writes);
  const budget: Budget = { units: 0, nodes: 0 };
  const result: SpaceWrite[] = [];
  for (let index = 0; index < length; index++) {
    const write = ownSpaceWriteValue(writes, String(index));
    if (!isPlainObject(write)) throw invalid();
    const action = ownSpaceWriteValue(write, 'action');
    const collection = ownSpaceWriteValue(write, 'collection');
    const rkey = ownSpaceWriteValue(write, 'rkey');
    if (typeof collection !== 'string' || typeof rkey !== 'string' ||
      !isValidNsid(collection) || !isValidRecordKey(rkey)) throw invalid();
    if (action === 'delete') {
      result.push({ action, collection, rkey });
    } else if (action === 'create' || action === 'update') {
      const copied = copyValue(ownSpaceWriteValue(write, 'record'), budget, new Set(), 0);
      const record = validateRawRecord(collection, copied);
      const blobs: BlobReference[] = [];
      collectBlobRefs(record, blobs);
      if (blobs.length) throw new SpaceStorageError('BlobIntegrityUnavailable', 'Space blob storage is unavailable');
      result.push({ action, collection, rkey, record });
    } else {
      throw invalid();
    }
  }
  return result;
}

function copyValue(value: unknown, budget: Budget, ancestors: Set<object>, depth: number): unknown {
  if (++budget.nodes > MAX_INPUT_NODES || depth > MAX_DEPTH) throw invalid();
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  if (typeof value === 'string') {
    addUnits(budget, value.length);
    return value;
  }
  if (!value || typeof value !== 'object' || ancestors.has(value)) throw invalid();
  if (!Array.isArray(value) && !isPlainObject(value)) throw invalid();
  if (Array.isArray(value) && Object.getPrototypeOf(value) !== Array.prototype) throw invalid();
  ancestors.add(value);
  try {
    const keys = Reflect.ownKeys(value);
    if (keys.length > MAX_INPUT_NODES - budget.nodes || keys.some((key) => typeof key !== 'string')) throw invalid();
    if (Array.isArray(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, 'length');
      const length = descriptor && 'value' in descriptor ? descriptor.value : undefined;
      if (!Number.isSafeInteger(length) || length < 0 || length > MAX_INPUT_NODES - budget.nodes || keys.length !== length + 1) {
        throw invalid();
      }
      const copied: unknown[] = [];
      for (let index = 0; index < length; index++) {
        copied.push(copyValue(ownSpaceWriteValue(value, String(index)), budget, ancestors, depth + 1));
      }
      return copied;
    }
    const copied: Record<string, unknown> = Object.create(null);
    for (const key of keys) {
      if (typeof key !== 'string' || key === '__proto__') throw invalid();
      addUnits(budget, key.length);
      copied[key] = copyValue(ownSpaceWriteValue(value, key), budget, ancestors, depth + 1);
    }
    return copied;
  } finally {
    ancestors.delete(value);
  }
}

export function ownSpaceWriteValue(object: object, key: string): unknown {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) throw invalid();
    return descriptor.value;
  } catch {
    throw invalid();
  }
}

export function spaceWriteArrayLength(value: unknown): number {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) throw invalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, 'length');
    const length = descriptor && 'value' in descriptor ? descriptor.value : undefined;
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_SPACE_WRITES) throw invalid();
    return length;
  } catch {
    throw invalid();
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function addUnits(budget: Budget, amount: number): void {
  budget.units += amount;
  if (budget.units > MAX_INPUT_UNITS) throw invalid();
}

function invalid(): SpaceStorageError {
  return new SpaceStorageError('InvalidRequest', 'Invalid or oversized space write input');
}
