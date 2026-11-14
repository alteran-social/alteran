import { inspectRecordCborDetails, type RecordCborDetails } from './record-cbor-bounds';

// These limits bound the additional lossless JSON conversion work. Concurrent
// responses still require an operational memory and request-concurrency limit.
export const MAX_INTEGER_PAGE_BYTES = 64 * 1024;
export const MAX_INTEGER_PAGE_ITEMS = 4_096;
export const MAX_INTEGER_PAGE_BIGINTS = 64;
export const MAX_INTEGER_JSON_BYTES = 1024 * 1024;

export type IntegerBudget = { bytes: number; items: number; bigints: number };

export function addIntegerRecord(budget: IntegerBudget, bytes: Uint8Array): RecordCborDetails['tag'] {
  const inspected = inspectRecordCborDetails(bytes);
  if (inspected.tag !== 'valid') return inspected.tag;
  budget.bytes += bytes.byteLength;
  budget.items += inspected.items;
  budget.bigints += inspected.bigints;
  return 'valid';
}

export function integerBudgetExceeded(budget: IntegerBudget): boolean {
  return budget.bigints > 0 && (budget.bytes > MAX_INTEGER_PAGE_BYTES || budget.items > MAX_INTEGER_PAGE_ITEMS ||
    budget.bigints > MAX_INTEGER_PAGE_BIGINTS);
}
