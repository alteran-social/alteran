import type { ListedSpaceRecord } from '../../db/space-authorized-list';
import type { SpaceListRequest } from './list-records-request';
import { serializeSpaceRecordValue, SpaceRecordResponseError } from './record-response';

const MAX_PAGE_RESPONSE_BYTES = 16 * 1024 * 1024;

export class SpaceListResponseTooLarge extends Error {}

/** Serialize a complete authorized page before its final authorization check. */
export function createSpaceListResponse(
  target: SpaceListRequest, records: readonly ListedSpaceRecord[], cursor?: string,
): string {
  if (target.excludeValues) {
    return JSON.stringify({ records: records.map(({ collection, rkey, cid }) => ({ collection, rkey, cid })),
      ...(cursor ? { cursor } : {}) });
  }
  const chunks: string[] = [];
  const encoder = new TextEncoder();
  let bytes = 0;
  const append = (part: string) => {
    if (part.length > MAX_PAGE_RESPONSE_BYTES - bytes) throw new SpaceListResponseTooLarge();
    bytes += encoder.encode(part).byteLength;
    if (bytes > MAX_PAGE_RESPONSE_BYTES) throw new SpaceListResponseTooLarge();
    chunks.push(part);
  };
  append('{"records":[');
  for (let index = 0; index < records.length; index++) {
    const item = records[index];
    if (!item.record) throw new Error('Missing Space record value');
    let value;
    try {
      value = serializeSpaceRecordValue({
        space: target.space, repo: target.repo, collection: item.collection, rkey: item.rkey,
      }, item.record);
    } catch (cause) {
      if (cause instanceof SpaceRecordResponseError && cause.code === 'ResponseTooLarge') throw new SpaceListResponseTooLarge();
      throw cause;
    }
    if (value.cid !== item.cid) throw new Error('Invalid Space record value');
    if (index) append(',');
    append(`{"collection":${JSON.stringify(item.collection)},"rkey":${JSON.stringify(item.rkey)},"cid":${JSON.stringify(item.cid)},"value":`);
    append(value.valueJson);
    append('}');
  }
  append(']');
  if (cursor) append(`,"cursor":${JSON.stringify(cursor)}`);
  append('}');
  return chunks.join('');
}
