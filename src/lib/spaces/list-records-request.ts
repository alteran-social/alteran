import { isValidNsid, isValidRecordKey } from '@atproto/syntax-spaces';
import { isSpaceDid } from './space-did';
import { captureRecordIdentity } from './record-response-input';
import { parseSpaceRef } from '../../db/space-ref';

export const MAX_SPACE_LIST_LIMIT = 50;
const PARAMETERS = ['space', 'repo', 'collection', 'limit', 'cursor', 'excludeValues'] as const;

export type SpaceListRequest = {
  readonly space: string;
  readonly repo: string;
  readonly collection: string | null;
  readonly cursorPath: string | null;
  readonly limit: number;
};
export type SpaceListParseResult =
  | { readonly tag: 'valid'; readonly target: SpaceListRequest }
  | { readonly tag: 'invalid'; readonly error: 'InvalidRequest' | 'InvalidCursor' };

/** Parse the bounded metadata-only subset of listRecords. */
export function parseSpaceListRequest(request: Request): SpaceListParseResult {
  if (request.method !== 'GET' || request.signal.aborted || request.url.length > 16_384) return invalid();
  const url = new URL(request.url);
  if (url.pathname !== '/xrpc/com.atproto.space.listRecords' ||
    Array.from(url.searchParams.keys()).some((key) => !PARAMETERS.includes(key as typeof PARAMETERS[number])) ||
    PARAMETERS.some((key) => url.searchParams.getAll(key).length > 1)) return invalid();
  const space = url.searchParams.get('space');
  const repo = url.searchParams.get('repo');
  const collection = url.searchParams.get('collection');
  const limitText = url.searchParams.get('limit');
  const cursor = url.searchParams.get('cursor');
  if (!space || !isSpaceDid(repo) || (collection !== null && !isValidNsid(collection)) ||
    url.searchParams.get('excludeValues') !== 'true' ||
    (limitText !== null && !/^[1-9][0-9]{0,2}$/.test(limitText))) return invalid();
  const limit = limitText === null ? 50 : Number(limitText);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_SPACE_LIST_LIMIT) return invalid();
  try { parseSpaceRef(space); } catch { return invalid(); }
  let cursorPath: string | null = null;
  if (cursor !== null) {
    const prefix = `${space}/${repo}/`;
    if (!cursor.startsWith(prefix)) return { tag: 'invalid', error: 'InvalidCursor' };
    const path = cursor.slice(prefix.length);
    const slash = path.indexOf('/');
    const cursorCollection = path.slice(0, slash);
    const rkey = path.slice(slash + 1);
    if (slash < 0 || path.indexOf('/', slash + 1) !== -1 || !isValidNsid(cursorCollection) || !isValidRecordKey(rkey)) {
      return { tag: 'invalid', error: 'InvalidCursor' };
    }
    try {
      if (captureRecordIdentity({ space, repo, collection: cursorCollection, rkey }).uri !== cursor) {
        return { tag: 'invalid', error: 'InvalidCursor' };
      }
    } catch { return { tag: 'invalid', error: 'InvalidCursor' }; }
    cursorPath = path;
  }
  return { tag: 'valid', target: { space, repo, collection, cursorPath, limit } };
}

function invalid(): SpaceListParseResult {
  return { tag: 'invalid', error: 'InvalidRequest' };
}
