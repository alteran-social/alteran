import { isAtUriString, isValidNsid } from '@atproto/syntax-spaces';
import { isSpaceDid } from './space-did';
import { parseSpaceRef } from '../../db/space-ref';

export const MAX_SPACE_LIST_LIMIT = 1000;
export const MAX_SPACE_LIST_PAGE_LIMIT = 50;
const PARAMETERS = ['space', 'repo', 'collection', 'limit', 'cursor', 'excludeValues'] as const;

export type SpaceListCursor =
  | { readonly tag: 'unbounded' }
  | { readonly tag: 'empty' }
  | { readonly tag: 'before'; readonly path: string };

export type SpaceListRequest = {
  readonly space: string;
  readonly repo: string;
  readonly collection: string | null;
  readonly cursor: SpaceListCursor;
  readonly limit: number;
  readonly excludeValues: boolean;
};
export type SpaceListParseResult =
  | { readonly tag: 'valid'; readonly target: SpaceListRequest }
  | { readonly tag: 'invalid'; readonly error: 'InvalidRequest' | 'InvalidCursor' };

/** Parse bounded owner-repository listRecords requests. */
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
  const excludeValues = url.searchParams.get('excludeValues');
  if (!space || !isSpaceDid(repo) || (collection !== null && !isValidNsid(collection)) ||
    (excludeValues !== null && excludeValues !== 'true' && excludeValues !== 'false') ||
    (limitText !== null && !/^[1-9][0-9]{0,3}$/.test(limitText))) return invalid();
  const limit = limitText === null ? 50 : Number(limitText);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_SPACE_LIST_LIMIT) return invalid();
  try { parseSpaceRef(space); } catch { return invalid(); }
  let range: SpaceListCursor = { tag: 'unbounded' };
  if (cursor) {
    if (!isAtUriString(cursor)) return { tag: 'invalid', error: 'InvalidCursor' };
    const prefix = `${space}/${repo}/`;
    range = cursor.startsWith(prefix) ? { tag: 'before', path: cursor.slice(prefix.length) }
      : cursor <= prefix ? { tag: 'empty' } : { tag: 'unbounded' };
  }
  return { tag: 'valid', target: { space, repo, collection, cursor: range, limit, excludeValues: excludeValues === 'true' } };
}

function invalid(): SpaceListParseResult {
  return { tag: 'invalid', error: 'InvalidRequest' };
}
