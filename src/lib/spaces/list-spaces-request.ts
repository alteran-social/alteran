import { isSpaceRefString, isValidNsid } from '@atproto/syntax-spaces';
import { isSpaceDid } from './space-did';

export type ListSpacesTarget = {
  readonly authorityDid: string;
  readonly spaceType: string;
  readonly limit: number;
  readonly cursor: string | null;
};
export type ListSpacesParseResult =
  | { readonly tag: 'valid'; readonly target: ListSpacesTarget }
  | { readonly tag: 'invalid'; readonly error: 'InvalidRequest' | 'InvalidCursor' };

const PARAMETERS = ['spaceDid', 'spaceType', 'limit', 'cursor'] as const;

/** Require filters that describe the complete restricted listing target. */
export function parseListSpacesRequest(request: Request): ListSpacesParseResult {
  if (request.method !== 'GET' || request.signal.aborted || request.url.length > 16_384) return invalid();
  const url = new URL(request.url);
  if (url.pathname !== '/xrpc/com.atproto.space.listSpaces' ||
    Array.from(url.searchParams.keys()).some((key) => !PARAMETERS.includes(key as typeof PARAMETERS[number])) ||
    PARAMETERS.some((key) => url.searchParams.getAll(key).length > 1)) return invalid();
  const authorityDid = url.searchParams.get('spaceDid');
  const spaceType = url.searchParams.get('spaceType');
  const limitText = url.searchParams.get('limit');
  const cursor = url.searchParams.get('cursor') || null;
  if (!isSpaceDid(authorityDid) || !isValidNsid(spaceType) ||
    (limitText !== null && !/^[1-9][0-9]{0,2}$/.test(limitText))) return invalid();
  const limit = limitText === null ? 50 : Number(limitText);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) return invalid();
  if (cursor !== null && !isSpaceRefString(cursor)) return invalidCursor();
  return { tag: 'valid', target: Object.freeze({ authorityDid, spaceType, limit, cursor }) };
}

function invalid(): ListSpacesParseResult { return { tag: 'invalid', error: 'InvalidRequest' }; }
function invalidCursor(): ListSpacesParseResult { return { tag: 'invalid', error: 'InvalidCursor' }; }
