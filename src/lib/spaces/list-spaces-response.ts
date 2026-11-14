import { base64 } from 'multiformats/bases/base64';
import type { OwnerSpacePage } from '../../db/space-owner-page';
import { spaceSetHashDigest } from './lthash';

const MAX_RESPONSE_BYTES = 1024 * 1024;

/** Build a bounded Lex JSON response before checking final authorization. */
export function serializeOwnerSpacePage(page: OwnerSpacePage): string {
  const spaces = page.entries.map((entry) => ({
    space: entry.space,
    ...(entry.repo ? {
      repoRev: entry.repo.revision,
      data: { $bytes: base64.encode(spaceSetHashDigest(entry.repo.setHash)).slice(1) },
    } : {}),
  }));
  const body = JSON.stringify({ spaces, ...(page.cursor ? { cursor: page.cursor } : {}) });
  if (body.length > MAX_RESPONSE_BYTES || new TextEncoder().encode(body).byteLength > MAX_RESPONSE_BYTES) {
    throw new Error('Space listing response is too large');
  }
  return body;
}
