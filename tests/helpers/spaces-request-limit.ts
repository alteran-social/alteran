import { expect } from '@std/expect';
import { authorizedReadFixture, COLLECTION, DID, SPACE } from './spaces-authorized-read';
import { signResourceDpop } from './oauth';
import { loadActiveSpaceOwner } from '../../src/db/space-owner';
import { applySpaceWrites } from '../../src/db/space-store';
import { GET } from '../../src/pages/xrpc/com.atproto.space.listRecords';

export const ENDPOINT = 'https://pds.example/xrpc/com.atproto.space.listRecords';
export type Fixture = Awaited<ReturnType<typeof authorizedReadFixture>>;
export type Entry = { collection: string; rkey: string; cid: string; value?: unknown };
export type Page = { records: Entry[]; cursor?: string };

export function additionalRecords() {
  return Array.from({ length: 99 }, (_, index) => ({ collection: COLLECTION, rkey: `page-${String(index).padStart(3, '0')}`,
    record: { $type: COLLECTION, text: `value-${index}` } }));
}

export async function seed(f: Fixture): Promise<void> {
  const owner = await loadActiveSpaceOwner(f.env, DID);
  if (!owner) throw new Error('Missing Space owner');
  await applySpaceWrites(f.env, SPACE, DID, additionalRecords().map((item) => ({ action: 'create' as const, ...item })),
    owner.incarnation);
}

export async function request(f: Fixture, params: Record<string, string>, env: Fixture['env'] = f.env): Promise<Response> {
  const query = new URLSearchParams({ space: SPACE, repo: DID, ...params });
  const input = new Request(`${ENDPOINT}?${query}`, { headers: {
    authorization: `DPoP ${f.tokens.accessJwt}`,
    dpop: await signResourceDpop(env, f.key, 'GET', ENDPOINT, f.tokens.accessJwt),
  } });
  return GET({ locals: { env }, request: input, url: new URL(input.url) } as never);
}

export async function traverse(fetchPage: (params: Record<string, string>) => Promise<Page>,
  params: Record<string, string>): Promise<{ records: Entry[]; lengths: number[] }> {
  const records: Entry[] = [], lengths: number[] = [];
  const seen = new Set<string>();
  let cursor: string | undefined;
  for (let index = 0; index < 10; index++) {
    const page = await fetchPage({ ...params, ...(cursor ? { cursor } : {}) });
    expect(Array.isArray(page.records)).toBe(true);
    records.push(...page.records);
    lengths.push(page.records.length);
    if (!page.cursor) return { records, lengths };
    if (seen.has(page.cursor)) throw new Error('Repeated page cursor');
    seen.add(page.cursor);
    cursor = page.cursor;
  }
  throw new Error('Page traversal did not terminate');
}

export async function localPage(f: Fixture, params: Record<string, string>): Promise<Page> {
  const response = await request(f, params);
  expect(response.status).toBe(200);
  return await response.json() as Page;
}
