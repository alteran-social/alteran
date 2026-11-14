import { expect } from '@std/expect';
import { fixture, context, ref } from './helpers/spaces-owner-listing';
import { GET } from '../src/pages/xrpc/com.atproto.space.listSpaces';

type Page = { spaces: { space: string }[]; cursor?: string };

Deno.test('owner Space listings paginate exactly 100 and 101 entries without truncation', async () => {
  const f = await fixture();
  const names = Array.from({ length: 101 }, (_, index) => `page-${String(index).padStart(3, '0')}`);
  for (const name of names.slice(0, 100)) await f.create(name);
  const first = await GET(context(f.env, await f.request({ limit: '100' })));
  expect(first.status).toBe(200);
  const full = await first.json() as Page;
  expect(full.spaces.map((item) => item.space)).toEqual(names.slice(0, 100).map(ref));
  expect(full.cursor).toBe(ref(names[99]));
  if (!full.cursor) throw new Error('Missing full-page cursor');
  const cursor = full.cursor;
  const empty = await GET(context(f.env, await f.request({ limit: '100', cursor })));
  expect(empty.status).toBe(200);
  expect(await empty.json()).toEqual({ spaces: [] });
  await f.create(names[100]);
  const next = await GET(context(f.env, await f.request({ limit: '100', cursor })));
  expect(next.status).toBe(200);
  expect(await next.json()).toEqual({ spaces: [{ space: ref(names[100]) }] });
});
