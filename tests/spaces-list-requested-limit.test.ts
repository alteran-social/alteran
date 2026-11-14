import { expect } from '@std/expect';
import { authorizedReadFixture, COLLECTION, DID, interceptRead } from './helpers/spaces-authorized-read';
import { localPage, request, seed, traverse } from './helpers/spaces-request-limit';

Deno.test('signed Space lists honor large requested limits with bounded, complete pages', async () => {
  const f = await authorizedReadFixture();
  await seed(f);
  for (const excludeValues of ['true', 'false']) {
    for (const collection of [undefined, COLLECTION]) {
      const common = { excludeValues, ...(collection ? { collection } : {}) };
      const small = await traverse((params) => localPage(f, params), { ...common, limit: '25' });
      expect(small.records).toHaveLength(collection ? 100 : 101);
      expect(new Set(small.records.map((row) => `${row.collection}/${row.rkey}`)).size).toBe(small.records.length);
      for (const row of small.records) expect(Object.hasOwn(row, 'value')).toBe(excludeValues === 'false');
      for (const limit of ['51', '1000']) {
        const large = await traverse((params) => localPage(f, params), { ...common, limit });
        expect(large.records).toEqual(small.records);
        expect(large.lengths).toEqual(collection ? [50, 50, 0] : [50, 50, 1]);
      }
    }
  }

  const malformed = interceptRead(f.env, { after: (result) => {
    const rows = (result[2] as { results: { sentinel: number }[] }).results;
    const record = rows.find((row) => row.sentinel === 0);
    if (!record) throw new Error('Missing selected record');
    rows.push(record);
  } });
  malformed.arm();
  expect((await request(f, { limit: '1000', excludeValues: 'true' }, malformed.env)).status).toBe(401);

  const revoked = interceptRead(f.env, { after: async () => {
    await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
  } });
  revoked.arm();
  const denied = await request(f, { limit: '1000' }, revoked.env);
  expect(denied.status).toBe(401);
  expect(await denied.text()).not.toContain(DID);
});
