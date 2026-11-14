import { expect } from '@std/expect';
import { DID, TYPE, ref, fixture, context } from './helpers/spaces-owner-listing';
import { ownerSpacePageSql } from '../src/db/space-owner-page-sql';
import { GET } from '../src/pages/xrpc/com.atproto.space.listSpaces';

Deno.test('Space listing seeks current-incarnation rows before projecting values', async () => {
  const f = await fixture(); await f.create('one');
  const database = f.env.ALTERAN_DB;
  const sql = ownerSpacePageSql(true);
  const parameters = Array.from({ length: (sql.match(/\?/g) ?? []).length }, () => null);
  const plan = await database.prepare(`EXPLAIN QUERY PLAN ${sql}`).bind(...parameters).all<{ detail: string }>();
  const details: string[] = plan.results.map((row: { detail: string }) => row.detail);
  expect(details.some((detail) => detail.includes('space_owner_listing_owner_type') && detail.includes('space_ref>?'))).toBe(true);
  expect(details.some((detail) => detail.includes('USE TEMP B-TREE FOR ORDER BY'))).toBe(false);
  expect(details.some((detail) => detail === 'SCAN space_owner_listing' || detail === 'SCAN space')).toBe(false);

  const trigger = await database.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'space_owner_listing_insert'")
    .first<{ sql: string }>();
  if (!trigger?.sql) throw new Error('Missing catalog trigger');
  await database.exec('DROP TRIGGER space_owner_listing_insert');
  try {
    const oldIncarnation = 'a'.repeat(32);
    expect(oldIncarnation).not.toBe(f.account.space_incarnation);
    for (let offset = 0; offset < 3000; offset += 100) {
      await database.batch(Array.from({ length: 100 }, (_, index) => database.prepare(`INSERT INTO space_owner_listing
        (space_ref, authority_did, authority_incarnation, space_type, creation_nonce) VALUES (?, ?, ?, ?, ?)`)
        .bind(ref(`old-${String(offset + index).padStart(4, '0')}`), DID, oldIncarnation, TYPE, crypto.randomUUID())));
    }
  } finally {
    await database.exec(trigger.sql.replace(/\n/g, ' '));
  }
  let reads = -1;
  const wrapped = new Proxy(database, { get(target, property) {
    if (property === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
      const result = await database.batch(statements);
      if (statements.length === 6 && reads < 0) reads = Number(result[2]?.meta?.rows_read);
      return result;
    };
    const value = Reflect.get(target, property, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  const response = await GET(context({ ...f.env, ALTERAN_DB: wrapped }, await f.request()));
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ spaces: [{ space: ref('one') }] });
  expect(reads).toBeGreaterThan(0);
  expect(reads).toBeLessThan(150);
});
