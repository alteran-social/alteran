import { expect } from '@std/expect';
import { EMPTY, policyFixture, policyPrincipal } from './helpers/spaces-policy-read';
import { readAuthorizedSpacePolicy } from '../src/db/space-authorized-policy';

Deno.test('policy lookup is driven by the authorized sentinel and bounded primary-key seeks', async () => {
  const f = await policyFixture();
  const db = f.env.ALTERAN_DB;
  let sql = '';
  let values: unknown[] = [];
  const wrapped = new Proxy(db, { get(target, key) {
    if (key === 'prepare') return (query: string) => {
      const statement = target.prepare(query);
      if (!query.includes('SELECT 0 AS sentinel')) return statement;
      return new Proxy(statement, { get(inner, property) {
        if (property === 'bind') return (...args: unknown[]) => {
          sql = query;
          values = args;
          return inner.bind(...args);
        };
        const value = Reflect.get(inner, property, inner);
        return typeof value === 'function' ? value.bind(inner) : value;
      } });
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  const env = { ...f.env, ALTERAN_DB: wrapped };
  const current = await policyPrincipal(f, EMPTY, env);
  expect((await readAuthorizedSpacePolicy(env, current.principal, current.request)).tag).toBe('found');
  if (!sql) throw new Error('Policy selection was not captured');
  const plan = await db.prepare(`EXPLAIN QUERY PLAN ${sql}`).bind(...values).all<{ detail: string }>();
  const details = plan.results.map((row) => row.detail);
  const authorized = details.findIndex((line) => line.includes('SCAN authorized'));
  const space = details.findIndex((line) => line.includes('SEARCH s USING INDEX') && line.includes('space_ref=?'));
  const policy = details.findIndex((line) => line.includes('SEARCH p USING INDEX') && line.includes('space_ref=?'));
  expect(authorized).toBeGreaterThanOrEqual(0);
  expect(space).toBeGreaterThan(authorized);
  expect(policy).toBeGreaterThan(space);
  const live = await db.prepare(sql).bind(...values).all();
  expect(live.results).toHaveLength(2);
  await db.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
  const revoked = await db.prepare(sql).bind(...values).all();
  expect(revoked.results).toEqual([]);
  expect(Number(revoked.meta.rows_read)).toBeLessThan(Number(live.meta.rows_read));
});
