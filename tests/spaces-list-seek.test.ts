import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { authorizedReadFixture, COLLECTION, DID, SPACE } from './helpers/spaces-authorized-read';
import { signResourceDpop } from './helpers/oauth';
import { verifyResourceRequest } from '../src/lib/oauth/resource';
import { listAuthorizedSpaceRecords } from '../src/db/space-authorized-list';
import { captureRecordIdentity } from '../src/lib/spaces/record-response-input';

const ENDPOINT = 'https://pds.example/xrpc/com.atproto.space.listRecords';

describe('Space list seek bounds', () => {
  it('seeks bounded metadata and value pages with each filter and cursor combination', async () => {
    const f = await authorizedReadFixture();
    const db = f.env.ALTERAN_DB;
    let sql = '';
    let values: unknown[] = [];
    const wrapped = new Proxy(db, { get(target, property) {
      if (property === 'prepare') return (query: string) => {
        const statement = target.prepare(query);
        if (!query.includes('candidates AS MATERIALIZED')) return statement;
        return new Proxy(statement, { get(inner, key) {
          if (key === 'bind') return (...args: unknown[]) => {
            sql = query;
            values = args;
            return inner.bind(...args);
          };
          const value = Reflect.get(inner, key, inner);
          return typeof value === 'function' ? value.bind(inner) : value;
        } });
      };
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
    const env = { ...f.env, ALTERAN_DB: wrapped };
    const cursor = captureRecordIdentity({ space: SPACE, repo: DID, collection: COLLECTION, rkey: 'r00000010' }).uri;
    const queries: { sql: string; values: unknown[]; before: number }[] = [];
    for (const [excludeValues, extra] of [
      ['true', {}], ['true', { collection: COLLECTION }], ['true', { cursor }], ['true', { collection: COLLECTION, cursor }],
      ['false', {}], ['false', { collection: COLLECTION }], ['false', { cursor }], ['false', { collection: COLLECTION, cursor }],
    ] as const) {
      const params = new URLSearchParams({ space: SPACE, repo: DID, excludeValues, limit: '1', ...extra });
      const request = new Request(`${ENDPOINT}?${params}`, { headers: {
        authorization: `DPoP ${f.tokens.accessJwt}`,
        dpop: await signResourceDpop(env, f.key, 'GET', ENDPOINT, f.tokens.accessJwt),
      } });
      const auth = await verifyResourceRequest(env, request);
      if (!auth?.spacePrincipal) throw new Error('Missing principal');
      const result = await listAuthorizedSpaceRecords(env, auth.spacePrincipal, request);
      if (result.tag !== 'found' || !sql) throw new Error('Missing query');
      const measured = await db.prepare(sql).bind(...values).all();
      const plan = await db.prepare(`EXPLAIN QUERY PLAN ${sql}`).bind(...values).all();
      expect(plan.results.some((row) => String(row.detail).includes('SEARCH record USING INTEGER PRIMARY KEY'))).toBe(true);
      queries.push({ sql, values, before: Number(measured.meta.rows_read) });
    }
    await db.prepare('DROP TRIGGER space_record_fence_insert').run();
    await db.prepare(`WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM numbers WHERE n<3000)
      INSERT INTO space_record(space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
      SELECT r.space_ref, r.repo_did, r.collection, printf('r%08d',numbers.n), r.cid, r.value_cbor, r.repo_rev
      FROM space_record r CROSS JOIN numbers WHERE r.space_ref=? AND r.repo_did=? AND r.collection=? AND r.rkey='one'`)
      .bind(SPACE, DID, COLLECTION).run();
    for (const query of queries) {
      await db.prepare('UPDATE oauth_replay_clock SET seconds = MAX(seconds, unixepoch()), nonce = ? WHERE id = 1')
        .bind(query.values[0]).run();
      const measured = await db.prepare(query.sql).bind(...query.values).all();
      expect(measured.results).toHaveLength(2);
      expect(Number(measured.meta.rows_read)).toBeLessThan(query.before + 100);
    }
  });
});
