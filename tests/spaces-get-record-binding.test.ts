import { expect } from '@std/expect';
import { authorizedReadFixture, COLLECTION, DID, SPACE } from './helpers/spaces-authorized-read';
import { signResourceDpop } from './helpers/oauth';
import { GET } from '../src/pages/xrpc/com.atproto.space.getRecord';

Deno.test('database rebinding after final completion readback', async () => {
  const f = await authorizedReadFixture();
  const db = f.env.ALTERAN_DB;
  const env = { ...f.env };
  let changed = false;
  const wrapped = new Proxy(db, { get(target, key) {
    if (key === 'prepare') return (sql: string) => {
      const statement = db.prepare(sql);
      if (!sql.includes('SELECT clock.seconds, authorized.session_expires_at')) return statement;
      return new Proxy(statement, { get(prepared, property) {
        if (property === 'bind') return (...values: Parameters<typeof prepared.bind>) => {
          const bound = prepared.bind(...values);
          return new Proxy(bound, { get(boundTarget, boundKey) {
            if (boundKey === 'first') return async () => {
              const row = await bound.first();
              env.ALTERAN_DB = new Proxy(db, {});
              changed = true;
              return row;
            };
            const value = Reflect.get(boundTarget, boundKey, boundTarget);
            return typeof value === 'function' ? value.bind(boundTarget) : value;
          } });
        };
        const value = Reflect.get(prepared, property, prepared);
        return typeof value === 'function' ? value.bind(prepared) : value;
      } });
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  env.ALTERAN_DB = wrapped;
  const endpoint = 'https://pds.example/xrpc/com.atproto.space.getRecord';
  const query = new URLSearchParams({ space: SPACE, repo: DID, collection: COLLECTION, rkey: 'one' });
  const request = new Request(`${endpoint}?${query}`, { headers: {
    authorization: `DPoP ${f.tokens.accessJwt}`,
    dpop: await signResourceDpop(f.env, f.key, 'GET', endpoint, f.tokens.accessJwt),
  } });
  const response = await GET({ locals: { env }, request, url: new URL(request.url) } as never);
  expect(changed).toBe(true);
  expect(response.status).toBe(401);
  expect(await response.text()).not.toContain('private');
});
