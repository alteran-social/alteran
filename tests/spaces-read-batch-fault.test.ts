import { expect } from '@std/expect';
import { authorizedReadFixture, interceptRead, COLLECTION, DID, SPACE } from './helpers/spaces-authorized-read';
import { signResourceDpop } from './helpers/oauth';
import { GET as getRecord } from '../src/pages/xrpc/com.atproto.space.getRecord';
import { GET as listRecords } from '../src/pages/xrpc/com.atproto.space.listRecords';

Deno.test('record selection faults do not disclose data after revocation', async () => {
  for (const operation of ['getRecord', 'listRecords'] as const) {
    for (const present of [false, true]) {
      const f = await authorizedReadFixture();
      let faulted = false;
      const watched = interceptRead(f.env, { after: async (results) => {
        await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
        const rows = (results[2] as { results?: { sentinel?: number }[] }).results;
        if (rows?.some((row) => row.sentinel === 0)) {
          faulted = true;
          throw new Error('private record-dependent D1 failure');
        }
      } });
      const endpoint = `https://pds.example/xrpc/com.atproto.space.${operation}`;
      const query = new URLSearchParams(operation === 'getRecord'
        ? { space: SPACE, repo: DID, collection: COLLECTION, rkey: present ? 'one' : 'missing' }
        : { space: SPACE, repo: DID, excludeValues: 'true', collection: present ? COLLECTION : 'com.example.empty' });
      const request = new Request(`${endpoint}?${query}`, { headers: {
        authorization: `DPoP ${f.tokens.accessJwt}`,
        dpop: await signResourceDpop(watched.env, f.key, 'GET', endpoint, f.tokens.accessJwt),
      } });
      watched.arm();
      const context = { locals: { env: watched.env }, request, url: new URL(request.url) } as never;
      const response = await (operation === 'getRecord' ? getRecord(context) : listRecords(context));
      expect(faulted).toBe(present);
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: 'AuthRequired', message: 'Authentication required' });
    }
  }
});

Deno.test('synchronous D1 selection faults deny access', async () => {
  for (const [operation, location] of [
    ['getRecord', 'prepare'], ['getRecord', 'bind'], ['getRecord', 'batch'],
    ['listRecords', 'prepare'], ['listRecords', 'bind'], ['listRecords', 'batch'],
  ] as const) {
    const f = await authorizedReadFixture();
    const db = f.env.ALTERAN_DB;
    let faulted = false;
    const wrapped = new Proxy(db, { get(target, key) {
      if (key === 'prepare') return (sql: string) => {
        if (location === 'prepare' && sql.includes('0 AS sentinel, NULL AS session_expires_at')) {
          faulted = true;
          throw new Error('private synchronous D1 failure');
        }
        const statement = db.prepare(sql);
        if (location !== 'bind' || !sql.includes('0 AS sentinel, NULL AS session_expires_at')) return statement;
        return new Proxy(statement, { get(prepared, member) {
          if (member === 'bind') return () => {
            faulted = true;
            throw new Error('private synchronous D1 failure');
          };
          const value = Reflect.get(prepared, member, prepared);
          return typeof value === 'function' ? value.bind(prepared) : value;
        } });
      };
      if (key === 'batch') return (statements: Parameters<typeof db.batch>[0]) => {
        if (location === 'batch' && statements.length === 6) {
          faulted = true;
          throw new Error('private synchronous D1 failure');
        }
        return db.batch(statements);
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
    const env = { ...f.env, ALTERAN_DB: wrapped };
    const endpoint = `https://pds.example/xrpc/com.atproto.space.${operation}`;
    const query = new URLSearchParams(operation === 'getRecord'
      ? { space: SPACE, repo: DID, collection: COLLECTION, rkey: 'one' }
      : { space: SPACE, repo: DID, excludeValues: 'true' });
    const request = new Request(`${endpoint}?${query}`, { headers: {
      authorization: `DPoP ${f.tokens.accessJwt}`,
      dpop: await signResourceDpop(env, f.key, 'GET', endpoint, f.tokens.accessJwt),
    } });
    const context = { locals: { env }, request, url: new URL(request.url) } as never;
    const response = await (operation === 'getRecord' ? getRecord(context) : listRecords(context));
    expect(faulted).toBe(true);
    expect(response.status).toBe(401);
    expect(await response.text()).not.toContain('private synchronous D1 failure');
  }
});
