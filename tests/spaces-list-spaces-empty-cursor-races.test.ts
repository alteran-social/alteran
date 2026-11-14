import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { DID, ref, fixture, context } from './helpers/spaces-owner-listing';
import { createAccount } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { listAuthorizedOwnerSpaces } from '../src/db/space-authorized-spaces';
import { verifyResourceRequest } from '../src/lib/oauth/resource';
import { GET } from '../src/pages/xrpc/com.atproto.space.listSpaces';

describe('empty cursor-range authorization', () => {
  it('rechecks revocation, database binding, account incarnation, and a newly matching Space after serialization', async () => {
    for (const change of ['revocation', 'binding', 'incarnation', 'insertion'] as const) {
      const f = await fixture(); await f.create('a');
      const database = f.env.ALTERAN_DB;
      const env = { ...f.env };
      const other = change === 'binding' ? await makeEnv() : null;
      let selections = 0;
      const wrapped = new Proxy(database, { get(target, property) {
        if (property === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
          if (statements.length === 6 && ++selections === 2) {
            if (change === 'revocation') {
              await database.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
            } else if (change === 'binding' && other) {
              env.ALTERAN_DB = other.ALTERAN_DB;
            } else if (change === 'incarnation') {
              await database.prepare('DELETE FROM account WHERE did = ?').bind(DID).run();
              await database.prepare('DELETE FROM account_state WHERE did = ?').bind(DID).run();
              await createAccount(f.env, { did: DID, handle: 'test.example', passwordScrypt: null });
              await setAccountState(f.env, DID, { tag: 'active' });
            } else if (change === 'insertion') {
              await f.create('zzz');
            }
          }
          return database.batch(statements);
        };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      } });
      env.ALTERAN_DB = wrapped;
      const response = await GET(context(env, await f.request({ cursor: ref('zz') })));
      expect(selections).toBe(2);
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: 'AuthRequired', message: 'Authentication required' });
    }
  });

  it('binds an empty response completion to its request and database and permits one completion only', async () => {
    for (const mismatch of ['none', 'request', 'database'] as const) {
      const f = await fixture();
      const request = await f.request({ cursor: ref('zz') });
      const auth = await verifyResourceRequest(f.env, request);
      if (!auth?.spacePrincipal) throw new Error('Missing signed principal');
      const result = await listAuthorizedOwnerSpaces(f.env, auth.spacePrincipal, request);
      if (result.tag !== 'found') throw new Error('Empty range was denied');
      expect(JSON.parse(result.body)).toEqual({ spaces: [] });
      const database = mismatch === 'database' ? (await makeEnv()).ALTERAN_DB : f.env.ALTERAN_DB;
      const completed = await result.complete(mismatch === 'request' ? new Request(request) : request, database);
      expect(completed).toBe(mismatch === 'none');
      expect(await result.complete(request, f.env.ALTERAN_DB)).toBe(false);
    }
  });
});
