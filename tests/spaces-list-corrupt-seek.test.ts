import { expect } from '@std/expect';
import { authorizedReadFixture, COLLECTION, DID, SPACE } from './helpers/spaces-authorized-read';
import { signResourceDpop } from './helpers/oauth';
import { verifyResourceRequest } from '../src/lib/oauth/resource';
import { captureRecordIdentity } from '../src/lib/spaces/record-response-input';
import { listAuthorizedSpaceRecords } from '../src/db/space-authorized-list';

Deno.test('filtered Space listing bounds work when stored paths are corrupt', async () => {
  const f = await authorizedReadFixture();
  const db = f.env.ALTERAN_DB;
  let reads = 0;
  const wrapped = new Proxy(db, { get(target, key) {
    if (key === 'batch') return async (statements: Parameters<typeof db.batch>[0]) => {
      const result = await db.batch(statements);
      if (statements.length === 6) reads = Number(result[2]?.meta?.rows_read);
      return result;
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  const env = { ...f.env, ALTERAN_DB: wrapped };
  const endpoint = 'https://pds.example/xrpc/com.atproto.space.listRecords';
  const cursor = captureRecordIdentity({ space: SPACE, repo: DID, collection: COLLECTION, rkey: 'zzzzzz' }).uri;
  async function read(excludeValues: string, withCursor: boolean, expected: 'found' | 'invalid') {
    const query = new URLSearchParams({ space: SPACE, repo: DID, collection: COLLECTION, limit: '1', excludeValues,
      ...(withCursor ? { cursor } : {}) });
    const request = new Request(`${endpoint}?${query}`, { headers: {
      authorization: `DPoP ${f.tokens.accessJwt}`,
      dpop: await signResourceDpop(env, f.key, 'GET', endpoint, f.tokens.accessJwt),
    } });
    const auth = await verifyResourceRequest(env, request);
    if (!auth?.spacePrincipal) throw new Error('Missing principal');
    const result = await listAuthorizedSpaceRecords(env, auth.spacePrincipal, request);
    expect(result.tag).toBe(expected);
    if (result.tag !== 'found' && result.tag !== 'invalid') throw new Error('Unexpected result');
    expect(await result.complete(request, wrapped)).toBe(true);
    return reads;
  }
  const cases = [['true', false], ['true', true], ['false', false], ['false', true]] as const;
  const before = [];
  for (const [excludeValues, withCursor] of cases) before.push(await read(excludeValues, withCursor, 'found'));
  await db.prepare('DROP TRIGGER space_record_fence_insert').run();
  await db.prepare(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i < 3000)
    INSERT INTO space_record(space_ref, repo_did, collection, rkey, cid, value_cbor, repo_rev)
    SELECT r.space_ref, r.repo_did, 'com.example.note/zzzz', printf('r%08d',n.i), r.cid, r.value_cbor, r.repo_rev
    FROM space_record r CROSS JOIN n WHERE r.space_ref = ? AND r.repo_did = ? AND r.collection = ? AND r.rkey = 'one'`)
    .bind(SPACE, DID, COLLECTION).run();
  for (const [index, [excludeValues, withCursor]] of cases.entries()) {
    const after = await read(excludeValues, withCursor, 'invalid');
    expect(after).toBeLessThan(before[index] + 100);
  }
});
