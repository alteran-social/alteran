import { expect } from '@std/expect';
import { authorizedReadFixture, COLLECTION, DID, SPACE } from './helpers/spaces-authorized-read';
import { signResourceDpop } from './helpers/oauth';
import { consumeVerifiedSpacePrincipal, verifyResourceRequest } from '../src/lib/oauth/resource';
import { readAuthorizedSpaceRecord } from '../src/db/space-authorized-record';
import { listAuthorizedSpaceRecords } from '../src/db/space-authorized-list';

Deno.test('Space readers burn principals when database bindings disagree', async () => {
  for (const [operation, principalMatches] of [
    ['getRecord', false], ['getRecord', true], ['listRecords', false], ['listRecords', true],
  ] as const) {
    const f = await authorizedReadFixture();
    let projected = 0;
    const wrap = (track: boolean) => new Proxy(f.env.ALTERAN_DB, { get(target, key) {
      if (track && key === 'batch') return (...args: Parameters<typeof target.batch>) => {
        if (args[0].length === 6) projected++;
        return target.batch(...args);
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
    const selectedDb = wrap(true), principalDb = wrap(false);
    const authorizedDb = principalMatches ? selectedDb : principalDb;
    const authorizedEnv = { ...f.env, ALTERAN_DB: authorizedDb };
    const endpoint = `https://pds.example/xrpc/com.atproto.space.${operation}`;
    const query = new URLSearchParams(operation === 'getRecord'
      ? { space: SPACE, repo: DID, collection: COLLECTION, rkey: 'one' }
      : { space: SPACE, repo: DID, excludeValues: 'true' });
    const request = new Request(`${endpoint}?${query}`, { headers: {
      authorization: `DPoP ${f.tokens.accessJwt}`,
      dpop: await signResourceDpop(authorizedEnv, f.key, 'GET', endpoint, f.tokens.accessJwt),
    } });
    const verified = await verifyResourceRequest(authorizedEnv, request);
    if (!verified?.spacePrincipal) throw new Error('Missing signed principal');
    projected = 0;
    const sequence = [selectedDb, principalDb, principalDb, principalDb, selectedDb,
      selectedDb, principalDb, principalDb, principalDb];
    let reads = 0;
    const env = Object.create(f.env) as typeof f.env;
    Object.defineProperty(env, 'ALTERAN_DB', { get: () => sequence[reads++] ?? principalDb });
    const result = operation === 'getRecord'
      ? await readAuthorizedSpaceRecord(env, verified.spacePrincipal, request, SPACE, DID, COLLECTION, 'one')
      : await listAuthorizedSpaceRecords(env, verified.spacePrincipal, request);
    expect(result.tag).toBe('unauthorized');
    expect(projected).toBe(0);
    expect(consumeVerifiedSpacePrincipal(verified.spacePrincipal, request, authorizedDb)).toBe(false);
  }
});
