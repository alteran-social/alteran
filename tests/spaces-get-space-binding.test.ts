import { expect } from '@std/expect';
import { authorizedReadFixture, COLLECTION, DID, SPACE } from './helpers/spaces-authorized-read';
import { EMPTY, policyFixture, policyPrincipal, signedPolicyRequest } from './helpers/spaces-policy-read';
import { consumeVerifiedSpacePrincipal, verifyResourceRequest } from '../src/lib/oauth/resource';
import { readAuthorizedSpacePolicy } from '../src/db/space-authorized-policy';
import { readAuthorizedSpaceRecord } from '../src/db/space-authorized-record';

Deno.test('policy and record operations cannot exchange verified request principals', async () => {
  const record = await authorizedReadFixture();
  const existing = await record.principal();
  expect((await readAuthorizedSpacePolicy(record.env, existing.principal, existing.request)).tag).toBe('unauthorized');
  expect(consumeVerifiedSpacePrincipal(existing.principal, existing.request, record.env.ALTERAN_DB)).toBe(false);
  const f = await policyFixture();
  const current = await policyPrincipal(f);
  expect((await readAuthorizedSpaceRecord(f.env, current.principal, current.request, SPACE, DID, COLLECTION, 'one')).tag)
    .toBe('unauthorized');
  expect((await readAuthorizedSpacePolicy(f.env, current.principal, current.request)).tag).toBe('unauthorized');
});

Deno.test('policy reads burn principals when captured and observed D1 bindings disagree', async () => {
  for (const principalMatches of [false, true]) {
    const f = await policyFixture();
    let projected = 0;
    const wrap = (track: boolean) => new Proxy(f.env.ALTERAN_DB, { get(target, key) {
      if (track && key === 'batch') return (...args: Parameters<typeof target.batch>) => {
        if (args[0].length === 6) projected++;
        return target.batch(...args);
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
    const selected = wrap(true), other = wrap(false);
    const verifiedDb = principalMatches ? selected : other;
    const verifiedEnv = { ...f.env, ALTERAN_DB: verifiedDb };
    const request = await signedPolicyRequest(f, EMPTY, { env: verifiedEnv });
    const auth = await verifyResourceRequest(verifiedEnv, request);
    if (!auth?.spacePrincipal) throw new Error('Missing verified principal');
    projected = 0;
    const sequence = [selected, other, other, other, selected, selected, other];
    let reads = 0;
    const env = Object.create(f.env) as typeof f.env;
    Object.defineProperty(env, 'ALTERAN_DB', { get: () => sequence[reads++] ?? other });
    expect((await readAuthorizedSpacePolicy(env, auth.spacePrincipal, request)).tag).toBe('unauthorized');
    expect(projected).toBe(0);
    expect(consumeVerifiedSpacePrincipal(auth.spacePrincipal, request, verifiedDb)).toBe(false);
  }
});
