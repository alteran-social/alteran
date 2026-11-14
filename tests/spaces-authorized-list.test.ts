import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { authorizedReadFixture, interceptRead, COLLECTION, DID, SPACE } from './helpers/spaces-authorized-read';
import { signResourceDpop } from './helpers/oauth';
import { verifyResourceRequest } from '../src/lib/oauth/resource';
import type { VerifiedSpacePrincipal } from '../src/lib/oauth/space-principal';
import { loadActiveSpaceOwner } from '../src/db/space-owner';
import { applySpaceWrites } from '../src/db/space-store';
import { listAuthorizedSpaceRecords } from '../src/db/space-authorized-list';
import { authorizeSpaceRead, completion, consumeSpaceRead, type SpaceReadHandle } from '../src/db/space-read-auth';

const endpoint = 'https://pds.example/xrpc/com.atproto.space.listRecords';
type Fixture = Awaited<ReturnType<typeof authorizedReadFixture>>;
type TestEnv = Fixture['env'];

async function principal(f: Fixture, params: Record<string, string> = {}, env: TestEnv = f.env, signal?: AbortSignal) {
  const query = new URLSearchParams({ space: SPACE, repo: DID, excludeValues: 'true', ...params });
  const request = new Request(`${endpoint}?${query}`, { headers: { authorization: `DPoP ${f.tokens.accessJwt}`,
    dpop: await signResourceDpop(env, f.key, 'GET', endpoint, f.tokens.accessJwt) }, signal });
  const verified = await verifyResourceRequest(env, request);
  if (!verified?.spacePrincipal) throw new Error('Missing list principal');
  return { request, principal: verified.spacePrincipal };
}

describe('authorized Space metadata listing', () => {
  it('pages in reference URI order, including sibling collection prefixes', async () => {
    const f = await authorizedReadFixture();
    const owner = await loadActiveSpaceOwner(f.env, DID);
    if (!owner) throw new Error('Missing owner');
    await applySpaceWrites(f.env, SPACE, DID, [
      { action: 'create', collection: COLLECTION, rkey: 'z', record: { $type: COLLECTION, text: 'z' } },
      { action: 'create', collection: 'com.example.note.sub', rkey: 'a', record: { $type: 'com.example.note.sub', text: 'a' } },
    ], owner.incarnation);
    const first = await principal(f, { limit: '2' });
    const page1 = await listAuthorizedSpaceRecords(f.env, first.principal, first.request);
    expect(page1.tag).toBe('found');
    if (page1.tag !== 'found' || !page1.cursor) throw new Error('Missing first page');
    expect(page1.records.map(({ collection, rkey }) => `${collection}/${rkey}`))
      .toEqual(['com.example.other/two', 'com.example.note/z']);
    expect(await page1.complete(first.request, f.env.ALTERAN_DB)).toBe(true);
    const second = await principal(f, { limit: '2', cursor: page1.cursor });
    const page2 = await listAuthorizedSpaceRecords(f.env, second.principal, second.request);
    expect(page2.tag).toBe('found');
    if (page2.tag !== 'found') throw new Error('Missing second page');
    expect(page2.records.map(({ collection, rkey }) => `${collection}/${rkey}`))
      .toEqual(['com.example.note/one', 'com.example.note.sub/a']);
    expect(page2.cursor).toBeTruthy();
    expect(await page2.complete(second.request, f.env.ALTERAN_DB)).toBe(true);
    const filtered = await principal(f, { collection: COLLECTION });
    const page = await listAuthorizedSpaceRecords(f.env, filtered.principal, filtered.request);
    expect(page.tag).toBe('found');
    if (page.tag !== 'found') throw new Error('Missing filtered page');
    expect(page.records.map(({ rkey }) => rkey)).toEqual(['z', 'one']);
    expect(page.records.every((row) => Object.keys(row).sort().join(',') === 'cid,collection,rkey')).toBe(true);
    expect(await page.complete(filtered.request, f.env.ALTERAN_DB)).toBe(true);
  });

  it('requires a consumed, operation-bound principal and a one-use completion', async () => {
    const f = await authorizedReadFixture();
    const current = await principal(f);
    expect((await listAuthorizedSpaceRecords(f.env, { ...current.principal } as VerifiedSpacePrincipal, current.request)).tag)
      .toBe('unauthorized');
    const result = await listAuthorizedSpaceRecords(f.env, current.principal, current.request);
    expect(result.tag).toBe('found');
    if (result.tag !== 'found') throw new Error('Missing page');
    expect(await result.complete(current.request, f.env.ALTERAN_DB)).toBe(true);
    expect(await result.complete(current.request, f.env.ALTERAN_DB)).toBe(false);
    expect((await listAuthorizedSpaceRecords(f.env, current.principal, current.request)).tag).toBe('unauthorized');
    const get = await f.principal();
    const handle = consumeSpaceRead(f.env, get.principal, get.request, f.env.ALTERAN_DB);
    if (!handle) throw new Error('Missing read handle');
    expect(await authorizeSpaceRead(handle, 'listRecords', SPACE, DID)).toBe(false);
    expect(await completion(handle, 'epoch')(get.request, f.env.ALTERAN_DB)).toBe(false);
    expect(await authorizeSpaceRead({} as SpaceReadHandle, 'listRecords', SPACE, DID)).toBe(false);
    expect(await completion({} as SpaceReadHandle, 'epoch')(get.request, f.env.ALTERAN_DB)).toBe(false);
  });

  it('projects no metadata if revocation wins before the D1 page query', async () => {
    const f = await authorizedReadFixture();
    const watched = interceptRead(f.env, { before: async () => {
      await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
    } });
    const current = await principal(f, {}, watched.env);
    watched.arm();
    expect((await listAuthorizedSpaceRecords(watched.env, current.principal, current.request)).tag).toBe('unauthorized');
    expect(watched.returned()).toEqual([]);
  });

  it('withholds a serialized page if its session is revoked or request cancelled', async () => {
    for (const mode of ['revoked', 'cancelled']) {
      const f = await authorizedReadFixture();
      const controller = new AbortController();
      const current = await principal(f, {}, f.env, controller.signal);
      const result = await listAuthorizedSpaceRecords(f.env, current.principal, current.request);
      if (result.tag !== 'found') throw new Error('Missing page');
      if (mode === 'cancelled') controller.abort();
      else await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?').bind(f.sessionId).run();
      expect(await result.complete(current.request, f.env.ALTERAN_DB)).toBe(false);
    }
  });
});
