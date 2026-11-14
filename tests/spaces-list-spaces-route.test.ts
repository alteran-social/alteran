import { expect } from '@std/expect';
import { base64 } from 'multiformats/bases/base64';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { DID, TYPE, ref, fixture, context } from './helpers/spaces-owner-listing';
import { applySpaceWrites } from '../src/db/space-store';
import { GET } from '../src/pages/xrpc/com.atproto.space.listSpaces';

describe('owner Space listing', () => {
  it('paginates personal policies and represents a current repo by revision and digest', async () => {
    const f = await fixture();
    await f.create('a'); await f.create('b'); await f.create('c');
    const commit = await applySpaceWrites(f.env, ref('b'), DID, [
      { action: 'create', collection: 'com.example.note', rkey: 'one', record: { $type: 'com.example.note', text: 'one' } },
    ], f.account.space_incarnation);
    if (!commit) throw new Error('Missing commit');
    const first = await GET(context(f.env, await f.request({ limit: '2' })));
    expect(first.status).toBe(200);
    expect(first.headers.get('cache-control')).toBe('private, no-store');
    const firstPage = await first.json() as { spaces: { space: string; repoRev?: string; data?: { $bytes: string } }[]; cursor: string };
    expect(firstPage.spaces.map((item) => item.space)).toEqual([ref('a'), ref('b')]);
    expect(firstPage.spaces[0]).toEqual({ space: ref('a') });
    expect(firstPage.spaces[1].repoRev).toBe(commit.rev);
    expect(firstPage.spaces[1].data?.$bytes).toBe(base64.encode(commit.data).slice(1));
    expect(firstPage.cursor).toBe(ref('b'));
    const second = await GET(context(f.env, await f.request({ limit: '2', cursor: firstPage.cursor })));
    expect(second.status).toBe(200);
    expect(await second.json()).toEqual({ spaces: [{ space: ref('c') }] });
  });

  it('denies a narrower key grant and rejects unsupported filters', async () => {
    const f = await fixture('a');
    await f.create('a');
    expect((await GET(context(f.env, await f.request()))).status).toBe(403);
    expect((await GET(context(f.env, await f.request({ spaceDid: 'did:example:other' })))).status).toBe(401);
    expect((await GET(context(f.env, await f.request({ spaceDid: 'did:example:other',
      cursor: 'at://did:zzz:other/space/com.example.other/z' })))).status).toBe(401);
    expect((await GET(context(f.env, await f.request({ limit: '101' })))).status).toBe(400);
    expect((await GET(context(f.env, await f.request({ cursor: ref('a') + '/extra' })))).status).toBe(400);
    expect((await GET(context(f.env, await f.request({ cursor: 'at://did:zzz:other/space/com.example.other/z' })))).status).toBe(403);
  });

  it('treats valid cursors as literal binary bounds independent of the filters', async () => {
    const f = await fixture();
    for (const key of ['a', 'b', 'c']) await f.create(key);
    for (const [cursor, expected] of [
      ['', ['a', 'b', 'c']],
      [ref('a') + '#/fragment%2Fpart', ['b', 'c']],
      [`at://${DID}/space/com.example.aaa/z`, ['a', 'b', 'c']],
      [`at://${DID}/space/com.example.zzz/a`, []],
      ['at://did:aaa:other/space/com.example.other/z', ['a', 'b', 'c']],
      ['at://did:zzz:other/space/com.example.other/a', []],
    ] as [string, string[]][]) {
      const response = await GET(context(f.env, await f.request({ cursor })));
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ spaces: expected.map((key) => ({ space: ref(key) })) });
    }
  });

  it('fails closed when the page changes after selection', async () => {
    const f = await fixture();
    await f.create('b');
    const database = f.env.ALTERAN_DB;
    let changed = false;
    const wrapped = new Proxy(database, { get(target, property) {
      if (property === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
        const result = await database.batch(statements);
        if (!changed && statements.length === 6) {
          changed = true;
          await f.create('a');
        }
        return result;
      };
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
    const response = await GET(context({ ...f.env, ALTERAN_DB: wrapped }, await f.request()));
    expect(changed).toBe(true);
    expect(response.status).toBe(401);
  });

  it('quarantines pre-existing foreign rows without blocking account creation', async () => {
    const env = await makeEnv();
    await env.ALTERAN_DB.prepare('INSERT INTO space (space_ref, authority_did, space_type, skey, created_at) VALUES (?, ?, ?, ?, 1)')
      .bind(ref('foreign-before-account'), DID, TYPE, 'foreign-before-account').run();
    const f = await fixture('*', env);
    expect((await GET(context(env, await f.request()))).status).toBe(401);
  });

  it('does not list an earlier account incarnation after replacement', async () => {
    const original = await fixture();
    await original.create('old');
    await original.env.ALTERAN_DB.prepare('DELETE FROM account WHERE did = ?').bind(DID).run();
    await original.env.ALTERAN_DB.prepare('DELETE FROM account_state WHERE did = ?').bind(DID).run();
    const replacement = await fixture('*', original.env);
    expect(replacement.account.space_incarnation).not.toBe(original.account.space_incarnation);
    await replacement.create('new');
    const response = await GET(context(replacement.env, await replacement.request()));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ spaces: [{ space: ref('new') }] });
  });

  it('denies listing while locally attributable or globally ambiguous rows are quarantined', async () => {
    const f = await fixture();
    await f.create('a');
    await f.env.ALTERAN_DB.prepare('INSERT INTO space (space_ref, authority_did, space_type, skey, created_at) VALUES (?, ?, ?, ?, 1)')
      .bind(ref('legacy'), DID, TYPE, 'legacy').run();
    expect((await GET(context(f.env, await f.request()))).status).toBe(401);
    expect((await GET(context(f.env, await f.request({ cursor: 'at://did:zzz:other/space/com.example.other/z' })))).status).toBe(401);
    const marker = await f.env.ALTERAN_DB.prepare('SELECT authority_did FROM space_owner_unclassified WHERE authority_did = ?')
      .bind(DID).first();
    expect(marker).not.toBeNull();
  });

  it('does not apply an unrelated valid type quarantine to this listing', async () => {
    const f = await fixture();
    await f.create('a');
    await f.env.ALTERAN_DB.prepare('INSERT INTO space (space_ref, authority_did, space_type, skey, created_at) VALUES (?, ?, ?, ?, 1)')
      .bind(`at://${DID}/space/com.example.other/legacy`, DID, 'com.example.other', 'legacy').run();
    const response = await GET(context(f.env, await f.request()));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ spaces: [{ space: ref('a') }] });
  });
});
