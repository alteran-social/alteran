import { isValidDid, isValidTid } from '@atproto/syntax-spaces';
import { expect } from '@std/expect';
import { DID, refForType, fixture, context } from './helpers/spaces-owner-listing';
import { applySpaceWrites } from '../src/db/space-store';
import { GET } from '../src/pages/xrpc/com.atproto.space.listSpaces';

const configPath = Deno.env.get('ALTERAN_REFERENCE_OWNER_LIST_CONFIG');
type View = { space: string; repoRev?: string; data?: { $bytes: string } };
type Page = { spaces: View[]; cursor?: string };

Deno.test({
  name: 'owner Space listing agrees with the disposable reference PDS',
  ignore: !configPath, sanitizeOps: false, sanitizeResources: false,
  async fn() {
    let cleanupFailed = false;
    const created: string[] = [];
    let origin = '', authorization = '';
    try {
      if (!configPath) throw new Error();
      const fields: unknown = JSON.parse(await Deno.readTextFile(configPath));
      if (!fields || typeof fields !== 'object' || Array.isArray(fields)) throw new Error();
      const config = fields as Record<string, unknown>;
      const address = new URL(String(config.pds));
      if (address.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(address.hostname) ||
        address.username || address.password || address.pathname !== '/' || address.search || address.hash ||
        !isValidDid(config.did) || typeof config.accessJwt !== 'string' || !config.accessJwt) throw new Error();
      origin = address.origin;
      authorization = `Bearer ${config.accessJwt}`;
      const referenceDid = config.did;
      const spaceType = `com.example.notes${crypto.randomUUID().replaceAll('-', '')}`;
      const keys = ['a', 'b', 'c'].map((suffix) => `owner-${crypto.randomUUID()}-${suffix}`);
      const f = await fixture('*', undefined, spaceType);
      const rpc = async (name: string, init: RequestInit = {}) => {
        const headers = new Headers(init.headers);
        headers.set('authorization', authorization);
        const response = await fetch(`${origin}/xrpc/${name}`, { ...init, headers, redirect: 'manual',
          signal: AbortSignal.timeout(10_000) });
        if (!response.ok) { await response.body?.cancel(); throw new Error(); }
        return response;
      };
      const post = (name: string, body: unknown) => rpc(name, { method: 'POST',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
      for (const key of keys) {
        await f.create(key);
        const space = `at://${referenceDid}/space/${spaceType}/${key}`;
        created.push(space);
        await (await post('com.atproto.space.createSpace', { spaceType, skey: key,
          policy: { $type: 'com.atproto.personalspace.policy' } })).body?.cancel();
      }
      const value = { $type: 'com.example.note', text: 'matching record' };
      await applySpaceWrites(f.env, refForType(keys[1], spaceType), DID, [
        { action: 'create', collection: 'com.example.note', rkey: 'one', record: value },
      ], f.account.space_incarnation);
      await (await post('com.atproto.space.createRecord', { space: created[1], repo: referenceDid,
        collection: 'com.example.note', rkey: 'one', validate: false, record: value })).body?.cancel();
      const collectReference = async () => {
        const views: View[] = []; let cursor: string | undefined;
        for (let iteration = 0; iteration < 5; iteration++) {
          const query = new URLSearchParams({ spaceDid: referenceDid, spaceType, limit: '1', ...(cursor ? { cursor } : {}) });
          const page = await (await rpc(`com.atproto.space.listSpaces?${query}`)).json() as Page;
          if (!Array.isArray(page.spaces)) throw new Error();
          views.push(...page.spaces); cursor = page.cursor;
          if (!cursor) return views;
        }
        throw new Error();
      };
      const collectLocal = async () => {
        const views: View[] = []; let cursor: string | undefined;
        for (let iteration = 0; iteration < 5; iteration++) {
          const response = await GET(context(f.env, await f.request({ limit: '1', ...(cursor ? { cursor } : {}) })));
          if (!response.ok) throw new Error();
          const page = await response.json() as Page;
          if (!Array.isArray(page.spaces)) throw new Error();
          views.push(...page.spaces); cursor = page.cursor;
          if (!cursor) return views;
        }
        throw new Error();
      };
      const [reference, local] = await Promise.all([collectReference(), collectLocal()]);
      expect(reference.map((item) => item.space.slice(item.space.lastIndexOf('/') + 1)))
        .toEqual(local.map((item) => item.space.slice(item.space.lastIndexOf('/') + 1)));
      for (let index = 0; index < local.length; index++) {
        const expected = reference[index], actual = local[index];
        expect(actual.data).toEqual(expected.data);
        expect(!!actual.repoRev).toBe(!!expected.repoRev);
        if (actual.repoRev) expect(isValidTid(actual.repoRev) && isValidTid(expected.repoRev)).toBe(true);
      }
      const remoteRef = (key: string) => `at://${referenceDid}/space/${spaceType}/${key}`;
      const longCursor = (base: string, length: number) => `${base}#/${'a'.repeat(length - base.length - 2)}`;
      const cursors: [string, string][] = [
        ['', ''],
        [refForType(keys[0], spaceType) + '#/fragment%2Fpart', remoteRef(keys[0]) + '#/fragment%2Fpart'],
        [`at://${DID}/space/com.example.aaa/z`, `at://${referenceDid}/space/com.example.aaa/z`],
        [`at://${DID}/space/com.example.zzz/a`, `at://${referenceDid}/space/com.example.zzz/a`],
        ['at://did:aaa:other/space/com.example.other/z', 'at://did:aaa:other/space/com.example.other/z'],
        ['at://did:zzz:other/space/com.example.other/a', 'at://did:zzz:other/space/com.example.other/a'],
        [longCursor(refForType(keys[0], spaceType), 8192), longCursor(remoteRef(keys[0]), 8192)],
      ];
      for (const [localCursor, remoteCursor] of cursors) {
        const query = new URLSearchParams({ spaceDid: referenceDid, spaceType, cursor: remoteCursor });
        const remotePage = await (await rpc(`com.atproto.space.listSpaces?${query}`)).json() as Page;
        const response = await GET(context(f.env, await f.request({ cursor: localCursor })));
        expect(response.status).toBe(200);
        const localPage = await response.json() as Page;
        const expectedRefs = (reference: (key: string) => string, cursor: string) => keys.map(reference)
          .filter((space) => !cursor || space > cursor).sort();
        expect(localPage.spaces.map((item) => item.space))
          .toEqual(expectedRefs((key) => refForType(key, spaceType), localCursor));
        expect(remotePage.spaces.map((item) => item.space)).toEqual(expectedRefs(remoteRef, remoteCursor));
        expect(localPage.cursor).toBeUndefined();
        expect(remotePage.cursor).toBeUndefined();
      }
      for (const [localCursor, remoteCursor] of [
        ['not-a-space-ref', 'not-a-space-ref'],
        [refForType(keys[0], spaceType) + '/extra', remoteRef(keys[0]) + '/extra'],
        [refForType(keys[0], spaceType) + '#/%FF', remoteRef(keys[0]) + '#/%FF'],
        [longCursor(refForType(keys[0], spaceType), 8193), longCursor(remoteRef(keys[0]), 8193)],
      ]) {
        const query = new URLSearchParams({ spaceDid: referenceDid, spaceType, cursor: remoteCursor });
        const remoteResponse = await fetch(`${origin}/xrpc/com.atproto.space.listSpaces?${query}`, {
          headers: { authorization }, redirect: 'manual', signal: AbortSignal.timeout(10_000),
        });
        const localResponse = await GET(context(f.env, await f.request({ cursor: localCursor })));
        expect(remoteResponse.status).toBe(400);
        expect(localResponse.status).toBe(400);
        expect((await localResponse.text()).includes(localCursor)).toBe(false);
        await remoteResponse.body?.cancel();
      }
    } catch {
      throw new Error('Disposable reference Space listing comparison failed');
    } finally {
      for (const space of created) {
        try {
          const response = await fetch(`${origin}/xrpc/com.atproto.space.deleteSpace`, { method: 'POST', redirect: 'manual',
            signal: AbortSignal.timeout(10_000), headers: { authorization, 'content-type': 'application/json' },
            body: JSON.stringify({ space }) });
          if (!response.ok) cleanupFailed = true;
          await response.body?.cancel();
        } catch { cleanupFailed = true; }
      }
      if (cleanupFailed) throw new Error('Disposable reference Space cleanup failed');
    }
  },
});
