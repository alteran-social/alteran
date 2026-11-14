import { isValidDid } from '@atproto/syntax-spaces';
import { expect } from '@std/expect';
import { authorizedReadFixture, COLLECTION, DID, OTHER_COLLECTION, SPACE } from './helpers/spaces-authorized-read';
import { signResourceDpop } from './helpers/oauth';
import { loadActiveSpaceOwner } from '../src/db/space-owner';
import { applySpaceWrites } from '../src/db/space-store';
import { GET } from '../src/pages/xrpc/com.atproto.space.listRecords';

const configPath = Deno.env.get('ALTERAN_REFERENCE_INTEROP_CONFIG');
const ENDPOINT = 'https://pds.example/xrpc/com.atproto.space.listRecords';
const LINK = 'bafkreigh2akiscaildcw453tj2mzyv4eicv7yqmx26iubepzwcndhy6eyu';
type ListedRecord = { collection: string; rkey: string; cid: string; value?: unknown };
type Page = { records: ListedRecord[]; cursor?: string };

Deno.test({
  name: 'reference PDS agrees on value and metadata Space list pages',
  ignore: !configPath,
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    if (!configPath) throw new Error('Missing reference configuration');
    const config: unknown = JSON.parse(await Deno.readTextFile(configPath));
    if (!config || typeof config !== 'object') throw new Error('Invalid reference configuration');
    const fields = config as Record<string, unknown>;
    const origin = loopbackOrigin(fields.pds);
    if (!isValidDid(fields.did) || typeof fields.accessJwt !== 'string' || !fields.accessJwt) {
      throw new Error('Invalid disposable reference account');
    }
    const repo = fields.did;
    const skey = `values-${crypto.randomUUID()}`;
    const space = `at://${repo}/space/com.example.notes/${skey}`;
    const authorization = `Bearer ${fields.accessJwt}`;
    const rpc = async (name: string, init: RequestInit = {}) => {
      const headers = new Headers(init.headers);
      headers.set('authorization', authorization);
      const response = await fetch(`${origin}/xrpc/${name}`, {
        ...init, headers, redirect: 'manual', signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error(`Reference ${name.split('?')[0]} returned HTTP ${response.status}`);
      }
      return response;
    };
    const post = (name: string, body: unknown) => rpc(name, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    });
    const fixture = await authorizedReadFixture();
    const owner = await loadActiveSpaceOwner(fixture.env, DID);
    if (!owner) throw new Error('Missing Alteran Space owner');
    const rich = {
      $type: COLLECTION,
      nested: { link: { $link: LINK }, bytes: { $bytes: 'AP8=' } },
      controls: '\u0000\n\t\r"\\',
    };
    const additions = [
      { collection: COLLECTION, rkey: 'z', record: rich },
      { collection: 'com.example.note.sub', rkey: 'a', record: { $type: 'com.example.note.sub', text: 'sibling' } },
    ];
    await applySpaceWrites(fixture.env, SPACE, DID, additions.map((item) => ({ action: 'create' as const, ...item })),
      owner.incarnation);
    const records = [
      { collection: COLLECTION, rkey: 'one', record: { $type: COLLECTION, text: 'private' } },
      { collection: OTHER_COLLECTION, rkey: 'two', record: { $type: OTHER_COLLECTION, text: 'also private' } },
      ...additions,
    ];
    let attempted = false;
    try {
      attempted = true;
      const created = await post('com.atproto.space.createSpace', {
        spaceType: 'com.example.notes', skey, policy: { $type: 'com.atproto.personalspace.policy' },
      });
      expect((await created.json() as { space: string }).space).toBe(space);
      for (const item of records) {
        const createdRecord = await post('com.atproto.space.createRecord', {
          space, repo, collection: item.collection, rkey: item.rkey, validate: false, record: item.record,
        });
        await createdRecord.body?.cancel();
      }

      async function referencePage(params: Record<string, string>): Promise<Page> {
        const query = new URLSearchParams({ space, repo, ...params });
        return await (await rpc(`com.atproto.space.listRecords?${query}`)).json() as Page;
      }
      async function alteranPage(params: Record<string, string>): Promise<Page> {
        const query = new URLSearchParams({ space: SPACE, repo: DID, ...params });
        const request = new Request(`${ENDPOINT}?${query}`, { headers: {
          authorization: `DPoP ${fixture.tokens.accessJwt}`,
          dpop: await signResourceDpop(fixture.env, fixture.key, 'GET', ENDPOINT, fixture.tokens.accessJwt),
        } });
        const response = await GET({ locals: { env: fixture.env }, request, url: new URL(request.url) } as never);
        if (!response.ok) throw new Error(`Alteran listRecords returned HTTP ${response.status}`);
        return await response.json() as Page;
      }
      for (const mode of ['default', 'false', 'true'] as const) {
        const valueMode: Record<string, string> = mode === 'default' ? {} : { excludeValues: mode };
        for (const collection of [undefined, COLLECTION, 'com.example.note.sub', 'com.example.empty']) {
          let referenceCursor: string | undefined;
          let alteranCursor: string | undefined;
          const all: ListedRecord[] = [];
          let pages = 0;
          for (; pages < 4; pages++) {
            const common: Record<string, string> = { ...valueMode, limit: '2', ...(collection ? { collection } : {}) };
            const reference = await referencePage({ ...common, ...(referenceCursor ? { cursor: referenceCursor } : {}) });
            const actual = await alteranPage({ ...common, ...(alteranCursor ? { cursor: alteranCursor } : {}) });
            expect(actual.records).toEqual(reference.records);
            for (const item of actual.records) {
              expect(Object.hasOwn(item, 'value')).toBe(mode !== 'true');
            }
            expect(cursorPath(actual.cursor, SPACE, DID)).toBe(cursorPath(reference.cursor, space, repo));
            all.push(...actual.records);
            referenceCursor = reference.cursor;
            alteranCursor = actual.cursor;
            if (!referenceCursor) break;
          }
          if (pages === 4) throw new Error('Reference pagination did not terminate');
          const paths = all.map(({ collection: nsid, rkey }) => `${nsid}/${rkey}`);
          const expected = collection === COLLECTION ? [`${COLLECTION}/z`, `${COLLECTION}/one`]
            : collection === 'com.example.note.sub' ? ['com.example.note.sub/a']
            : collection === 'com.example.empty' ? []
            : [`${OTHER_COLLECTION}/two`, `${COLLECTION}/z`, `${COLLECTION}/one`, 'com.example.note.sub/a'];
          expect(paths).toEqual(expected);
          if (collection === undefined) expect(pages).toBe(2);
          if (collection === COLLECTION) expect(pages).toBe(1);
          if (mode !== 'true' && collection === undefined) {
            const record = all.find(({ collection: nsid, rkey }) => nsid === COLLECTION && rkey === 'z');
            expect(record?.value).toEqual({
              $type: COLLECTION, nested: { link: { $link: LINK }, bytes: { $bytes: 'AP8' } },
              controls: rich.controls,
            });
          }
        }
        const firstReference = await referencePage({ ...valueMode, limit: '2' });
        const firstAlteran = await alteranPage({ ...valueMode, limit: '2' });
        if (!firstReference.cursor || !firstAlteran.cursor) throw new Error('Missing full-page cursor');
        const reference = await referencePage({ ...valueMode, limit: '2', collection: COLLECTION, cursor: firstReference.cursor });
        const actual = await alteranPage({ ...valueMode, limit: '2', collection: COLLECTION, cursor: firstAlteran.cursor });
        expect(actual.records).toEqual(reference.records);
        expect(actual.records.map(({ rkey }) => rkey)).toEqual(['one']);
        expect(actual.cursor).toBeUndefined();
        expect(reference.cursor).toBeUndefined();
      }
    } finally {
      if (attempted) {
        const deleted = await fetch(`${origin}/xrpc/com.atproto.space.deleteSpace`, {
          method: 'POST', headers: { authorization, 'content-type': 'application/json' },
          body: JSON.stringify({ space }), redirect: 'manual', signal: AbortSignal.timeout(10_000),
        });
        if (!deleted.ok && (await deleted.json() as { error?: string }).error !== 'SpaceNotFound') {
          throw new Error(`Reference cleanup returned HTTP ${deleted.status}`);
        }
        await deleted.body?.cancel();
      }
    }
  },
});

function cursorPath(cursor: string | undefined, space: string, repo: string): string | undefined {
  if (cursor === undefined) return undefined;
  const prefix = `${space}/${repo}/`;
  if (!cursor.startsWith(prefix)) throw new Error('Cursor belongs to another Space or repo');
  return cursor.slice(prefix.length);
}

function loopbackOrigin(value: unknown): string {
  if (typeof value !== 'string') throw new Error('A loopback URL is required');
  const url = new URL(value);
  if (url.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ||
    url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Only a loopback reference PDS origin is allowed');
  }
  return url.origin;
}
