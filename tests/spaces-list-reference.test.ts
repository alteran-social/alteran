import { isValidDid } from '@atproto/syntax-spaces';
import { expect } from '@std/expect';
import { authorizedReadFixture, COLLECTION, DID, OTHER_COLLECTION, SPACE } from './helpers/spaces-authorized-read';
import { signResourceDpop } from './helpers/oauth';
import { loadActiveSpaceOwner } from '../src/db/space-owner';
import { applySpaceWrites } from '../src/db/space-store';
import { GET } from '../src/pages/xrpc/com.atproto.space.listRecords';

const configPath = Deno.env.get('ALTERAN_REFERENCE_INTEROP_CONFIG');
const ENDPOINT = 'https://pds.example/xrpc/com.atproto.space.listRecords';

type Metadata = { collection: string; rkey: string; cid: string };
type Page = { records: Metadata[]; cursor?: string };

Deno.test({
  name: 'reference PDS agrees on metadata-only Space record pagination',
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
    const space = `at://${repo}/space/com.example.notes/list-${crypto.randomUUID()}`;
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
    const post = (name: string, value: unknown) => rpc(name, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(value),
    });
    const f = await authorizedReadFixture();
    const owner = await loadActiveSpaceOwner(f.env, DID);
    if (!owner) throw new Error('Missing Alteran Space owner');
    const additions = [
      { collection: COLLECTION, rkey: 'z', record: { $type: COLLECTION, text: 'z' } },
      { collection: 'com.example.note.sub', rkey: 'a', record: { $type: 'com.example.note.sub', text: 'sibling' } },
    ];
    await applySpaceWrites(f.env, SPACE, DID, additions.map((item) => ({ action: 'create' as const, ...item })), owner.incarnation);
    const records = [
      { collection: COLLECTION, rkey: 'one', record: { $type: COLLECTION, text: 'private' } },
      { collection: OTHER_COLLECTION, rkey: 'two', record: { $type: OTHER_COLLECTION, text: 'also private' } },
      ...additions,
    ];
    let attempted = false;
    try {
      attempted = true;
      const created = await post('com.atproto.space.createSpace', {
        spaceType: 'com.example.notes', skey: space.slice(space.lastIndexOf('/') + 1),
        policy: { $type: 'com.atproto.personalspace.policy' },
      });
      expect((await created.json() as { space: string }).space).toBe(space);
      for (const item of records) {
        const response = await post('com.atproto.space.createRecord', {
          space, repo, collection: item.collection, rkey: item.rkey, validate: false, record: item.record,
        });
        await response.body?.cancel();
      }

      async function referencePage(params: Record<string, string>): Promise<Page> {
        const query = new URLSearchParams({ space, repo, excludeValues: 'true', ...params });
        return await (await rpc(`com.atproto.space.listRecords?${query}`)).json() as Page;
      }
      async function alteranPage(params: Record<string, string>): Promise<Page> {
        const query = new URLSearchParams({ space: SPACE, repo: DID, excludeValues: 'true', ...params });
        const request = new Request(`${ENDPOINT}?${query}`, { headers: {
          authorization: `DPoP ${f.tokens.accessJwt}`,
          dpop: await signResourceDpop(f.env, f.key, 'GET', ENDPOINT, f.tokens.accessJwt),
        } });
        const response = await GET({ locals: { env: f.env }, request, url: new URL(request.url) } as never);
        if (!response.ok) throw new Error(`Alteran listRecords returned HTTP ${response.status}`);
        return await response.json() as Page;
      }
      for (const collection of [undefined, COLLECTION, 'com.example.note.sub']) {
        let referenceCursor: string | undefined;
        let alteranCursor: string | undefined;
        const all: Metadata[] = [];
        for (let page = 0; page < 4; page++) {
          const common = { limit: '2', ...(collection ? { collection } : {}) };
          const ref = await referencePage({ ...common, ...(referenceCursor ? { cursor: referenceCursor } : {}) });
          const actual = await alteranPage({ ...common, ...(alteranCursor ? { cursor: alteranCursor } : {}) });
          expect(actual.records).toEqual(ref.records);
          for (const item of actual.records) expect(Object.keys(item).sort()).toEqual(['cid', 'collection', 'rkey']);
          expect(cursorPath(actual.cursor, SPACE, DID)).toBe(cursorPath(ref.cursor, space, repo));
          all.push(...actual.records);
          referenceCursor = ref.cursor;
          alteranCursor = actual.cursor;
          if (!referenceCursor) break;
          if (page === 3) throw new Error('Reference pagination did not terminate');
        }
        const paths = all.map(({ collection: nsid, rkey }) => `${nsid}/${rkey}`);
        const expected = collection === COLLECTION ? [`${COLLECTION}/z`, `${COLLECTION}/one`]
          : collection ? ['com.example.note.sub/a']
          : [`${OTHER_COLLECTION}/two`, `${COLLECTION}/z`, `${COLLECTION}/one`, 'com.example.note.sub/a'];
        expect(paths).toEqual(expected);
      }
      const referenceFirst = await referencePage({ limit: '2' });
      const alteranFirst = await alteranPage({ limit: '2' });
      if (!referenceFirst.cursor || !alteranFirst.cursor) throw new Error('Missing full-page cursor');
      const refFiltered = await referencePage({ limit: '2', collection: COLLECTION, cursor: referenceFirst.cursor });
      const actualFiltered = await alteranPage({ limit: '2', collection: COLLECTION, cursor: alteranFirst.cursor });
      expect(actualFiltered.records).toEqual(refFiltered.records);
      expect(actualFiltered.records.map(({ rkey }) => rkey)).toEqual(['one']);
      expect(actualFiltered.cursor).toBeUndefined();
      expect(refFiltered.cursor).toBeUndefined();
    } finally {
      if (attempted) {
        const response = await fetch(`${origin}/xrpc/com.atproto.space.deleteSpace`, {
          method: 'POST', headers: { authorization, 'content-type': 'application/json' },
          body: JSON.stringify({ space }), redirect: 'manual', signal: AbortSignal.timeout(10_000),
        });
        if (!response.ok && (await response.json() as { error?: string }).error !== 'SpaceNotFound') {
          throw new Error(`Reference cleanup returned HTTP ${response.status}`);
        }
        await response.body?.cancel();
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
