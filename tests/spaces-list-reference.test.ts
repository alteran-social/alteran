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

Deno.test('malformed reference input errors do not expose credentials', async () => {
  const sentinel = 'leakme';
  const malformed = `{"accessJwt":${sentinel}}`;
  const path = await Deno.makeTempFile();
  try {
    await Deno.writeTextFile(path, malformed);
    for (const [run, message] of [
      [() => readReferenceConfig(path), 'Invalid reference configuration'],
      [() => readReferenceJson(new Response(malformed)), 'Invalid reference response'],
      [() => loopbackOrigin(`http://[${sentinel}`), 'Only a loopback reference PDS origin is allowed'],
      [() => referenceFetch('http://127.0.0.1', `Bearer ${sentinel}\0`, {}), 'Reference request failed'],
    ] as const) {
      let error: unknown;
      try {
        await run();
      } catch (caught) {
        error = caught;
      }
      expect(error instanceof Error && error.message === message).toBe(true);
      expect(error instanceof Error && !!error.stack && !error.stack.includes(sentinel)).toBe(true);
    }
  } finally {
    await Deno.remove(path);
  }
});

Deno.test({
  name: 'reference PDS agrees on metadata-only Space record pagination',
  ignore: !configPath,
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    if (!configPath) throw new Error('Missing reference configuration');
    const config = await readReferenceConfig(configPath);
    if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Invalid reference configuration');
    const fields = config as Record<string, unknown>;
    const origin = loopbackOrigin(fields.pds);
    if (typeof fields.did !== 'string' || !isValidDid(fields.did) ||
      typeof fields.accessJwt !== 'string' || !fields.accessJwt) {
      throw new Error('Invalid disposable reference account');
    }
    const repo = fields.did;
    const space = `at://${repo}/space/com.example.notes/list-${crypto.randomUUID()}`;
    const authorization = `Bearer ${fields.accessJwt}`;
    const rpc = async (name: string, init: RequestInit = {}) => {
      const response = await referenceFetch(`${origin}/xrpc/${name}`, authorization, init);
      if (!response.ok) {
        await discardResponse(response);
        throw new Error('Reference request returned an error');
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
      const createdValue = await readReferenceJson(created);
      if (!createdValue || typeof createdValue !== 'object' ||
        (createdValue as Record<string, unknown>).space !== space) throw new Error('Reference returned the wrong Space');
      for (const item of records) {
        const response = await post('com.atproto.space.createRecord', {
          space, repo, collection: item.collection, rkey: item.rkey, validate: false, record: item.record,
        });
        await discardResponse(response);
      }

      async function referencePage(params: Record<string, string>): Promise<Page> {
        const query = new URLSearchParams({ space, repo, excludeValues: 'true', ...params });
        return metadataPage(await readReferenceJson(await rpc(`com.atproto.space.listRecords?${query}`)));
      }
      async function alteranPage(params: Record<string, string>): Promise<Page> {
        const query = new URLSearchParams({ space: SPACE, repo: DID, excludeValues: 'true', ...params });
        const request = new Request(`${ENDPOINT}?${query}`, { headers: {
          authorization: `DPoP ${f.tokens.accessJwt}`,
          dpop: await signResourceDpop(f.env, f.key, 'GET', ENDPOINT, f.tokens.accessJwt),
        } });
        const response = await GET({ locals: { env: f.env }, request, url: new URL(request.url) } as never);
        if (!response.ok) throw new Error(`Alteran listRecords returned HTTP ${response.status}`);
        return metadataPage(await readReferenceJson(response));
      }
      for (const collection of [undefined, COLLECTION, 'com.example.note.sub']) {
        let referenceCursor: string | undefined;
        let alteranCursor: string | undefined;
        const all: Metadata[] = [];
        for (let page = 0; page < 4; page++) {
          const common = { limit: '2', ...(collection ? { collection } : {}) };
          const ref = await referencePage({ ...common, ...(referenceCursor ? { cursor: referenceCursor } : {}) });
          const actual = await alteranPage({ ...common, ...(alteranCursor ? { cursor: alteranCursor } : {}) });
          if (!sameRecords(actual.records, ref.records)) throw new Error('Record metadata differs');
          if (cursorPath(actual.cursor, SPACE, DID) !== cursorPath(ref.cursor, space, repo)) {
            throw new Error('Pagination cursors differ');
          }
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
        if (!sameStrings(paths, expected)) throw new Error('Record order or collection filtering differs');
      }
      const referenceFirst = await referencePage({ limit: '2' });
      const alteranFirst = await alteranPage({ limit: '2' });
      if (!referenceFirst.cursor || !alteranFirst.cursor) throw new Error('Missing full-page cursor');
      const refFiltered = await referencePage({ limit: '2', collection: COLLECTION, cursor: referenceFirst.cursor });
      const actualFiltered = await alteranPage({ limit: '2', collection: COLLECTION, cursor: alteranFirst.cursor });
      if (!sameRecords(actualFiltered.records, refFiltered.records)) throw new Error('Filtered record metadata differs');
      if (!sameStrings(actualFiltered.records.map(({ rkey }) => rkey), ['one'])) {
        throw new Error('Filtered record keys differ');
      }
      if (actualFiltered.cursor !== undefined || refFiltered.cursor !== undefined) {
        throw new Error('Unexpected filtered pagination cursor');
      }
    } finally {
      if (attempted) {
        try {
          const response = await referenceFetch(`${origin}/xrpc/com.atproto.space.deleteSpace`, authorization, {
            method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ space }),
          });
          if (!response.ok) {
            const result = await readReferenceJson(response);
            if (!result || typeof result !== 'object' ||
              (result as Record<string, unknown>).error !== 'SpaceNotFound') throw new Error('Reference cleanup failed');
          } else {
            await discardResponse(response);
          }
        } catch {
          throw new Error('Reference cleanup failed');
        }
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
  let url: URL;
  try {
    if (typeof value !== 'string') throw new Error();
    url = new URL(value);
  } catch {
    throw new Error('Only a loopback reference PDS origin is allowed');
  }
  if (url.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ||
    url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Only a loopback reference PDS origin is allowed');
  }
  return url.origin;
}

async function readReferenceConfig(path: string): Promise<unknown> {
  try {
    return JSON.parse(await Deno.readTextFile(path));
  } catch {
    throw new Error('Invalid reference configuration');
  }
}

async function readReferenceJson(response: Response): Promise<unknown> {
  try {
    return JSON.parse(await response.text());
  } catch {
    throw new Error('Invalid reference response');
  }
}

async function referenceFetch(url: string, authorization: string, init: RequestInit): Promise<Response> {
  try {
    const headers = new Headers(init.headers);
    headers.set('authorization', authorization);
    return await fetch(url, { ...init, headers, redirect: 'manual', signal: AbortSignal.timeout(10_000) });
  } catch {
    throw new Error('Reference request failed');
  }
}

async function discardResponse(response: Response): Promise<void> {
  try {
    if (!response.bodyUsed) await response.body?.cancel();
  } catch {
    throw new Error('Reference response could not be discarded');
  }
}

function metadataPage(value: unknown): Page {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid metadata page');
  const fields = value as Record<string, unknown>;
  if (!Array.isArray(fields.records) || (fields.cursor !== undefined && typeof fields.cursor !== 'string')) {
    throw new Error('Invalid metadata page');
  }
  for (const record of fields.records) {
    if (!record || typeof record !== 'object' || Array.isArray(record) || Object.keys(record).length !== 3 ||
      typeof record.cid !== 'string' || typeof record.collection !== 'string' || typeof record.rkey !== 'string') {
      throw new Error('Invalid metadata page');
    }
  }
  return value as Page;
}

function sameRecords(left: Metadata[], right: Metadata[]): boolean {
  return left.length === right.length && left.every((item, index) =>
    item.cid === right[index].cid && item.collection === right[index].collection && item.rkey === right[index].rkey
  );
}

function sameStrings(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}
