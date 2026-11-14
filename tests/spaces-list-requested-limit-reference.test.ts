import { expect } from '@std/expect';
import { isValidDid } from '@atproto/syntax-spaces';
import { authorizedReadFixture, COLLECTION, OTHER_COLLECTION } from './helpers/spaces-authorized-read';
import { additionalRecords, localPage, seed, traverse, type Page } from './helpers/spaces-request-limit';

const configPath = Deno.env.get('ALTERAN_REFERENCE_INTEROP_CONFIG');

Deno.test({ name: 'reference and bounded Space lists return the same complete traversals',
  ignore: !configPath, sanitizeOps: false, sanitizeResources: false, async fn() {
    try { await compare(); } catch { throw new Error('Reference list traversal failed'); }
  },
});

async function compare(): Promise<void> {
  if (!configPath) throw new Error();
  const config: unknown = JSON.parse(await Deno.readTextFile(configPath));
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error();
  const fields = config as Record<string, unknown>;
  const origin = loopbackOrigin(fields.pds);
  if (!isValidDid(fields.did) || typeof fields.accessJwt !== 'string' || !fields.accessJwt) throw new Error();
  const repo = fields.did, authorization = `Bearer ${fields.accessJwt}`;
  const space = `at://${repo}/space/com.example.notes/page-${crypto.randomUUID()}`;
  const rpc = (name: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    headers.set('authorization', authorization);
    return fetch(`${origin}/xrpc/${name}`, { ...init, headers, redirect: 'manual', signal: AbortSignal.timeout(10_000) });
  };
  const post = (name: string, body: unknown) => rpc(name, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const records = [
    { collection: COLLECTION, rkey: 'one', record: { $type: COLLECTION, text: 'private' } },
    { collection: OTHER_COLLECTION, rkey: 'two', record: { $type: OTHER_COLLECTION, text: 'also private' } },
    ...additionalRecords(),
  ];
  const f = await authorizedReadFixture();
  await seed(f);
  let attempted = false;
  try {
    attempted = true;
    const created = await post('com.atproto.space.createSpace', {
      spaceType: 'com.example.notes', skey: space.split('/').at(-1), policy: { $type: 'com.atproto.personalspace.policy' },
    });
    if (!created.ok || (await created.json() as { space?: unknown }).space !== space) throw new Error();
    const writes = records.map(({ collection, rkey, record }) => ({
      $type: 'com.atproto.space.applyWrites#create', collection, rkey, value: record,
    }));
    const written = await post('com.atproto.space.applyWrites', { space, repo, validate: false, writes });
    if (!written.ok) throw new Error();
    await written.body?.cancel();
    async function referencePage(params: Record<string, string>): Promise<Page> {
      const query = new URLSearchParams({ space, repo, ...params });
      const response = await rpc(`com.atproto.space.listRecords?${query}`);
      if (!response.ok) throw new Error();
      const page: unknown = await response.json();
      if (!page || typeof page !== 'object' || Array.isArray(page) || !Array.isArray((page as Page).records) ||
        ((page as Page).cursor !== undefined && typeof (page as Page).cursor !== 'string')) throw new Error();
      return page as Page;
    }
    for (const excludeValues of ['true', 'false']) {
      for (const collection of [undefined, COLLECTION]) {
        const params = { excludeValues, limit: '1000', ...(collection ? { collection } : {}) };
        const reference = await traverse(referencePage, params);
        const local = await traverse((query) => localPage(f, query), params);
        expect(local.records).toEqual(reference.records);
        expect(reference.lengths).toEqual([collection ? 100 : 101]);
        expect(local.lengths).toEqual(collection ? [50, 50, 0] : [50, 50, 1]);
      }
    }
  } finally {
    if (attempted) {
      const response = await post('com.atproto.space.deleteSpace', { space });
      if (response.ok) await response.body?.cancel();
      else if (response.status !== 400 || (await response.json() as { error?: unknown }).error !== 'SpaceNotFound') throw new Error();
    }
  }
}

function loopbackOrigin(value: unknown): string {
  if (typeof value !== 'string') throw new Error();
  const url = new URL(value);
  if (url.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ||
    url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error();
  return url.origin;
}
