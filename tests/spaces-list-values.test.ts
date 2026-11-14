import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { authorizedReadFixture, interceptRead, COLLECTION, DID, OTHER_COLLECTION, SPACE } from './helpers/spaces-authorized-read';
import { signResourceDpop } from './helpers/oauth';
import { loadActiveSpaceOwner } from '../src/db/space-owner';
import { applySpaceWrites } from '../src/db/space-store';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';
import { GET } from '../src/pages/xrpc/com.atproto.space.listRecords';

const ENDPOINT = 'https://pds.example/xrpc/com.atproto.space.listRecords';
const LINK = 'bafkreigh2akiscaildcw453tj2mzyv4eicv7yqmx26iubepzwcndhy6eyu';
type Fixture = Awaited<ReturnType<typeof authorizedReadFixture>>;
type Page = { records: { collection: string; rkey: string; cid: string; value?: unknown }[]; cursor?: string };

async function request(f: Fixture, params: Record<string, string> = {}, env: Fixture['env'] = f.env, signal?: AbortSignal) {
  const query = new URLSearchParams({ space: SPACE, repo: DID, ...params });
  const request = new Request(`${ENDPOINT}?${query}`, { headers: {
    authorization: `DPoP ${f.tokens.accessJwt}`,
    dpop: await signResourceDpop(env, f.key, 'GET', ENDPOINT, f.tokens.accessJwt),
  }, signal });
  const context = { locals: { env }, request, url: new URL(request.url) } as never;
  return GET(context);
}

async function disableRecordFences(f: Fixture) {
  for (const name of ['space_record_fence_update', 'space_record_version_update_guard', 'space_version_fence_update']) {
    await f.env.ALTERAN_DB.prepare(`DROP TRIGGER ${name}`).run();
  }
}

describe('Space list value responses', () => {
  it('defaults to values, accepts false and preserves Lex JSON links and bytes', async () => {
    const f = await authorizedReadFixture();
    const owner = await loadActiveSpaceOwner(f.env, DID);
    if (!owner) throw new Error('Missing owner');
    const rich = { $type: COLLECTION, nested: { link: { $link: LINK }, bytes: { $bytes: 'AP8=' } } };
    await applySpaceWrites(f.env, SPACE, DID, [{ action: 'create', collection: COLLECTION, rkey: 'rich', record: rich }],
      owner.incarnation);
    const first = await request(f);
    expect(first.status).toBe(200);
    const page = await first.json() as Page;
    expect(page.records.map(({ collection, rkey }) => `${collection}/${rkey}`))
      .toEqual([`${OTHER_COLLECTION}/two`, `${COLLECTION}/rich`, `${COLLECTION}/one`]);
    expect(page.records[0].value).toEqual({ $type: OTHER_COLLECTION, text: 'also private' });
    expect(page.records[1].value).toEqual({ $type: COLLECTION, nested: { link: { $link: LINK }, bytes: { $bytes: 'AP8' } } });
    expect(page.records[2].value).toEqual({ $type: COLLECTION, text: 'private' });
    const explicit = await request(f, { excludeValues: 'false' });
    expect(await explicit.json()).toEqual(page);
    const metadata = await request(f, { excludeValues: 'true' });
    expect((await metadata.json() as Page).records.every((row) => !Object.hasOwn(row, 'value'))).toBe(true);
    const paged = await request(f, { limit: '2' });
    const firstPage = await paged.json() as Page;
    expect(firstPage.records).toHaveLength(2);
    if (!firstPage.cursor) throw new Error('Missing cursor');
    const next = await request(f, { limit: '2', cursor: firstPage.cursor });
    const secondPage = await next.json() as Page;
    expect(secondPage.records).toHaveLength(1);
    expect(secondPage.records[0].value).toEqual({ $type: COLLECTION, text: 'private' });
    expect(secondPage.cursor).toBeUndefined();
  });

  it('gates a content-integrity error on post-selection authorization', async () => {
    for (const revoke of [false, true]) {
      const f = await authorizedReadFixture();
      await disableRecordFences(f);
      const [otherCid] = await encodeRecordBlock({ $type: COLLECTION, text: 'other' });
      await f.env.ALTERAN_DB.prepare('UPDATE space_record SET cid = ? WHERE space_ref = ? AND collection = ?')
        .bind(otherCid.toString(), SPACE, COLLECTION).run();
      await f.env.ALTERAN_DB.prepare('UPDATE space_record_version SET cid = ? WHERE space_ref = ? AND collection = ?')
        .bind(otherCid.toString(), SPACE, COLLECTION).run();
      const watched = interceptRead(f.env, { after: async () => {
        if (revoke) await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
          .bind(f.sessionId).run();
      } });
      watched.arm();
      const response = await request(f, { collection: COLLECTION }, watched.env);
      expect(response.status).toBe(revoke ? 401 : 500);
      expect(await response.text()).not.toContain('private');
    }
  });

  it('withholds value pages after revocation or cancellation during selection', async () => {
    for (const mode of ['revoke', 'cancel'] as const) {
      const f = await authorizedReadFixture();
      const controller = new AbortController();
      const watched = interceptRead(f.env, { after: async () => {
        if (mode === 'cancel') controller.abort();
        else await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
          .bind(f.sessionId).run();
      } });
      watched.arm();
      const response = await request(f, {}, watched.env, controller.signal);
      expect(response.status).toBe(401);
      expect(await response.text()).not.toContain('private');
    }
  });

  it('gates malformed D1 value arrays on final authorization', async () => {
    for (const revoke of [false, true]) {
      const f = await authorizedReadFixture();
      const watched = interceptRead(f.env, { after: async (result) => {
        const rows = (result[2] as { results?: { sentinel: number; value_cbor: unknown }[] }).results;
        const row = rows?.find((entry) => entry.sentinel === 0);
        if (!row) throw new Error('Missing selected value');
        row.value_cbor = [0, 256];
        if (revoke) await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
          .bind(f.sessionId).run();
      } });
      watched.arm();
      const response = await request(f, { collection: COLLECTION }, watched.env);
      expect(response.status).toBe(revoke ? 401 : 500);
      expect(await response.text()).not.toContain('private');
    }
  });

  it('gates response serialization failures on final authorization', async () => {
    for (const revoke of [false, true]) {
      const f = await authorizedReadFixture();
      const OriginalResponse = globalThis.Response;
      let faulted = false;
      const watched = interceptRead(f.env, { after: async () => {
        if (revoke) await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
          .bind(f.sessionId).run();
        globalThis.Response = class extends OriginalResponse {
          constructor(body?: BodyInit | null, init?: ResponseInit) {
            if (typeof body === 'string' && body.startsWith('{"records":[')) {
              faulted = true;
              throw new Error('private list serialization failure');
            }
            super(body, init);
          }
        };
      } });
      watched.arm();
      try {
        const response = await request(f, {}, watched.env);
        expect(faulted).toBe(true);
        expect(response.status).toBe(revoke ? 401 : 500);
        expect(await response.text()).not.toContain('private list serialization failure');
      } finally {
        globalThis.Response = OriginalResponse;
      }
    }
  });
});
