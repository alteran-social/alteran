import { MAX_RECORD_SIZE } from '@atproto/space';
import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { authorizedReadFixture, interceptRead, COLLECTION, DID, SPACE } from './helpers/spaces-authorized-read';
import { signResourceDpop } from './helpers/oauth';
import { loadActiveSpaceOwner } from '../src/db/space-owner';
import { applySpaceWrites } from '../src/db/space-store';
import { inspectRecordCborBounds, MAX_RECORD_CBOR_ITEMS } from '../src/lib/spaces/record-cbor-bounds';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';
import { GET } from '../src/pages/xrpc/com.atproto.space.listRecords';

const ENDPOINT = 'https://pds.example/xrpc/com.atproto.space.listRecords';
type Fixture = Awaited<ReturnType<typeof authorizedReadFixture>>;
type Page = { records: { collection: string; rkey: string; cid: string; value: unknown }[]; cursor?: string };
type SelectedRow = { sentinel: number; too_large: number; collection: unknown; rkey: unknown; cid: unknown; value_cbor: unknown };

async function request(f: Fixture, params: Record<string, string>, env: Fixture['env'] = f.env) {
  const query = new URLSearchParams({ space: SPACE, repo: DID, collection: COLLECTION, ...params });
  const request = new Request(`${ENDPOINT}?${query}`, { headers: {
    authorization: `DPoP ${f.tokens.accessJwt}`,
    dpop: await signResourceDpop(env, f.key, 'GET', ENDPOINT, f.tokens.accessJwt),
  } });
  return GET({ locals: { env }, request, url: new URL(request.url) } as never);
}

async function createPair(f: Fixture, record: Record<string, unknown>) {
  const owner = await loadActiveSpaceOwner(f.env, DID);
  if (!owner) throw new Error('Missing owner');
  for (const rkey of ['z-y', 'z-z']) {
    await applySpaceWrites(f.env, SPACE, DID, [{ action: 'create', collection: COLLECTION, rkey, record }], owner.incarnation);
  }
}

function assertOversizeProjection(value: unknown) {
  if (!Array.isArray(value)) throw new Error('Missing page result');
  const rows = value as SelectedRow[];
  expect(rows.length).toBe(1);
  expect(rows[0].sentinel).toBe(1);
  expect(rows[0].too_large).toBe(1);
  expect(rows[0].collection === null && rows[0].rkey === null && rows[0].cid === null).toBe(true);
  expect(rows[0].value_cbor === null).toBe(true);
  expect(JSON.stringify(rows).length).toBeLessThan(1_000);
}

async function expectTooLarge(response: Response) {
  expect(response.status).toBe(400);
  expect(response.headers.get('cache-control')).toBe('private, no-store');
  const body = await response.json() as { error?: unknown; records?: unknown };
  expect(body.error === 'InvalidRequest').toBe(true);
  expect(Object.hasOwn(body, 'records')).toBe(false);
}

describe('Space list value resource bounds', () => {
  it('projects no page rows over 1 MiB and reauthorizes the size error', async () => {
    const f = await authorizedReadFixture();
    const text = 'x'.repeat(600_000);
    await createPair(f, { $type: COLLECTION, text });

    const oversized = interceptRead(f.env);
    oversized.arm();
    await expectTooLarge(await request(f, { limit: '2' }, oversized.env));
    assertOversizeProjection(oversized.returned());

    const smaller = await request(f, { limit: '1' });
    expect(smaller.status).toBe(200);
    const page = await smaller.json() as Page;
    expect(page.records.length).toBe(1);
    expect(page.records[0].rkey === 'z-z').toBe(true);
    expect((page.records[0].value as { text?: unknown }).text === text).toBe(true);

    const revoked = interceptRead(f.env, { after: async () => {
      await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
        .bind(f.sessionId).run();
    } });
    revoked.arm();
    const denied = await request(f, { limit: '2' }, revoked.env);
    assertOversizeProjection(revoked.returned());
    expect(denied.status).toBe(401);
    const deniedBody = await denied.json() as { error?: unknown; records?: unknown };
    expect(deniedBody.error === 'AuthRequired').toBe(true);
    expect(Object.hasOwn(deniedBody, 'records')).toBe(false);
  });

  it('rejects an aggregate item budget overrun without returning a shortened page', async () => {
    const f = await authorizedReadFixture();
    const record = { $type: COLLECTION, values: Array.from({ length: 65_535 }, () => null) };
    const [, bytes] = await encodeRecordBlock(record);
    const inspected = inspectRecordCborBounds(bytes);
    if (inspected.tag !== 'valid') throw new Error('Invalid item-bound fixture');
    expect(inspected.items).toBeLessThanOrEqual(MAX_RECORD_CBOR_ITEMS);
    expect(inspected.items * 2).toBeGreaterThan(MAX_RECORD_CBOR_ITEMS);
    expect(bytes.byteLength * 2).toBeLessThan(MAX_RECORD_SIZE);
    await createPair(f, record);

    const oversized = interceptRead(f.env);
    oversized.arm();
    await expectTooLarge(await request(f, { limit: '2' }, oversized.env));
    const rows = oversized.returned();
    if (!Array.isArray(rows)) throw new Error('Missing selected page');
    expect((rows as SelectedRow[]).filter((row) => row.sentinel === 0).length).toBe(2);
    expect((rows as SelectedRow[]).find((row) => row.sentinel === 1)?.too_large).toBe(0);

    const smaller = await request(f, { limit: '1' });
    expect(smaller.status).toBe(200);
    const page = await smaller.json() as Page;
    expect(page.records.length).toBe(1);
    const values = (page.records[0].value as { values?: unknown }).values;
    expect(Array.isArray(values) ? values.length : -1).toBe(65_535);

    const revoked = interceptRead(f.env, { after: async () => {
      await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
        .bind(f.sessionId).run();
    } });
    revoked.arm();
    const denied = await request(f, { limit: '2' }, revoked.env);
    expect(denied.status).toBe(401);
    const deniedBody = await denied.json() as { error?: unknown; records?: unknown };
    expect(deniedBody.error === 'AuthRequired').toBe(true);
    expect(Object.hasOwn(deniedBody, 'records')).toBe(false);
  });

  it('projects no value rows when revocation wins before the page query', async () => {
    const f = await authorizedReadFixture();
    const watched = interceptRead(f.env, { before: async () => {
      await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
        .bind(f.sessionId).run();
    } });
    watched.arm();
    const denied = await request(f, { limit: '2' }, watched.env);
    expect(denied.status).toBe(401);
    const rows = watched.returned();
    expect(Array.isArray(rows) ? rows.length : -1).toBe(0);
    const deniedBody = await denied.json() as { error?: unknown; records?: unknown };
    expect(deniedBody.error === 'AuthRequired').toBe(true);
    expect(Object.hasOwn(deniedBody, 'records')).toBe(false);
  });

  it('reports an unsupported single-record complexity without suggesting a smaller page', async () => {
    const f = await authorizedReadFixture();
    const [cid, bytes] = await encodeRecordBlock({ $type: COLLECTION, values: Array.from({ length: MAX_RECORD_CBOR_ITEMS }, () => null) });
    for (const name of ['space_record_fence_update', 'space_record_version_update_guard', 'space_version_fence_update']) {
      await f.env.ALTERAN_DB.prepare(`DROP TRIGGER ${name}`).run();
    }
    await f.env.ALTERAN_DB.prepare('UPDATE space_record SET value_cbor = ?, cid = ? WHERE space_ref = ? AND collection = ?')
      .bind(bytes, cid.toString(), SPACE, COLLECTION).run();
    await f.env.ALTERAN_DB.prepare(`UPDATE space_record_version SET value_cbor = ?, value_size = ?, cid = ?
      WHERE space_ref = ? AND collection = ? AND until_generation IS NULL`)
      .bind(bytes, bytes.byteLength, cid.toString(), SPACE, COLLECTION).run();
    const response = await request(f, { limit: '1' });
    expect(response.status).toBe(400);
    const body = await response.json() as { error: string; message: string };
    expect(body.error).toBe('InvalidRequest');
    expect(body.message).toContain('size or complexity');
  });

  it('round-trips an exactly 1 MiB record with worst-case JSON escaping', async () => {
    const f = await authorizedReadFixture();
    const nul = String.fromCharCode(0);
    const initialLength = MAX_RECORD_SIZE - 100;
    const [, trial] = await encodeRecordBlock({ $type: COLLECTION, text: nul.repeat(initialLength) });
    const text = nul.repeat(initialLength + MAX_RECORD_SIZE - trial.byteLength);
    const [cid, bytes] = await encodeRecordBlock({ $type: COLLECTION, text });
    expect(bytes.byteLength).toBe(MAX_RECORD_SIZE);

    for (const name of ['space_record_fence_update', 'space_record_version_update_guard', 'space_version_fence_update']) {
      await f.env.ALTERAN_DB.prepare(`DROP TRIGGER ${name}`).run();
    }
    await f.env.ALTERAN_DB.prepare('UPDATE space_record SET value_cbor = ?, cid = ? WHERE space_ref = ? AND collection = ? AND rkey = ?')
      .bind(bytes, cid.toString(), SPACE, COLLECTION, 'one').run();
    await f.env.ALTERAN_DB.prepare(`UPDATE space_record_version SET value_cbor = ?, value_size = ?, cid = ?
      WHERE space_ref = ? AND collection = ? AND rkey = ? AND until_generation IS NULL`)
      .bind(bytes, bytes.byteLength, cid.toString(), SPACE, COLLECTION, 'one').run();

    const response = await request(f, { limit: '1' });
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('private, no-store');
    const body = await response.text();
    expect(body.length).toBeGreaterThan(6_000_000);
    expect(body.length).toBeLessThan(16 * 1024 * 1024);
    const page = JSON.parse(body) as Page;
    expect(page.records.length).toBe(1);
    expect(page.records[0].rkey === 'one').toBe(true);
    expect(page.records[0].cid === cid.toString()).toBe(true);
    expect((page.records[0].value as { text?: unknown }).text === text).toBe(true);
  });
});
