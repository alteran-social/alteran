import { expect } from '@std/expect';
import { encode } from '@atproto/lex-cbor';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { authorizedReadFixture, interceptRead, COLLECTION, DID, OTHER_COLLECTION, SPACE } from './helpers/spaces-authorized-read';
import { signResourceDpop } from './helpers/oauth';
import { parseIntegerLex } from '../src/lib/spaces/record-integer-json';
import { MAX_INTEGER_PAGE_BYTES } from '../src/lib/spaces/record-integer-budget';
import { GET as getRecord } from '../src/pages/xrpc/com.atproto.space.getRecord';
import { GET as listRecords } from '../src/pages/xrpc/com.atproto.space.listRecords';

type Fixture = Awaited<ReturnType<typeof authorizedReadFixture>>;
type Environment = Fixture['env'];
const large = 9007199254740993n;
function block(collection: string, value: Record<string, unknown>) {
  const bytes = encode({ $type: collection, ...value } as never);
  return { bytes, cid: CID.createV1(0x71, createDigest(0x12, sha256(bytes))).toString() };
}
function sameBytes(a: Uint8Array, b: Uint8Array) {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}
async function allowEdits(f: Fixture) {
  for (const name of ['space_record_fence_update', 'space_record_version_update_guard', 'space_version_fence_update']) {
    await f.env.ALTERAN_DB.prepare(`DROP TRIGGER ${name}`).run();
  }
}
async function setRecord(f: Fixture, collection: string, rkey: string, value: Record<string, unknown>) {
  const input = block(collection, value);
  await f.env.ALTERAN_DB.prepare('UPDATE space_record SET cid = ?, value_cbor = ? WHERE space_ref = ? AND collection = ? AND rkey = ?')
    .bind(input.cid, input.bytes, SPACE, collection, rkey).run();
  await f.env.ALTERAN_DB.prepare(`UPDATE space_record_version SET cid = ?, value_cbor = ?, value_size = ?
    WHERE space_ref = ? AND collection = ? AND rkey = ? AND until_generation IS NULL`)
    .bind(input.cid, input.bytes, input.bytes.byteLength, SPACE, collection, rkey).run();
  return input;
}
async function request(f: Fixture, operation: 'getRecord' | 'listRecords', env: Environment = f.env,
  signal?: AbortSignal, params: Record<string, string> = {}) {
  const endpoint = `https://pds.example/xrpc/com.atproto.space.${operation}`;
  const fields = operation === 'getRecord' ? { space: SPACE, repo: DID, collection: COLLECTION, rkey: 'one', ...params }
    : { space: SPACE, repo: DID, ...params };
  const req = new Request(`${endpoint}?${new URLSearchParams(fields)}`, { headers: {
    authorization: `DPoP ${f.tokens.accessJwt}`,
    dpop: await signResourceDpop(env, f.key, 'GET', endpoint, f.tokens.accessJwt),
  }, signal });
  const context = { locals: { env }, request: req, url: new URL(req.url) } as never;
  return operation === 'getRecord' ? getRecord(context) : listRecords(context);
}

function waitForRevocation(database: D1Database, pending: () => Promise<unknown> | undefined): D1Database {
  return new Proxy(database, { get(target, key) {
    if (key === 'prepare') return (sql: string) => {
      const prepared = target.prepare(sql);
      if (!sql.includes('RETURNING seconds, nonce')) return prepared;
      return new Proxy(prepared, { get(statement, member) {
        if (member === 'bind') return (...values: unknown[]) => {
          const bound = Reflect.apply(statement.bind, statement, values) as D1PreparedStatement;
          return new Proxy(bound, { get(result, method) {
            if (method === 'first') return async (...args: unknown[]) => {
              await pending();
              return Reflect.apply(result.first, result, args);
            };
            const value = Reflect.get(result, method, result);
            return typeof value === 'function' ? value.bind(result) : value;
          } });
        };
        const value = Reflect.get(statement, member, statement);
        return typeof value === 'function' ? value.bind(statement) : value;
      } });
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
}

Deno.test('signed get and list return exact signed-64-bit literals and metadata', async () => {
  const f = await authorizedReadFixture();
  await allowEdits(f);
  const record = await setRecord(f, COLLECTION, 'one', { low: -9223372036854775808n, high: 9223372036854775807n,
    nested: [{ n: large }, { n: 0 }], bytes: new Uint8Array([0, 255]) });
  const get = await request(f, 'getRecord');
  expect(get.status).toBe(200);
  const text = await get.text();
  expect(text).toContain('9223372036854775807');
  expect(text).toContain('-9223372036854775808');
  const body = parseIntegerLex(text) as { value: unknown; cid: string };
  expect(body.cid).toBe(record.cid);
  expect(sameBytes(encode(body.value as never), record.bytes)).toBe(true);
  const list = await request(f, 'listRecords');
  expect(list.status).toBe(200);
  const listed = parseIntegerLex(await list.text()) as { records: { collection: string; cid: string; value: unknown }[] };
  const found = listed.records.find((item) => item.collection === COLLECTION);
  if (!found) throw new Error('Missing list entry');
  expect(found.cid).toBe(record.cid);
  expect(sameBytes(encode(found.value as never), record.bytes)).toBe(true);
  const metadata = await request(f, 'listRecords', f.env, undefined, { excludeValues: 'true' });
  expect(metadata.status).toBe(200);
  const meta = await metadata.json() as { records: Record<string, unknown>[] };
  expect(meta.records.every((item) => !Object.hasOwn(item, 'value'))).toBe(true);
});

Deno.test('bigint-bearing get and list size errors remain behind final authorization', async () => {
  for (const operation of ['getRecord', 'listRecords'] as const) {
    for (const mode of ['allow', 'revoke', 'cancel'] as const) {
      const f = await authorizedReadFixture();
      await allowEdits(f);
      await setRecord(f, COLLECTION, 'one', { n: large, text: '\0'.repeat(MAX_INTEGER_PAGE_BYTES) });
      const controller = new AbortController();
      const watched = interceptRead(f.env, { after: async () => {
        if (mode === 'revoke') await f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
          .bind(f.sessionId).run();
        if (mode === 'cancel') controller.abort();
      } });
      watched.arm();
      const response = await request(f, operation, watched.env, controller.signal);
      expect(response.status).toBe(mode === 'allow' ? 400 : 401);
      const text = await response.text();
      expect(text).not.toContain(large.toString());
      expect(text).not.toContain('records');
    }
  }
});

Deno.test('revocation and cancellation during bigint serialization withhold the response', async () => {
  for (const operation of ['getRecord', 'listRecords'] as const) {
    for (const mode of ['revoke', 'cancel'] as const) {
      const f = await authorizedReadFixture();
      await allowEdits(f);
      await setRecord(f, COLLECTION, 'one', { n: large });
      const controller = new AbortController();
      const rawDescriptor = Object.getOwnPropertyDescriptor(JSON, 'rawJSON');
      if (!rawDescriptor || typeof rawDescriptor.value !== 'function') throw new Error('Missing raw JSON feature');
      const originalRaw = rawDescriptor.value as (value: string) => unknown;
      let fired = false;
      let revocation: Promise<unknown> | undefined;
      const watched = interceptRead(f.env, { after: () => {
        Object.defineProperty(JSON, 'rawJSON', { ...rawDescriptor, value: (source: string) => {
          if (!fired) {
            fired = true;
            if (mode === 'cancel') controller.abort();
            else revocation = f.env.ALTERAN_DB.prepare('UPDATE oauth_session SET revoked_at = unixepoch() WHERE id = ?')
              .bind(f.sessionId).run();
          }
          return originalRaw(source);
        } });
      } });
      const env = { ...watched.env, ALTERAN_DB: waitForRevocation(watched.env.ALTERAN_DB, () => revocation) };
      watched.arm();
      try {
        const response = await request(f, operation, env, controller.signal);
        expect(fired).toBe(true);
        expect(response.status).toBe(401);
        expect(await response.text()).not.toContain(large.toString());
      } finally {
        Object.defineProperty(JSON, 'rawJSON', rawDescriptor);
        await revocation;
      }
    }
  }
});

Deno.test('the bigint envelope is aggregate across value pages, not individual records', async () => {
  const f = await authorizedReadFixture();
  await allowEdits(f);
  const first = await setRecord(f, COLLECTION, 'one', { n: large, text: 'x'.repeat(33_000) });
  const second = await setRecord(f, OTHER_COLLECTION, 'two', { text: 'y'.repeat(33_000) });
  expect(first.bytes.byteLength).toBeLessThan(MAX_INTEGER_PAGE_BYTES);
  expect(second.bytes.byteLength).toBeLessThan(MAX_INTEGER_PAGE_BYTES);
  expect(first.bytes.byteLength + second.bytes.byteLength).toBeGreaterThan(MAX_INTEGER_PAGE_BYTES);
  const get = await request(f, 'getRecord');
  expect(get.status).toBe(200);
  const list = await request(f, 'listRecords');
  expect(list.status).toBe(400);
  expect(await list.text()).not.toContain(large.toString());
  const onePage = await request(f, 'listRecords', f.env, undefined, { collection: COLLECTION });
  expect(onePage.status).toBe(200);
  const metadata = await request(f, 'listRecords', f.env, undefined, { excludeValues: 'true' });
  expect(metadata.status).toBe(200);
});

Deno.test('the bigint item and integer-count limits are aggregate across records', async () => {
  const f = await authorizedReadFixture();
  await allowEdits(f);
  await setRecord(f, COLLECTION, 'one', { values: Array(32).fill(large) });
  await setRecord(f, OTHER_COLLECTION, 'two', { values: Array(32).fill(large) });
  expect((await request(f, 'listRecords')).status).toBe(200);
  await setRecord(f, OTHER_COLLECTION, 'two', { values: Array(33).fill(large) });
  expect((await request(f, 'listRecords')).status).toBe(400);
  expect((await request(f, 'getRecord')).status).toBe(200);
  await setRecord(f, COLLECTION, 'one', { n: large, values: Array(2_000).fill(0) });
  await setRecord(f, OTHER_COLLECTION, 'two', { values: Array(2_000).fill(0) });
  expect((await request(f, 'listRecords')).status).toBe(200);
  await setRecord(f, OTHER_COLLECTION, 'two', { values: Array(2_100).fill(0) });
  expect((await request(f, 'listRecords')).status).toBe(400);
  expect((await request(f, 'listRecords', f.env, undefined, { excludeValues: 'true' })).status).toBe(200);
});

Deno.test('a single bigint alongside a large safe-integer array is rejected before serialization', async () => {
  const f = await authorizedReadFixture();
  await allowEdits(f);
  const input = await setRecord(f, COLLECTION, 'one', { n: large, values: Array(131_000).fill(0) });
  expect(input.bytes.byteLength).toBeGreaterThan(MAX_INTEGER_PAGE_BYTES);
  let used = false;
  const descriptor = Object.getOwnPropertyDescriptor(JSON, 'rawJSON');
  if (!descriptor) throw new Error('Missing raw JSON feature');
  try {
    Object.defineProperty(JSON, 'rawJSON', { configurable: true, get() { used = true; throw new Error('Unexpected conversion'); } });
    expect((await request(f, 'getRecord')).status).toBe(400);
    expect((await request(f, 'listRecords')).status).toBe(400);
    expect(used).toBe(false);
  } finally {
    Object.defineProperty(JSON, 'rawJSON', descriptor);
  }
});
