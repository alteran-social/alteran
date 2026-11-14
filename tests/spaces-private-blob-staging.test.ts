import { expect } from '@std/expect';
import type { D1Database, R2Bucket, R2Object } from '@cloudflare/workers-types';
import { sha256 } from '@noble/hashes/sha2.js';
import { CID } from 'multiformats/cid';
import { create as createDigest } from 'multiformats/hashes/digest';
import { afterEach, describe, it } from './helpers/bdd';
import { disposePrivateBlobEnv, makePrivateBlobEnv, type PrivateBlobTestEnv } from './helpers/private-blob-env';
import {
  getPrivateBlobStatus, preparePrivateBlobReservation, reservePrivateBlob, stagePrivateBlob,
  PRIVATE_BLOB_MAX_BYTES, PRIVATE_BLOB_MAX_GLOBAL_RESERVATIONS, PRIVATE_BLOB_MAX_RESERVATIONS,
  type PrivateBlobReservation,
} from '../src/lib/spaces/private-blob-staging';

const DID = 'did:example:test';
type TestEnv = PrivateBlobTestEnv;

async function setup() {
  const env = await makePrivateBlobEnv();
  const incarnation = await addOwner(env, DID, 'test.example');
  return { env, incarnation };
}
async function addOwner(env: TestEnv, did: string, handle: string) {
  await env.ALTERAN_DB.prepare('INSERT INTO account (did, handle, created_at, updated_at) VALUES (?, ?, 1, 1)').bind(did, handle).run();
  await env.ALTERAN_DB.prepare('INSERT INTO account_state (did, active, created_at) VALUES (?, 1, 1)').bind(did).run();
  const account = await env.ALTERAN_DB.prepare('SELECT space_incarnation FROM account WHERE did = ?').bind(did).first<{ space_incarnation: string }>();
  if (!account) throw new Error('Missing test account');
  return account.space_incarnation;
}
function handle(did: string, incarnation: string) {
  const value = preparePrivateBlobReservation(did, incarnation);
  if (!value) throw new Error('Invalid test owner');
  return value;
}
async function reservation(env: TestEnv, did: string, incarnation: string) {
  const value = handle(did, incarnation);
  expect((await reservePrivateBlob(env.ALTERAN_DB, value)).tag).toBe('reserved');
  return value;
}
async function row(env: TestEnv, value: PrivateBlobReservation) {
  return await env.ALTERAN_DB.prepare(`SELECT state, object_key, reserved_bytes, cid, digest, size, mime_type, r2_version, etag
    FROM private_blob_staging WHERE id = ?`).bind(value.id).first<{
      state: string; object_key: string; reserved_bytes: number; cid: string | null; digest: string | null;
      size: number | null; mime_type: string | null; r2_version: string | null; etag: string | null;
    }>();
}
async function count(env: TestEnv, table: string) {
  return (await env.ALTERAN_DB.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>())?.n;
}
async function rejected(operation: () => Promise<unknown>) {
  let failed = false;
  try { await operation(); } catch { failed = true; }
  expect(failed).toBe(true);
}
function lostBatch(database: D1Database, lostIndex: number): D1Database {
  let calls = 0;
  return new Proxy(database, { get(target, key) {
    if (key === 'batch') return async (...args: Parameters<D1Database['batch']>) => {
      const result = await target.batch(...args);
      if (++calls === lostIndex) throw new Error('response lost');
      return result;
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
}
function captureStatus(database: D1Database) {
  let transferred = 0;
  const wrapped = new Proxy(database, { get(target, key) {
    if (key === 'prepare') return (sql: string) => new Proxy(target.prepare(sql), { get(prepared, method) {
      if (method === 'bind') return (...values: unknown[]) => new Proxy(prepared.bind(...values), { get(query, operation) {
        if (operation === 'first') return async () => {
          const result = await query.first();
          transferred = JSON.stringify(result).length;
          return result;
        };
        const value = Reflect.get(query, operation, query);
        return typeof value === 'function' ? value.bind(query) : value;
      } });
      const value = Reflect.get(prepared, method, prepared);
      return typeof value === 'function' ? value.bind(prepared) : value;
    } });
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  return { database: wrapped, transferred: () => transferred };
}
function putProxy(bucket: R2Bucket, operation: (key: string, body: Uint8Array, options: Parameters<R2Bucket['put']>[2]) => Promise<R2Object | null>): R2Bucket {
  return { put: operation } as unknown as R2Bucket;
}

describe('durable private blob staging', () => {
  afterEach(disposePrivateBlobEnv);
  it('stages an immutable checksum-verified object without creating public or Space associations', async () => {
    const { env, incarnation } = await setup();
    const value = await reservation(env, DID, incarnation);
    const bytes = new TextEncoder().encode('private content');
    const expected = CID.createV1(0x55, createDigest(0x12, sha256(bytes))).toString();
    const pending = stagePrivateBlob(env.ALTERAN_DB, env.ALTERAN_BLOBS, value, bytes, 'text/plain');
    bytes.fill(0);
    expect(await pending).toEqual({ tag: 'staged', cid: expected, size: 15, mimeType: 'text/plain' });
    const stored = await row(env, value);
    expect(stored?.state).toBe('ready');
    expect(stored?.reserved_bytes).toBe(PRIVATE_BLOB_MAX_BYTES);
    expect(stored?.cid).toBe(expected);
    expect(stored?.r2_version).toBeTruthy();
    expect(stored?.etag).toBeTruthy();
    expect(await (await env.ALTERAN_BLOBS.get(stored!.object_key))?.text()).toBe('private content');
    for (const table of ['blob', 'blob_usage', 'space_blob_usage', 'space_record']) expect(await count(env, table)).toBe(0);
    expect((await env.ALTERAN_BLOBS.list({ prefix: 'blobs/by-cid/' })).objects).toHaveLength(0);
    expect((await env.PUBLIC_BLOBS.list()).objects).toHaveLength(0);
    expect(await getPrivateBlobStatus(env.ALTERAN_DB, value)).toEqual({ tag: 'staged', cid: expected, size: 15, mimeType: 'text/plain' });
  });

  it('recovers reservation response loss and serializes duplicate reservation attempts', async () => {
    const { env, incarnation } = await setup();
    const value = handle(DID, incarnation);
    expect((await reservePrivateBlob(lostBatch(env.ALTERAN_DB, 1), value)).tag).toBe('reserved');
    const repeated = await Promise.all(Array.from({ length: 8 }, () => reservePrivateBlob(env.ALTERAN_DB, value)));
    expect(repeated.every((result) => result.tag === 'reserved')).toBe(true);
    expect(await count(env, 'private_blob_staging')).toBe(1);
    const forged = { ...value, token: 'a'.repeat(32) };
    expect((await reservePrivateBlob(env.ALTERAN_DB, forged)).tag).toBe('invalid');
    expect((await getPrivateBlobStatus(env.ALTERAN_DB, forged)).tag).toBe('invalid');
  });

  it('allows only one upload claim and recovers a lost ready response', async () => {
    const { env, incarnation } = await setup();
    const value = await reservation(env, DID, incarnation);
    let puts = 0;
    const bucket = putProxy(env.ALTERAN_BLOBS, async (key, body, options) => { puts++; return await env.ALTERAN_BLOBS.put(key, body, options); });
    const results = await Promise.all([
      stagePrivateBlob(lostBatch(env.ALTERAN_DB, 2), bucket, value, new Uint8Array([1]), 'text/plain'),
      stagePrivateBlob(env.ALTERAN_DB, bucket, value, new Uint8Array([2]), 'text/plain'),
    ]);
    expect(puts).toBe(1);
    expect(results.filter((result) => result.tag === 'staged')).toHaveLength(1);
    const stored = await row(env, value);
    expect(stored?.state).toBe('ready');
    const status = await getPrivateBlobStatus(env.ALTERAN_DB, value);
    expect(status.tag).toBe('staged');
    const repeated = await stagePrivateBlob(env.ALTERAN_DB, bucket, value, new Uint8Array([stored!.size === 1 && stored!.cid === CID.createV1(0x55, createDigest(0x12, sha256(new Uint8Array([1])))).toString() ? 1 : 2]), 'text/plain');
    expect(repeated.tag).toBe('staged');
    expect(puts).toBe(1);
  });

  it('recovers the exact ready receipt after its D1 response is lost', async () => {
    const { env, incarnation } = await setup();
    const value = await reservation(env, DID, incarnation);
    let puts = 0;
    const bucket = putProxy(env.ALTERAN_BLOBS, async (key, body, options) => { puts++; return await env.ALTERAN_BLOBS.put(key, body, options); });
    const bytes = new Uint8Array([11, 12]);
    const first = await stagePrivateBlob(lostBatch(env.ALTERAN_DB, 2), bucket, value, bytes, 'text/plain');
    expect(first.tag).toBe('staged');
    expect(await getPrivateBlobStatus(env.ALTERAN_DB, value)).toEqual(first);
    expect(await stagePrivateBlob(env.ALTERAN_DB, bucket, value, bytes, 'text/plain')).toEqual(first);
    expect(puts).toBe(1);
  });

  it('retains a claim when its D1 response is lost before any PUT', async () => {
    const { env, incarnation } = await setup();
    const value = await reservation(env, DID, incarnation);
    let puts = 0;
    const bucket = putProxy(env.ALTERAN_BLOBS, async (key, body, options) => { puts++; return await env.ALTERAN_BLOBS.put(key, body, options); });
    expect((await stagePrivateBlob(lostBatch(env.ALTERAN_DB, 1), bucket, value, new Uint8Array([1]), 'text/plain')).tag).toBe('uncertain');
    expect(puts).toBe(0);
    expect((await getPrivateBlobStatus(env.ALTERAN_DB, value)).tag).toBe('putting');
    expect((await stagePrivateBlob(env.ALTERAN_DB, bucket, value, new Uint8Array([1]), 'text/plain')).tag).toBe('uncertain');
    expect(puts).toBe(0);
    expect((await row(env, value))?.reserved_bytes).toBe(PRIVATE_BLOB_MAX_BYTES);
  });

  it('keeps an ambiguous PUT charged when it commits after a negative read', async () => {
    const { env, incarnation } = await setup();
    const value = await reservation(env, DID, incarnation);
    let release!: () => void;
    const wait = new Promise<void>((resolve) => { release = resolve; });
    let late: Promise<R2Object | null> | undefined;
    let puts = 0;
    const bucket = putProxy(env.ALTERAN_BLOBS, async (key, body, options) => {
      puts++;
      late = wait.then(() => env.ALTERAN_BLOBS.put(key, body, options));
      throw new Error('response lost before PUT settled');
    });
    expect((await stagePrivateBlob(env.ALTERAN_DB, bucket, value, new Uint8Array([3]), 'text/plain')).tag).toBe('uncertain');
    const stored = await row(env, value);
    expect(await env.ALTERAN_BLOBS.head(stored!.object_key)).toBeNull();
    await rejected(() => env.ALTERAN_DB.prepare('DELETE FROM private_blob_staging WHERE id = ?').bind(value.id).run());
    release();
    expect(await late).toBeTruthy();
    expect(await env.ALTERAN_BLOBS.head(stored!.object_key)).toBeTruthy();
    expect((await getPrivateBlobStatus(env.ALTERAN_DB, value)).tag).toBe('uncertain');
    expect((await stagePrivateBlob(env.ALTERAN_DB, bucket, value, new Uint8Array([3]), 'text/plain')).tag).toBe('uncertain');
    expect(puts).toBe(1);
  });

  it('never returns an old-incarnation receipt after replacement during PUT', async () => {
    const { env, incarnation } = await setup();
    const value = await reservation(env, DID, incarnation);
    let reached!: () => void, release!: () => void;
    const started = new Promise<void>((resolve) => { reached = resolve; });
    const wait = new Promise<void>((resolve) => { release = resolve; });
    const bucket = putProxy(env.ALTERAN_BLOBS, async (key, body, options) => {
      const object = await env.ALTERAN_BLOBS.put(key, body, options);
      reached(); await wait; return object;
    });
    const pending = stagePrivateBlob(env.ALTERAN_DB, bucket, value, new Uint8Array([7]), 'text/plain');
    await started;
    await env.ALTERAN_DB.prepare('DELETE FROM account WHERE did = ?').bind(DID).run();
    await env.ALTERAN_DB.prepare('INSERT INTO account (did,handle,created_at,updated_at) VALUES (?, ?, 1, 1)').bind(DID, 'test.example').run();
    const replacement = await env.ALTERAN_DB.prepare('SELECT space_incarnation FROM account WHERE did = ?').bind(DID).first<{ space_incarnation: string }>();
    expect(replacement?.space_incarnation).not.toBe(incarnation);
    release();
    expect((await pending).tag).toBe('invalid');
    expect((await row(env, value))?.state).toBe('ready');
    expect((await getPrivateBlobStatus(env.ALTERAN_DB, value)).tag).toBe('invalid');
    expect((await getPrivateBlobStatus(env.ALTERAN_DB, { ...value, accountIncarnation: replacement!.space_incarnation })).tag).toBe('invalid');
  });

  it('rejects bad R2 metadata, skipped transitions, and object-key collisions without refunds', async () => {
    const { env, incarnation } = await setup();
    for (const mismatch of ['size', 'checksum', 'version', 'etag', 'key']) {
      const value = await reservation(env, DID, incarnation);
      const bucket = putProxy(env.ALTERAN_BLOBS, async (key, body, options) => {
        const object = await env.ALTERAN_BLOBS.put(key, body, options);
        if (!object) throw new Error('Missing object');
        return { key: mismatch === 'key' ? 'other' : object.key, size: mismatch === 'size' ? object.size + 1 : object.size,
          version: mismatch === 'version' ? 'x'.repeat(513) : object.version, etag: mismatch === 'etag' ? '' : object.etag,
          checksums: mismatch === 'checksum' ? { sha256: new Uint8Array(32).buffer } : object.checksums } as R2Object;
      });
      expect((await stagePrivateBlob(env.ALTERAN_DB, bucket, value, new Uint8Array([9]), 'text/plain')).tag).toBe('uncertain');
      expect((await row(env, value))?.reserved_bytes).toBe(PRIVATE_BLOB_MAX_BYTES);
      expect((await row(env, value))?.state).toBe('uncertain');
    }
    const skipped = await reservation(env, DID, incarnation);
    await env.ALTERAN_DB.exec("CREATE TRIGGER skip_ready BEFORE UPDATE ON private_blob_staging WHEN NEW.state = 'ready' BEGIN SELECT RAISE(IGNORE); END");
    expect((await stagePrivateBlob(env.ALTERAN_DB, env.ALTERAN_BLOBS, skipped, new Uint8Array([8]), 'text/plain')).tag).toBe('uncertain');
    expect((await row(env, skipped))?.state).toBe('putting');
    await env.ALTERAN_DB.exec('DROP TRIGGER skip_ready');
    const collision = await reservation(env, DID, incarnation);
    const collisionRow = await row(env, collision);
    await env.ALTERAN_BLOBS.put(collisionRow!.object_key, 'existing');
    expect((await stagePrivateBlob(env.ALTERAN_DB, env.ALTERAN_BLOBS, collision, new Uint8Array([4]), 'text/plain')).tag).toBe('uncertain');
    expect(await (await env.ALTERAN_BLOBS.get(collisionRow!.object_key))?.text()).toBe('existing');
  });

  it('does not trust an R2 adapter that mutates both bytes and supplied checksum', async () => {
    const { env, incarnation } = await setup();
    const value = await reservation(env, DID, incarnation);
    const bucket = putProxy(env.ALTERAN_BLOBS, async (key, body, options) => {
      body.fill(0);
      const checksum = (options as { sha256?: unknown } | undefined)?.sha256;
      if (!(checksum instanceof Uint8Array)) throw new Error('Missing checksum');
      checksum.set(sha256(body));
      return await env.ALTERAN_BLOBS.put(key, body, options);
    });
    expect((await stagePrivateBlob(env.ALTERAN_DB, bucket, value, new Uint8Array([1, 2]), 'text/plain')).tag).toBe('uncertain');
    expect((await row(env, value))?.state).toBe('uncertain');
    expect((await row(env, value))?.reserved_bytes).toBe(PRIVATE_BLOB_MAX_BYTES);
  });

  it('captures R2 version and etag once before recording a receipt', async () => {
    const { env, incarnation } = await setup();
    const value = await reservation(env, DID, incarnation);
    let versionReads = 0, etagReads = 0, version = '', etag = '';
    const bucket = putProxy(env.ALTERAN_BLOBS, async (key, body, options) => {
      const object = await env.ALTERAN_BLOBS.put(key, body, options);
      if (!object) throw new Error('Missing object');
      version = object.version; etag = object.etag;
      return { key: object.key, size: object.size, checksums: object.checksums,
        get version() { return ++versionReads === 1 ? version : 'changed'; },
        get etag() { return ++etagReads === 1 ? etag : 'changed'; },
      } as R2Object;
    });
    expect((await stagePrivateBlob(env.ALTERAN_DB, bucket, value, new Uint8Array([9]), 'text/plain')).tag).toBe('staged');
    const stored = await row(env, value);
    expect(versionReads).toBe(1);
    expect(etagReads).toBe(1);
    expect(stored?.r2_version).toBe(version);
    expect(stored?.etag).toBe(etag);
  });

  it('rolls back skipped or rewritten ledger transitions and rejects replacement or deletion', async () => {
    const { env, incarnation } = await setup();
    const skippedInsert = handle(DID, incarnation);
    await env.ALTERAN_DB.exec('CREATE TRIGGER skip_reservation BEFORE INSERT ON private_blob_staging BEGIN SELECT RAISE(IGNORE); END');
    expect((await reservePrivateBlob(env.ALTERAN_DB, skippedInsert)).tag).toBe('unavailable');
    expect(await count(env, 'private_blob_staging')).toBe(0);
    await env.ALTERAN_DB.exec('DROP TRIGGER skip_reservation');
    const value = await reservation(env, DID, incarnation);
    const key = `space-staging/${value.id}`;
    await rejected(() => env.ALTERAN_DB.prepare(`INSERT OR REPLACE INTO private_blob_staging
      (id, token, repo_did, account_incarnation, object_key, state, reserved_bytes)
      VALUES (?, ?, ?, ?, ?, 'reserved', 5242880)`)
      .bind(value.id, value.token, value.repoDid, value.accountIncarnation, key).run());
    for (const sql of ["UPDATE private_blob_staging SET token = 'bad'", "UPDATE private_blob_staging SET state = 'ready'",
      'UPDATE private_blob_staging SET claim_nonce = NULL', 'DELETE FROM private_blob_staging']) {
      await rejected(() => env.ALTERAN_DB.prepare(`${sql} WHERE id = ?`).bind(value.id).run());
    }
    await env.ALTERAN_DB.exec("CREATE TRIGGER skip_claim BEFORE UPDATE ON private_blob_staging WHEN NEW.state = 'putting' BEGIN SELECT RAISE(IGNORE); END");
    expect((await stagePrivateBlob(env.ALTERAN_DB, env.ALTERAN_BLOBS, value, new Uint8Array([1]), 'text/plain')).tag).toBe('unavailable');
    expect((await row(env, value))?.state).toBe('reserved');
    expect(await env.ALTERAN_BLOBS.head(key)).toBeNull();
    await env.ALTERAN_DB.exec('DROP TRIGGER skip_claim');
    await env.ALTERAN_DB.exec("CREATE TRIGGER rewrite_ready AFTER UPDATE ON private_blob_staging WHEN NEW.state = 'ready' BEGIN UPDATE private_blob_staging SET etag = 'forged' WHERE id = NEW.id; END");
    expect((await stagePrivateBlob(env.ALTERAN_DB, env.ALTERAN_BLOBS, value, new Uint8Array([1]), 'text/plain')).tag).toBe('uncertain');
    expect((await row(env, value))?.state).toBe('putting');
    expect((await row(env, value))?.etag).toBeNull();
    expect(await env.ALTERAN_BLOBS.head(key)).toBeTruthy();
  });

  it('fails closed when a stored receipt is malformed or its owner is inactive', async () => {
    const { env, incarnation } = await setup();
    const value = await reservation(env, DID, incarnation);
    expect((await stagePrivateBlob(env.ALTERAN_DB, env.ALTERAN_BLOBS, value, new Uint8Array([1]), 'text/plain')).tag).toBe('staged');
    await env.ALTERAN_DB.prepare('UPDATE account_state SET active = 0 WHERE did = ?').bind(DID).run();
    expect((await getPrivateBlobStatus(env.ALTERAN_DB, value)).tag).toBe('invalid');
    await env.ALTERAN_DB.prepare('UPDATE account_state SET active = 1 WHERE did = ?').bind(DID).run();
    await env.ALTERAN_DB.exec('DROP TRIGGER private_blob_staging_update');
    await env.ALTERAN_DB.prepare('UPDATE private_blob_staging SET digest = ? WHERE id = ?').bind('a'.repeat(64) + '\0' + 'z'.repeat(400_000), value.id).run();
    const observed = captureStatus(env.ALTERAN_DB);
    expect((await getPrivateBlobStatus(observed.database, value)).tag).toBe('unavailable');
    expect(observed.transferred()).toBeLessThan(1_000);
  });

  it('rejects shared, detached, oversized and malformed input without consuming a reservation', async () => {
    const { env, incarnation } = await setup();
    const value = await reservation(env, DID, incarnation);
    const detached = new Uint8Array([1]); structuredClone(detached.buffer, { transfer: [detached.buffer] });
    const invalid: Uint8Array[] = [detached, new Uint8Array(PRIVATE_BLOB_MAX_BYTES + 1)];
    if (typeof SharedArrayBuffer !== 'undefined') invalid.push(new Uint8Array(new SharedArrayBuffer(1)));
    for (const bytes of invalid) expect((await stagePrivateBlob(env.ALTERAN_DB, env.ALTERAN_BLOBS, value, bytes, 'text/plain')).tag).toBe('invalid');
    expect((await stagePrivateBlob(env.ALTERAN_DB, env.ALTERAN_BLOBS, value, new Uint8Array(), 'text/*')).tag).toBe('invalid');
    expect((await stagePrivateBlob(env.ALTERAN_DB, env.ALTERAN_BLOBS, value, new Uint8Array(), 'text/plain\n')).tag).toBe('invalid');
    expect(preparePrivateBlobReservation(`${DID}\n`, incarnation)).toBeNull();
    expect(preparePrivateBlobReservation(DID, `${incarnation.slice(0, 31)}\n`)).toBeNull();
    expect((await reservePrivateBlob(env.ALTERAN_DB, { ...value, id: `${value.id.slice(0, 31)}\n` })).tag).toBe('invalid');
    expect((await stagePrivateBlob(env.ALTERAN_DB, env.ALTERAN_BLOBS, { ...value, repoDid: 'did:example:other' }, new Uint8Array(), 'text/plain')).tag).toBe('invalid');
    expect((await row(env, value))?.state).toBe('reserved');
  });

  it('enforces per-DID and global permanent capacity even for direct inserts and account recreation', async () => {
    const { env, incarnation } = await setup();
    const owners = [{ did: DID, incarnation }];
    for (let index = 1; index < 4; index++) {
      const did = `did:example:owner${index}`;
      owners.push({ did, incarnation: await addOwner(env, did, `owner${index}.example`) });
    }
    for (let owner = 0; owner < owners.length; owner++) {
      const start = owner * PRIVATE_BLOB_MAX_RESERVATIONS;
      await env.ALTERAN_DB.prepare(`WITH RECURSIVE numbers(n) AS (SELECT ? UNION ALL SELECT n + 1 FROM numbers WHERE n < ?)
        INSERT INTO private_blob_staging (id, token, repo_did, account_incarnation, object_key, state, reserved_bytes)
        SELECT printf('%032x', n), printf('%032x', n + 1000), ?, ?, 'space-staging/' || printf('%032x', n), 'reserved', 5242880 FROM numbers`)
        .bind(start, start + PRIVATE_BLOB_MAX_RESERVATIONS - 1, owners[owner].did, owners[owner].incarnation).run();
    }
    expect(await count(env, 'private_blob_staging')).toBe(PRIVATE_BLOB_MAX_GLOBAL_RESERVATIONS);
    const full = handle(DID, incarnation);
    expect((await reservePrivateBlob(env.ALTERAN_DB, full)).tag).toBe('quota-exceeded');
    await rejected(() => env.ALTERAN_DB.prepare(`INSERT INTO private_blob_staging (id,token,repo_did,account_incarnation,object_key,state,reserved_bytes)
      VALUES (?, ?, ?, ?, ?, 'reserved', 5242880)`).bind(full.id, full.token, full.repoDid, full.accountIncarnation, `space-staging/${full.id}`).run());
    await env.ALTERAN_DB.prepare('DELETE FROM account WHERE did = ?').bind(DID).run();
    await env.ALTERAN_DB.prepare('INSERT INTO account (did,handle,created_at,updated_at) VALUES (?, ?, 1, 1)').bind(DID, 'test.example').run();
    const newIncarnation = (await env.ALTERAN_DB.prepare('SELECT space_incarnation FROM account WHERE did = ?').bind(DID).first<{space_incarnation: string}>())!.space_incarnation;
    expect((await reservePrivateBlob(env.ALTERAN_DB, handle(DID, newIncarnation))).tag).toBe('quota-exceeded');
    const freshDid = 'did:example:fresh', fresh = await addOwner(env, freshDid, 'fresh.example');
    expect((await reservePrivateBlob(env.ALTERAN_DB, handle(freshDid, fresh))).tag).toBe('quota-exceeded');
    const plan = await env.ALTERAN_DB.prepare('EXPLAIN QUERY PLAN SELECT 1 FROM private_blob_staging INDEXED BY private_blob_staging_owner WHERE repo_did = ? LIMIT 1 OFFSET 63').bind(DID).all<{detail: string}>();
    expect(plan.results.some((entry: { detail: string }) => entry.detail.includes('private_blob_staging_owner'))).toBe(true);
  });

  it('serializes concurrent reservations at both quota boundaries', async () => {
    const { env, incarnation } = await setup();
    await env.ALTERAN_DB.prepare(`WITH RECURSIVE numbers(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM numbers WHERE n < 62)
      INSERT INTO private_blob_staging (id,token,repo_did,account_incarnation,object_key,state,reserved_bytes)
      SELECT printf('%032x', n), printf('%032x', n + 1000), ?, ?, 'space-staging/' || printf('%032x', n), 'reserved', 5242880 FROM numbers`)
      .bind(DID, incarnation).run();
    const ownerRace = await Promise.all([reservePrivateBlob(env.ALTERAN_DB, handle(DID, incarnation)), reservePrivateBlob(env.ALTERAN_DB, handle(DID, incarnation))]);
    expect(ownerRace.map((item) => item.tag).sort()).toEqual(['quota-exceeded', 'reserved']);
    for (let index = 1; index <= 3; index++) {
      const did = `did:example:extra${index}`, account = await addOwner(env, did, `extra${index}.example`);
      const start = index * PRIVATE_BLOB_MAX_RESERVATIONS;
      const amount = index === 3 ? PRIVATE_BLOB_MAX_RESERVATIONS - 1 : PRIVATE_BLOB_MAX_RESERVATIONS;
      await env.ALTERAN_DB.prepare(`WITH RECURSIVE numbers(n) AS (SELECT ? UNION ALL SELECT n + 1 FROM numbers WHERE n < ?)
        INSERT INTO private_blob_staging (id,token,repo_did,account_incarnation,object_key,state,reserved_bytes)
        SELECT printf('%032x', n), printf('%032x', n + 1000), ?, ?, 'space-staging/' || printf('%032x', n), 'reserved', 5242880 FROM numbers`)
        .bind(start, start + amount - 1, did, account).run();
    }
    expect(await count(env, 'private_blob_staging')).toBe(PRIVATE_BLOB_MAX_GLOBAL_RESERVATIONS - 1);
    const did = 'did:example:newowner', account = await addOwner(env, did, 'newowner.example');
    const globalRace = await Promise.all([reservePrivateBlob(env.ALTERAN_DB, handle(did, account)), reservePrivateBlob(env.ALTERAN_DB, handle(did, account))]);
    expect(globalRace.map((item) => item.tag).sort()).toEqual(['quota-exceeded', 'reserved']);
    expect(await count(env, 'private_blob_staging')).toBe(PRIVATE_BLOB_MAX_GLOBAL_RESERVATIONS);
  });
});
