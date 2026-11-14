import { describe, it } from './helpers/bdd';
import { expect } from '@std/expect';
import * as dagCbor from '@ipld/dag-cbor';
import { readRepoStar } from '@atproto/space';
import { makeEnv } from './helpers/env';
import { applySpaceWrites, createLocalSpace } from '../src/db/space-store';
import { pruneSpaceRecordVersionsPage } from '../src/db/space-version-gc';
import { readSpaceRepoArchive } from '../src/lib/spaces/repo-archive';
import { streamSpaceRepoArchive } from '../src/services/space-repo-export';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';

const DID = 'did:example:test';
const COLLECTION = 'com.example.note';
const SPACE = `at://${DID}/space/com.example.notes/export`;
type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

async function fixture() {
  const env = await makeEnv();
  await createLocalSpace(env, SPACE);
  await applySpaceWrites(env, SPACE, DID, [create('a', 'old')]);
  return env;
}

function create(rkey: string, text: string) {
  return { action: 'create' as const, collection: COLLECTION, rkey, record: { $type: COLLECTION, text } };
}

async function leaseCount(env: TestEnv): Promise<number> {
  const row = await env.ALTERAN_DB.prepare('SELECT COUNT(*) AS count FROM space_snapshot_lease').first<{ count: number }>();
  return row?.count ?? -1;
}

async function readArchive(body: ReadableStream<Uint8Array>) {
  const bytes = new Uint8Array(await new Response(body).arrayBuffer());
  return readSpaceRepoArchive(bytes, { space: SPACE, repo: DID });
}

describe('streamed Space repo export', () => {
  it('does not fetch pages before the first pull and releases an unstarted stream', async () => {
    const env = await fixture();
    let batches = 0;
    const database = env.ALTERAN_DB;
    const watched = new Proxy(database, {
      get(target, property) {
        if (property === 'batch') return (statements: Parameters<typeof database.batch>[0]) => {
          batches++;
          return database.batch(statements);
        };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const opened = await streamSpaceRepoArchive({ ...env, ALTERAN_DB: watched }, SPACE, DID);
    const acquisitionBatches = batches;
    await Promise.resolve();
    expect(batches).toBe(acquisitionBatches);
    expect(await leaseCount(env)).toBe(1);
    await opened.body.cancel();
    expect(await leaseCount(env)).toBe(0);
    expect(batches).toBe(acquisitionBatches);
  });

  it('copies shared SDK chunks and the returned commit bytes', async () => {
    const env = await fixture();
    const first = await streamSpaceRepoArchive(env, SPACE, DID);
    const firstReader = first.body.getReader();
    const magic = await firstReader.read();
    expect(magic.value?.[0]).toBe(42);
    if (!magic.value) throw new Error('Missing STAR magic');
    magic.value[0] = 0;
    await firstReader.cancel();
    const second = await streamSpaceRepoArchive(env, SPACE, DID);
    const originalDigest = Uint8Array.from(second.commit.data);
    second.commit.data.fill(0);
    const archive = await readArchive(second.body);
    expect([...archive.data]).toEqual([...originalDigest]);
    expect(archive.records).toHaveLength(1);
    expect(await leaseCount(env)).toBe(0);
  });

  it('exports an empty repo and releases its lease', async () => {
    const env = await fixture();
    await applySpaceWrites(env, SPACE, DID, [{ action: 'delete', collection: COLLECTION, rkey: 'a' }]);
    const opened = await streamSpaceRepoArchive(env, SPACE, DID);
    const archive = await readArchive(opened.body);
    expect(archive.records).toEqual([]);
    expect([...archive.data]).toEqual([...opened.commit.data]);
    expect(await leaseCount(env)).toBe(0);
  });

  it('streams a stable snapshot across short pages while writes and cleanup run', async () => {
    const env = await fixture();
    const large = 'x'.repeat(600_000);
    await applySpaceWrites(env, SPACE, DID, [create('b', large)]);
    await applySpaceWrites(env, SPACE, DID, [create('c', large)]);
    const opened = await streamSpaceRepoArchive(env, SPACE, DID);
    await applySpaceWrites(env, SPACE, DID, [
      { action: 'update', collection: COLLECTION, rkey: 'a', record: { $type: COLLECTION, text: 'new' } },
      { action: 'delete', collection: COLLECTION, rkey: 'b' },
      create('d', 'new'),
    ]);
    expect((await pruneSpaceRecordVersionsPage(env, SPACE, DID)).pruned).toBe(0);
    const archive = await readArchive(opened.body);
    expect(archive.records.map((record) => record.rkey)).toEqual(['a', 'b', 'c']);
    expect(dagCbor.decode(archive.records[0].value)).toMatchObject({ text: 'old' });
    expect([...archive.data]).toEqual([...opened.commit.data]);
    expect(await leaseCount(env)).toBe(0);
    expect((await pruneSpaceRecordVersionsPage(env, SPACE, DID)).pruned).toBe(2);
  });

  it('incrementally emits archives larger than the bounded import limit', async () => {
    const env = await fixture();
    const text = 'x'.repeat(900_000);
    for (let index = 0; index < 19; index++) {
      await applySpaceWrites(env, SPACE, DID, [create(`large-${index.toString().padStart(2, '0')}`, text)]);
    }
    const opened = await streamSpaceRepoArchive(env, SPACE, DID);
    let bytes = 0;
    let largestChunk = 0;
    async function* chunks() {
      for await (const chunk of opened.body) {
        bytes += chunk.byteLength;
        largestChunk = Math.max(largestChunk, chunk.byteLength);
        yield chunk;
      }
    }
    const archive = await readRepoStar(chunks());
    let count = 0;
    try {
      for await (const _record of archive.records) count++;
    } finally {
      await archive[Symbol.asyncDispose]();
    }
    expect(count).toBe(20);
    expect(bytes).toBeGreaterThan(16 * 1024 * 1024);
    expect(largestChunk).toBeLessThanOrEqual(1024 * 1024);
    expect(await leaseCount(env)).toBe(0);
  });

  it('fails before the STAR footer if valid record blocks no longer match the leased digest', async () => {
    const env = await fixture();
    const opened = await streamSpaceRepoArchive(env, SPACE, DID);
    const [cid, bytes] = await encodeRecordBlock({ $type: COLLECTION, text: 'tampered' });
    await env.ALTERAN_DB.prepare('DROP TRIGGER space_record_version_update_guard').run();
    await env.ALTERAN_DB.prepare('DROP TRIGGER space_version_fence_update').run();
    await env.ALTERAN_DB.prepare(
      'UPDATE space_record_version SET cid = ?, value_cbor = ?, value_size = ? WHERE space_ref = ?',
    ).bind(cid.toString(), bytes, bytes.byteLength, SPACE).run();
    const reader = opened.body.getReader();
    const chunks: Uint8Array[] = [];
    await expect((async () => {
      for (;;) {
        const result = await reader.read();
        if (result.done) return;
        chunks.push(result.value);
      }
    })()).rejects.toThrow('Space snapshot digest does not match');
    const truncated = await readRepoStar(chunks);
    try {
      await expect((async () => {
        for await (const _record of truncated.records) { /* consume the prefix */ }
      })()).rejects.toThrow('unexpected end of archive');
    } finally {
      await truncated[Symbol.asyncDispose]();
    }
    expect(await leaseCount(env)).toBe(0);
  });

  it('does not acquire an already-aborted request and releases an unpulled aborted stream', async () => {
    const env = await fixture();
    const database = env.ALTERAN_DB;
    let batches = 0;
    const watched = new Proxy(database, {
      get(target, property) {
        if (property === 'batch') return (statements: Parameters<typeof database.batch>[0]) => {
          batches++;
          return database.batch(statements);
        };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const stopped = new AbortController();
    stopped.abort();
    await expect(streamSpaceRepoArchive({ ...env, ALTERAN_DB: watched }, SPACE, DID, stopped.signal)).rejects.toThrow();
    expect(batches).toBe(0);
    expect(await leaseCount(env)).toBe(0);
    const controller = new AbortController();
    const opened = await streamSpaceRepoArchive(env, SPACE, DID, controller.signal);
    controller.abort();
    await expect(opened.body.getReader().read()).rejects.toThrow();
    await waitForNoLease(env);
  });

  it('cleans up when aborted during snapshot acquisition', async () => {
    const env = await fixture();
    const database = env.ALTERAN_DB;
    const paused = deferred();
    const resume = deferred();
    const watched = new Proxy(database, {
      get(target, property) {
        if (property === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
          const result = await database.batch(statements);
          paused.resolve();
          await resume.promise;
          return result;
        };
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const controller = new AbortController();
    const pending = streamSpaceRepoArchive({ ...env, ALTERAN_DB: watched }, SPACE, DID, controller.signal);
    await paused.promise;
    expect(await leaseCount(env)).toBe(1);
    controller.abort();
    resume.resolve();
    await expect(pending).rejects.toThrow();
    expect(await leaseCount(env)).toBe(0);
  });

  it('releases the lease when cancelled during a pending page', async () => {
    await checkInterruptedPage('cancel');
  });

  it('releases the lease when aborted during a pending page', async () => {
    await checkInterruptedPage('abort');
  });
});

function deferred() {
  let resolve = () => {};
  const promise = new Promise<void>((done) => resolve = done);
  return { promise, resolve };
}

async function checkInterruptedPage(interruption: 'cancel' | 'abort') {
  const env = await fixture();
  const database = env.ALTERAN_DB;
  const paused = deferred();
  const resume = deferred();
  let batches = 0;
  const watched = new Proxy(database, {
    get(target, property) {
      if (property === 'batch') return async (statements: Parameters<typeof database.batch>[0]) => {
        const result = await database.batch(statements);
        if (++batches === 2) {
          paused.resolve();
          await resume.promise;
        }
        return result;
      };
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  const controller = new AbortController();
  const opened = await streamSpaceRepoArchive({ ...env, ALTERAN_DB: watched }, SPACE, DID, controller.signal);
  const reader = opened.body.getReader();
  let chunks = 0;
  const reading = (async () => {
    for (;;) {
      const item = await reader.read();
      if (item.done) return;
      chunks++;
    }
  })().catch(() => {});
  await paused.promise;
  const beforeInterruption = chunks;
  const cancelling = interruption === 'cancel' ? reader.cancel() : Promise.resolve(controller.abort());
  await waitForNoLease(env);
  resume.resolve();
  await cancelling;
  await reading;
  expect(chunks).toBe(beforeInterruption);
  expect(batches).toBe(2);
}

async function waitForNoLease(env: TestEnv) {
  for (let attempt = 0; attempt < 100 && await leaseCount(env) !== 0; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  expect(await leaseCount(env)).toBe(0);
}
