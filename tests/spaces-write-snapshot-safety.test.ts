import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { makeSpaceEnv as makeEnv } from './helpers/space-env';
import { applySpaceWrites, createLocalSpace } from './helpers/space-storage';
import { commitSpaceWrites, loadSpaceSnapshot } from './helpers/space-storage';
import { parseSpaceRef } from '../src/db/space-ref';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';

const DID = 'did:example:test';
const COLLECTION = 'com.example.note';
const SPACE = `at://${DID}/space/com.example.notes/snapshot-safety`;
type TestEnv = Awaited<ReturnType<typeof makeEnv>>;
const deletion = (rkey: string) => ({ action: 'delete' as const, collection: COLLECTION, rkey });

async function fixture() {
  const env = await makeEnv();
  await createLocalSpace(env, SPACE);
  await applySpaceWrites(env, SPACE, DID, [{
    action: 'create', collection: COLLECTION, rkey: 'a', record: { $type: COLLECTION, text: 'private' },
  }]);
  for (const trigger of ['space_record_fence_update', 'space_record_version_update_guard', 'space_version_fence_update']) {
    await env.ALTERAN_DB.exec(`DROP TRIGGER ${trigger}`);
  }
  return env;
}

function watchSnapshot(env: TestEnv) {
  const db = env.ALTERAN_DB;
  let projected = 0;
  const wrapped = new Proxy(db, { get(target, key) {
    if (key === 'batch') return async (statements: Parameters<typeof db.batch>[0]) => {
      const result = await db.batch(statements);
      if (statements.length === 3) projected = JSON.stringify(result[2]?.results).length;
      return result;
    };
    const value = Reflect.get(target, key, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  return { env: { ...env, ALTERAN_DB: wrapped }, projected: () => projected };
}

describe('Space write snapshot integrity', () => {
  it('bounds corrupt metadata and values before transferring them from D1', async () => {
    for (const column of ['cid', 'value_cbor', 'repo_rev'] as const) {
      const env = await fixture();
      const oversized = `x${String.fromCharCode(0)}${'y'.repeat(400_000)}`;
      await env.ALTERAN_DB.prepare(`UPDATE space_record SET ${column} = ? WHERE space_ref = ?`).bind(oversized, SPACE).run();
      const versionSql = column === 'value_cbor'
        ? 'UPDATE space_record_version SET value_cbor = ?, value_size = 1 WHERE space_ref = ?'
        : `UPDATE space_record_version SET ${column} = ? WHERE space_ref = ?`;
      await env.ALTERAN_DB.prepare(versionSql).bind(oversized, SPACE).run();
      const watched = watchSnapshot(env);
      await expect(loadSpaceSnapshot(watched.env, parseSpaceRef(SPACE), DID, [deletion('a')])).rejects.toThrow();
      expect(watched.projected()).toBeLessThan(1_000);
    }
  });

  it('rejects matching copies whose bytes do not match their CID', async () => {
    const env = await fixture();
    const [, value] = await encodeRecordBlock({ $type: COLLECTION, text: 'different' });
    await env.ALTERAN_DB.prepare('UPDATE space_record SET value_cbor = ? WHERE space_ref = ?').bind(value, SPACE).run();
    await env.ALTERAN_DB.prepare('UPDATE space_record_version SET value_cbor = ?, value_size = ? WHERE space_ref = ?')
      .bind(value, value.length, SPACE).run();
    await expect(loadSpaceSnapshot(env, parseSpaceRef(SPACE), DID, [deletion('a')])).rejects.toThrow('Invalid Space record');
  });

  it('rejects invalid stored record revisions and detects revision changes after capture', async () => {
    const env = await fixture();
    const ref = parseSpaceRef(SPACE);
    const write = deletion('a');
    const snapshot = await loadSpaceSnapshot(env, ref, DID, [write]);
    const earlier = '2'.repeat(13);
    await env.ALTERAN_DB.prepare('UPDATE space_record SET repo_rev = ? WHERE space_ref = ?').bind(earlier, SPACE).run();
    await env.ALTERAN_DB.prepare('UPDATE space_record_version SET repo_rev = ? WHERE space_ref = ?').bind(earlier, SPACE).run();
    expect((await commitSpaceWrites(env, ref, DID, [write], snapshot)).tag).toBe('conflict');
    const invalid = `${'2'.repeat(12)}!`;
    await env.ALTERAN_DB.prepare('UPDATE space_record SET repo_rev = ? WHERE space_ref = ?').bind(invalid, SPACE).run();
    await env.ALTERAN_DB.prepare('UPDATE space_record_version SET repo_rev = ? WHERE space_ref = ?').bind(invalid, SPACE).run();
    await expect(loadSpaceSnapshot(env, ref, DID, [write])).rejects.toThrow();
  });

  it('caps aggregate old-record comparisons before projecting record bytes', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, SPACE);
    for (let index = 0; index < 5; index++) {
      await applySpaceWrites(env, SPACE, DID, [{ action: 'create', collection: COLLECTION, rkey: `r${index}`,
        record: { $type: COLLECTION, text: 'x'.repeat(850_000) } }]);
    }
    const watched = watchSnapshot(env);
    await expect(loadSpaceSnapshot(watched.env, parseSpaceRef(SPACE), DID,
      Array.from({ length: 5 }, (_, index) => deletion(`r${index}`))))
      .rejects.toThrow('too much existing data');
    expect(watched.projected()).toBeLessThan(5_000);
  });
});
