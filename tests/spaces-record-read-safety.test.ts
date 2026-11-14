import { describe, it } from './helpers/bdd';
import { expect } from '@std/expect';
import { makeEnv } from './helpers/env';
import { applySpaceWrites, createLocalSpace, getSpaceRecord } from '../src/db/space-store';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';
import { nextSpaceRevision } from '../src/db/space-tid';

const DID = 'did:example:test';
const COLLECTION = 'com.example.note';
const SPACE = `at://${DID}/space/com.example.notes/record-read`;
type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

async function fixture() {
  const env = await makeEnv();
  await createLocalSpace(env, SPACE);
  await applySpaceWrites(env, SPACE, DID, [{
    action: 'create', collection: COLLECTION, rkey: 'a', record: { $type: COLLECTION, text: 'private' },
  }]);
  for (const name of ['space_record_fence_update', 'space_record_version_update_guard', 'space_version_fence_update']) {
    await env.ALTERAN_DB.prepare(`DROP TRIGGER ${name}`).run();
  }
  return env;
}

function captureRecord(env: TestEnv) {
  const database = env.ALTERAN_DB;
  let bytes = 0;
  const wrapped = new Proxy(database, {
    get(target, property) {
      if (property === 'prepare') return (sql: string) => {
        const statement = target.prepare(sql);
        if (!sql.includes('FROM space_record record')) return statement;
        return new Proxy(statement, {
          get(prepared, method) {
            if (method === 'bind') return (...args: unknown[]) => {
              const bound = prepared.bind(...args);
              return new Proxy(bound, {
                get(query, name) {
                  if (name === 'first') return async () => {
                    const result = await query.first();
                    bytes = JSON.stringify(result).length;
                    return result;
                  };
                  const value = Reflect.get(query, name, query);
                  return typeof value === 'function' ? value.bind(query) : value;
                },
              });
            };
            const value = Reflect.get(prepared, method, prepared);
            return typeof value === 'function' ? value.bind(prepared) : value;
          },
        });
      };
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  return { env: { ...env, ALTERAN_DB: wrapped }, bytes: () => bytes };
}

describe('Space record read integrity', () => {
  it('rejects an oversized TEXT value without transferring it from D1', async () => {
    const env = await fixture();
    const text = `x\u0000${'y'.repeat(400_000)}`;
    await env.ALTERAN_DB.prepare('UPDATE space_record SET value_cbor = ? WHERE space_ref = ?').bind(text, SPACE).run();
    await env.ALTERAN_DB.prepare('UPDATE space_record_version SET value_cbor = ?, value_size = 1 WHERE space_ref = ?')
      .bind(text, SPACE).run();
    const observed = captureRecord(env);
    await expect(getSpaceRecord(observed.env, SPACE, DID, COLLECTION, 'a')).rejects.toThrow('Invalid Space record');
    expect(observed.bytes()).toBeLessThan(1_000);
  });

  it('rejects oversized CID and revision metadata without transferring it from D1', async () => {
    for (const column of ['cid', 'repo_rev']) {
      const env = await fixture();
      const text = `x\u0000${'y'.repeat(400_000)}`;
      await env.ALTERAN_DB.prepare(`UPDATE space_record SET ${column} = ? WHERE space_ref = ?`).bind(text, SPACE).run();
      await env.ALTERAN_DB.prepare(`UPDATE space_record_version SET ${column} = ? WHERE space_ref = ?`)
        .bind(text, SPACE).run();
      const observed = captureRecord(env);
      await expect(getSpaceRecord(observed.env, SPACE, DID, COLLECTION, 'a')).rejects.toThrow('Invalid Space record');
      expect(observed.bytes()).toBeLessThan(1_000);
    }
  });

  it('rejects canonical record bytes paired with another record CID', async () => {
    const env = await fixture();
    const [otherCid] = await encodeRecordBlock({ $type: COLLECTION, text: 'other' });
    await env.ALTERAN_DB.prepare('UPDATE space_record SET cid = ? WHERE space_ref = ?')
      .bind(otherCid.toString(), SPACE).run();
    await env.ALTERAN_DB.prepare('UPDATE space_record_version SET cid = ? WHERE space_ref = ?')
      .bind(otherCid.toString(), SPACE).run();
    await expect(getSpaceRecord(env, SPACE, DID, COLLECTION, 'a')).rejects.toThrow('Invalid Space record');
  });

  it('rejects a matching current version whose revision is newer than the head', async () => {
    const env = await fixture();
    const head = await env.ALTERAN_DB.prepare('SELECT rev FROM space_repo WHERE space_ref = ?')
      .bind(SPACE).first<{ rev: string }>();
    if (!head) throw new Error('Missing test repo');
    const next = nextSpaceRevision(head.rev);
    await env.ALTERAN_DB.prepare('UPDATE space_record SET repo_rev = ? WHERE space_ref = ?').bind(next, SPACE).run();
    await env.ALTERAN_DB.prepare('UPDATE space_record_version SET repo_rev = ? WHERE space_ref = ?').bind(next, SPACE).run();
    await expect(getSpaceRecord(env, SPACE, DID, COLLECTION, 'a')).rejects.toThrow('Invalid Space record');
  });

  it('rejects oversized head metadata without transferring it from D1', async () => {
    const env = await fixture();
    await env.ALTERAN_DB.prepare('DROP TRIGGER space_repo_fence_update').run();
    const text = `x\u0000${'y'.repeat(400_000)}`;
    await env.ALTERAN_DB.prepare('UPDATE space_repo SET rev = ? WHERE space_ref = ?').bind(text, SPACE).run();
    const observed = captureRecord(env);
    await expect(getSpaceRecord(observed.env, SPACE, DID, COLLECTION, 'a')).rejects.toThrow('Invalid Space record');
    expect(observed.bytes()).toBeLessThan(1_000);
  });

  it('rejects a head generation outside the safe integer range', async () => {
    const env = await fixture();
    await env.ALTERAN_DB.prepare('DROP TRIGGER space_repo_fence_update').run();
    await env.ALTERAN_DB.prepare('UPDATE space_repo SET generation = 9007199254740992 WHERE space_ref = ?')
      .bind(SPACE).run();
    await expect(getSpaceRecord(env, SPACE, DID, COLLECTION, 'a')).rejects.toThrow('Invalid Space record');
  });

  it('distinguishes a missing current version from an absent record', async () => {
    const env = await fixture();
    await env.ALTERAN_DB.prepare('DROP TRIGGER space_record_version_delete_guard').run();
    await env.ALTERAN_DB.prepare('DROP TRIGGER space_version_fence_delete').run();
    await env.ALTERAN_DB.prepare('DELETE FROM space_record_version WHERE space_ref = ?').bind(SPACE).run();
    await expect(getSpaceRecord(env, SPACE, DID, COLLECTION, 'a')).rejects.toThrow('Invalid Space record');
    expect(await getSpaceRecord(env, SPACE, DID, COLLECTION, 'missing')).toBeNull();
  });
});
