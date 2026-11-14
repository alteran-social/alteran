import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { applySpaceWrites, createLocalSpace, getSpaceRecord } from '../src/db/space-store';
import { commitSpaceWrites, loadSpaceSnapshot } from '../src/db/space-mutation';
import { parseSpaceRef } from '../src/db/space-ref';
import { SpaceStorageError } from '../src/db/space-types';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';

const did = 'did:example:test';
const space = `at://${did}/space/com.example.notes/a`;
const collection = 'com.example.note';

function withChangingLength<T>(value: T[]): { proxy: T[]; reads: () => number } {
  let reads = 0;
  const proxy = new Proxy(value, {
    get(target, key, receiver) {
      if (key === 'length') return ++reads === 1 ? 1 : 1_000_000;
      return Reflect.get(target, key, receiver);
    },
  });
  return { proxy, reads: () => reads };
}

async function expectInvalid(action: () => Promise<unknown>): Promise<void> {
  try {
    await action();
    throw new Error('Expected invalid request');
  } catch (error) {
    expect(error).toBeInstanceOf(SpaceStorageError);
    expect((error as SpaceStorageError).code).toBe('InvalidRequest');
  }
}

describe('space write input bounds', () => {
  it('captures a bounded high-level array length without invoking a proxy getter', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, space);
    const write = { action: 'create' as const, collection, rkey: 'a', record: { $type: collection } };
    const input = withChangingLength([write]);
    expect((await applySpaceWrites(env, space, did, input.proxy))!.operations).toHaveLength(1);
    expect(input.reads()).toBe(0);
    expect(await getSpaceRecord(env, space, did, collection, 'a')).not.toBeNull();
    const revoked = Proxy.revocable([write], {});
    revoked.revoke();
    await expectInvalid(() => applySpaceWrites(env, space, did, revoked.proxy));
    const revokedRecord = Proxy.revocable({}, {});
    revokedRecord.revoke();
    await expectInvalid(() => applySpaceWrites(env, space, did, [{ ...write, record: { $type: collection, nested: revokedRecord.proxy } }]));
  });

  it('captures a bounded prepared array length without invoking a proxy getter', async () => {
    const env = await makeEnv();
    await createLocalSpace(env, space);
    const [cid, value] = await encodeRecordBlock({ $type: collection });
    const write = { action: 'create' as const, collection, rkey: 'a', cid: cid.toString(), value, blobs: [] };
    const ref = parseSpaceRef(space);
    const input = withChangingLength([write]);
    const snapshot = await loadSpaceSnapshot(env, ref, did, input.proxy);
    expect((await commitSpaceWrites(env, ref, did, input.proxy, snapshot)).tag).toBe('committed');
    expect(input.reads()).toBe(0);
    expect(await getSpaceRecord(env, space, did, collection, 'a')).not.toBeNull();
    const revoked = Proxy.revocable([write], {});
    revoked.revoke();
    await expectInvalid(() => loadSpaceSnapshot(env, ref, did, revoked.proxy));
    await expectInvalid(() => commitSpaceWrites(env, ref, did, revoked.proxy, snapshot));
    const revokedBlobs = Proxy.revocable([], {});
    revokedBlobs.revoke();
    await expectInvalid(() => commitSpaceWrites(env, ref, did, [{ ...write, blobs: revokedBlobs.proxy }], snapshot));
  });
});
