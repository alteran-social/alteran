import { describe, it, expect } from 'bun:test';
import { makeEnv } from './helpers/env';
import type { Env } from '../src/env';
import { D1Blockstore, MST } from '../src/lib/mst';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { CID } from 'multiformats/cid';
import { RepoManager } from '../src/services/repo-manager';

async function encode(value: unknown): Promise<{ cid: CID; bytes: Uint8Array }> {
  const bytes = dagCbor.encode(value);
  const hash = await sha256.digest(bytes);
  const cid = CID.createV1(dagCbor.code, hash);
  return { cid, bytes };
}

async function storeMst(blockstore: D1Blockstore, mst: MST): Promise<void> {
  const { cid, bytes } = await mst.serialize();
  await blockstore.put(cid, bytes);
  const entries = await mst.getEntries();
  for (const entry of entries) {
    if (entry.isTree()) {
      await storeMst(blockstore, entry);
    }
  }
}

describe('RepoManager.extractOps (functional)', () => {
  it('detects create, update, and delete by diffing MST roots', async () => {
    const env = await makeEnv();
    await env.ALTERAN_DB.exec("CREATE TABLE IF NOT EXISTS blockstore (cid TEXT PRIMARY KEY, bytes TEXT)");
    const store = new D1Blockstore(env);

    // Start with empty tree
    const mst0 = await MST.create(store, []);

    // Create
    const { cid: rcidA, bytes: rbytesA } = await encode({ text: 'A' });
    await store.put(rcidA, rbytesA);
    const mst1 = await mst0.add('app.bsky.feed.post/r1', rcidA);
    await storeMst(store, mst1);
    const root1 = await mst1.getPointer();

    // Update
    const { cid: rcidB, bytes: rbytesB } = await encode({ text: 'B' });
    await store.put(rcidB, rbytesB);
    const mst1Loaded = await MST.load(store, root1);
    const mst2 = await mst1Loaded.update('app.bsky.feed.post/r1', rcidB);
    await storeMst(store, mst2);
    const root2 = await mst2.getPointer();

    // Delete
    const mst2Loaded = await MST.load(store, root2);
    const mst3 = await mst2Loaded.delete('app.bsky.feed.post/r1');
    await storeMst(store, mst3);
    const root3 = await mst3.getPointer();

    const mgr = new RepoManager(env);

    const opsCreate = await mgr.extractOps(null, root1);
    expect(opsCreate).toHaveLength(1);
    expect(opsCreate[0]).toMatchObject({ action: 'create', path: 'app.bsky.feed.post/r1' });

    const opsUpdate = await mgr.extractOps(root1, root2);
    expect(opsUpdate).toHaveLength(1);
    expect(opsUpdate[0]).toMatchObject({ action: 'update', path: 'app.bsky.feed.post/r1' });

    const opsDelete = await mgr.extractOps(root2, root3);
    expect(opsDelete).toHaveLength(1);
    expect(opsDelete[0]).toMatchObject({ action: 'delete', path: 'app.bsky.feed.post/r1' });
  });
});

