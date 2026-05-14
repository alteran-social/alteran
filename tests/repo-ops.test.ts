import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { RepoManager } from '../src/services/repo-manager';
import type { Env } from '../src/env';
import { makeEnv } from './helpers/env';
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';


async function cidFor(value: unknown): Promise<CID> {
  const bytes = dagCbor.encode(value);
  const hash = await sha256.digest(bytes);
  return CID.createV1(dagCbor.code, hash);
}

describe('RepoManager.extractOps', () => {
  it.todo('detects create, update, and delete (integration with MST/D1)', () => {});
  /* it('detects create, update, and delete', async () => {
    const env = await makeEnv();
    // Bootstrap minimal schema used by RepoManager
    await env.ALTERAN_DB.exec("CREATE TABLE IF NOT EXISTS repo_root (did TEXT PRIMARY KEY, commit_cid TEXT, rev INTEGER);");
    await env.ALTERAN_DB.exec("CREATE TABLE IF NOT EXISTS record (uri TEXT PRIMARY KEY, cid TEXT NOT NULL, json TEXT NOT NULL, created_at INTEGER DEFAULT 0);");
    await env.ALTERAN_DB.exec("CREATE TABLE IF NOT EXISTS blockstore (cid TEXT PRIMARY KEY, bytes TEXT);");
    const mgr = new RepoManager(env);

    // Start with empty MST
    const emptyRoot = (await mgr.getOrCreateRoot()).getPointer();
    const prevRoot = await emptyRoot;

    // Add a record (create)
    const { mst: mst1, recordCid: c1 } = await mgr.addRecord('app.bsky.feed.post', 'r1', { text: 'a' });
    const root1 = await mst1.getPointer();

    const ops1 = await mgr.extractOps(prevRoot, root1);
    expect(ops1).toHaveLength(1);
    expect(ops1[0]).toMatchObject({ action: 'create', path: 'app.bsky.feed.post/r1' });

    // Update the record
    const { mst: mst2, recordCid: c2 } = await mgr.updateRecord('app.bsky.feed.post', 'r1', { text: 'b' });
    const root2 = await mst2.getPointer();
    const ops2 = await mgr.extractOps(root1, root2);
    expect(ops2).toHaveLength(1);
    expect(ops2[0]).toMatchObject({ action: 'update', path: 'app.bsky.feed.post/r1' });

    // Delete the record
    const { mst: mst3 } = await mgr.deleteRecord('app.bsky.feed.post', 'r1');
    const root3 = await mst3.getPointer();
    const ops3 = await mgr.extractOps(root2, root3);
    expect(ops3).toHaveLength(1);
    expect(ops3[0]).toMatchObject({ action: 'delete', path: 'app.bsky.feed.post/r1' });
  });*/
});
