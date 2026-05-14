import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from './helpers/env';
import type { Env } from '../src/env';
import { D1Blockstore } from '../src/lib/mst';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { CID } from 'multiformats/cid';
import { parseCarFile } from '../src/lib/car-reader';

// Import the route handler directly and call GET() with a minimal APIContext
import * as GetBlocks from '../src/pages/xrpc/com.atproto.sync.getBlocks';

async function putBlock(env: Env, value: unknown): Promise<{ cid: CID; bytes: Uint8Array }> {
  const bytes = dagCbor.encode(value);
  const hash = await sha256.digest(bytes);
  const cid = CID.createV1(dagCbor.code, hash);
  const store = new D1Blockstore(env);
  await env.ALTERAN_DB.exec("CREATE TABLE IF NOT EXISTS blockstore (cid TEXT PRIMARY KEY, bytes TEXT)");
  await store.put(cid, bytes);
  return { cid, bytes };
}

describe('sync.getBlocks (CAR from blockstore)', () => {
  it('returns requested blocks as a CAR file', async () => {
    const env = await makeEnv();
    const a = await putBlock(env, { text: 'A' });
    const b = await putBlock(env, { text: 'B' });

    const url = new URL('http://localhost/xrpc/com.atproto.sync.getBlocks');
    url.searchParams.set('cids', [a.cid.toString(), b.cid.toString()].join(','));

    const res = await (GetBlocks as any).GET({
      locals: { env },
      request: new Request(url),
    });

    expect(res.status).toBe(200);
    expect(res.headers.get('content-type') || '').toContain('application/vnd.ipld.car');

    const buf = new Uint8Array(await res.arrayBuffer());
    const { header, blocks } = parseCarFile(buf);
    expect(header.roots.length).toBe(2);
    expect(String(header.roots[0])).toBe(a.cid.toString());
    expect(String(header.roots[1])).toBe(b.cid.toString());
    const gotCids = blocks.map((bl) => bl.cid.toString());
    expect(gotCids).toContain(a.cid.toString());
    expect(gotCids).toContain(b.cid.toString());
  });
});

