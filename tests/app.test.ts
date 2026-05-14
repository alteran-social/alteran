import { describe, it, beforeAll, afterAll } from "./helpers/bdd";
import { expect } from "@std/expect";
import * as dagCbor from '@ipld/dag-cbor';
import { fork } from 'node:child_process';
import getPort from 'get-port';
import dotenv from 'dotenv';

dotenv.config({ path: '.env.test' });

const runAppIntegrationTests = process.env.RUN_APP_TESTS === 'true';
const describeApp = runAppIntegrationTests ? describe : describe.skip;

async function j(r: Response) {
  const t = await r.text();
  try { return JSON.parse(t); } catch { return t; }
}

describeApp('app basics', () => {
  let app: any;
  let port: number;
  const serverLogs: string[] = [];

  const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

  async function waitForServerReady(url: string, timeoutMs = 30000): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const res = await fetch(url);
        if (res.ok) return;
      } catch {
        // swallow connection errors until timeout
      }
      await sleep(250);
    }
    const logTail = serverLogs.slice(-20).join('\n');
    throw new Error(`Dev server did not become ready at ${url} within ${timeoutMs}ms. Recent logs:\n${logTail}`);
  }

  beforeAll(async () => {
    port = await getPort();
    app = fork('./node_modules/astro/astro.js', ['dev', '--port', String(port)], { silent: true });
    app.stdout?.on('data', (data: Buffer) => {
      serverLogs.push(data.toString());
    });
    app.stderr?.on('data', (data: Buffer) => {
      serverLogs.push(data.toString());
    });
    await waitForServerReady(`http://localhost:${port}/health`);
  });

  afterAll(async () => {
    if (!app) return;
    app.kill();
    await new Promise(resolve => app.once('exit', resolve));
  });

  it('health and ready', async () => {
    const h = await fetch(`http://localhost:${port}/health`);
    expect(h.status).toBe(200);
    const r = await fetch(`http://localhost:${port}/ready`);
    expect(r.status).toBe(200);
  });

  it('denies CORS for disallowed origins when configured', async () => {
    // set allowed origin to example.com only
    const req = new Request(`http://localhost:${port}/xrpc/com.atproto.server.describeServer`, { headers: { origin: 'https://not-allowed.example' } });
    const res = await fetch(req);
    // When origin is disallowed, no ACAO header is present; browsers will block
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('bootstrap DB', async () => {
    const res = await fetch(`http://localhost:${port}/debug/db/bootstrap`, { method: 'POST' });
    expect(res.status).toBe(200);
  });

  it('createSession and create/put/delete record with head updates', async () => {
    // createSession
    const sess = await fetch(`http://localhost:${port}/xrpc/com.atproto.server.createSession`, {
      method: 'POST',
      body: JSON.stringify({ identifier: 'test', password: 'pwd' }),
      headers: { 'content-type': 'application/json' },
    });
    expect(sess.status).toBe(200);
    const sessBody = await j(sess);
    expect(sessBody.accessJwt).toBeDefined();
    const auth = { authorization: `Bearer ${sessBody.accessJwt}` };

    // createRecord
    const cr = await fetch(`http://localhost:${port}/xrpc/com.atproto.repo.createRecord`, {
      method: 'POST',
      body: JSON.stringify({ collection: 'app.bsky.feed.post', record: { text: 'hi' } }),
      headers: { 'content-type': 'application/json', ...auth },
    });
    expect(cr.status).toBe(200);
    const crBody = await j(cr);
    expect(crBody.uri).toContain('at://did:example:test/app.bsky.feed.post/');
    expect(crBody.commitCid).toBeDefined();
    expect(crBody.rev).toBe(1);

    // head
    const head1 = await fetch(`http://localhost:${port}/xrpc/com.atproto.sync.getHead`);
    const head1Body = await j(head1);
    expect(typeof head1Body.root).toBe('string');

    // putRecord
    const rkey = crBody.uri.split('/').pop();
    const pr = await fetch(`http://localhost:${port}/xrpc/com.atproto.repo.putRecord`, {
      method: 'POST',
      body: JSON.stringify({ collection: 'app.bsky.feed.post', rkey, record: { text: 'updated' } }),
      headers: { 'content-type': 'application/json', ...auth },
    });
    expect(pr.status).toBe(200);
    const prBody = await j(pr);
    expect(prBody.rev).toBe(2);

    const head2 = await fetch(`http://localhost:${port}/xrpc/com.atproto.sync.getHead`);
    const head2Body = await j(head2);
    expect(typeof head2Body.root).toBe('string');
    expect(head2Body.root).not.toBe(head1Body.root);

    // deleteRecord
    const dr = await fetch(`http://localhost:${port}/xrpc/com.atproto.repo.deleteRecord`, {
      method: 'POST',
      body: JSON.stringify({ collection: 'app.bsky.feed.post', rkey }),
      headers: { 'content-type': 'application/json', ...auth },
    });
    expect(dr.status).toBe(200);
    const drBody = await j(dr);
    expect(drBody.rev).toBe(3);
  });

  it('upload blob stores metadata', async () => {
    // create session to get access token
    const sess = await fetch(`http://localhost:${port}/xrpc/com.atproto.server.createSession`, {
      method: 'POST',
      body: JSON.stringify({ identifier: 'blobuser', password: 'pwd' }),
      headers: { 'content-type': 'application/json' },
    });
    const sessBody = await j(sess);
    const auth = { authorization: `Bearer ${sessBody.accessJwt}` };
    const body = new Blob([new Uint8Array([1,2,3,4])], { type: 'image/png' });
    const up = await fetch(`http://localhost:${port}/xrpc/com.atproto.repo.uploadBlob`, {
      method: 'POST', body, headers: { ...auth },
    });
    expect(up.status).toBe(200);
    const data = await j(up);
    expect(data.blob?.ref?.$link).toBeDefined();

    // reference blob in a record and then delete to allow GC
    const post = await fetch(`http://localhost:${port}/xrpc/com.atproto.repo.createRecord`, {
      method: 'POST', headers: { 'content-type': 'application/json', ...auth },
      body: JSON.stringify({ collection: 'app.bsky.feed.post', record: { text: 'blob', embed: { ref: { $link: data.blob.ref.$link } } } }),
    });
    expect(post.status).toBe(200);
    const uri = (await j(post)).uri as string;

    // delete record, run GC, ensure blob removed
    const rkey = uri.split('/').pop();
    const del = await fetch(`http://localhost:${port}/xrpc/com.atproto.repo.deleteRecord`, {
      method: 'POST', headers: { 'content-type': 'application/json', ...auth },
      body: JSON.stringify({ collection: 'app.bsky.feed.post', rkey }),
    });
    expect(del.status).toBe(200);
    const gc = await fetch(`http://localhost:${port}/debug/gc/blobs`, { method: 'POST' });
    expect(gc.status).toBe(200);
    const got = await fetch(`http://localhost:${port}/debug/blob/${data.blob.ref.$link}`);
    expect(got.status).toBe(404);
  });

  it('sync json endpoints return content', async () => {
    const repo = await fetch(`http://localhost:${port}/xrpc/com.atproto.sync.getRepo.json?did=did:example:test`);
    expect(repo.status).toBe(200);
    const chk = await fetch(`http://localhost:${port}/xrpc/com.atproto.sync.getCheckout.json?did=did:example:test`);
    expect(chk.status).toBe(200);
    const blocks = await fetch(`http://localhost:${port}/xrpc/com.atproto.sync.getBlocks.json?cids=invalid`);
    expect(blocks.status).toBe(200);
  });

  it('CAR getRepo root matches sync.getHead', async () => {
    // ensure at least one write for deterministic head
    const sess = await fetch(`http://localhost:${port}/xrpc/com.atproto.server.createSession`, {
      method: 'POST', body: JSON.stringify({ identifier: 't', password: 'pwd' }), headers: { 'content-type': 'application/json' },
    });
    const { accessJwt } = await j(sess);
    const auth = { authorization: `Bearer ${accessJwt}` };
    await fetch(`http://localhost:${port}/xrpc/com.atproto.repo.createRecord`, {
      method: 'POST', headers: { 'content-type': 'application/json', ...auth },
      body: JSON.stringify({ collection: 'app.bsky.feed.post', record: { text: 'car' } }),
    });

    const head = await fetch(`http://localhost:${port}/xrpc/com.atproto.sync.getHead`);
    const headBody = await j(head);
    const res = await fetch(`http://localhost:${port}/xrpc/com.atproto.sync.getRepo?did=did:example:test`);
    expect(res.status).toBe(200);
    const buf = new Uint8Array(await res.arrayBuffer());
    const [header, offset] = readCarHeader(buf);
    expect(header.version).toBe(1);
    const root = header.roots?.[0];
    const rootStr = typeof root === 'string' ? root : String(root);
    expect(rootStr).toBe(headBody.root);
    expect(offset).toBeGreaterThan(0);
  });

  it('streams CAR by commit seq range', async () => {
    // produce a couple commits
    const sess = await fetch(`http://localhost:${port}/xrpc/com.atproto.server.createSession`, {
      method: 'POST', body: JSON.stringify({ identifier: 'rng', password: 'pwd' }), headers: { 'content-type': 'application/json' },
    });
    const { accessJwt } = await j(sess);
    const auth = { authorization: `Bearer ${accessJwt}` };
    for (let i = 0; i < 3; i++) {
      await fetch(`http://localhost:${port}/xrpc/com.atproto.repo.createRecord`, {
        method: 'POST', headers: { 'content-type': 'application/json', ...auth },
        body: JSON.stringify({ collection: 'app.bsky.feed.post', record: { text: `rng-${i}` } }),
      });
    }
    // request a range
    const car = await fetch(`http://localhost:${port}/xrpc/com.atproto.sync.getRepo.range?from=1&to=3`);
    expect(car.status).toBe(200);
    const buf = new Uint8Array(await car.arrayBuffer());
    const [header, offset] = readCarHeader(buf);
    expect(header.version).toBe(1);
    expect(offset).toBeGreaterThan(0);
  });

  it('revokes old refresh tokens after rotation', async () => {
    // login
    const sess = await fetch(`http://localhost:${port}/xrpc/com.atproto.server.createSession`, {
      method: 'POST', body: JSON.stringify({ identifier: 'rot', password: 'pwd' }), headers: { 'content-type': 'application/json' },
    });
    expect(sess.status).toBe(200);
    const { refreshJwt } = await j(sess);

    // first refresh succeeds and rotates
    const r1 = await fetch(`http://localhost:${port}/xrpc/com.atproto.server.refreshSession`, {
      method: 'POST', headers: { authorization: `Bearer ${refreshJwt}` },
    });
    expect(r1.status).toBe(200);

    // second refresh with the old token should be rejected
    const r2 = await fetch(`http://localhost:${port}/xrpc/com.atproto.server.refreshSession`, {
      method: 'POST', headers: { authorization: `Bearer ${refreshJwt}` },
    });
    expect(r2.status).toBe(401);
  });

  it('keeps old access token valid until expiry after refresh', async () => {
    // login
    const sess = await fetch(`http://localhost:${port}/xrpc/com.atproto.server.createSession`, {
      method: 'POST', body: JSON.stringify({ identifier: 'rot2', password: 'pwd' }), headers: { 'content-type': 'application/json' },
    });
    expect(sess.status).toBe(200);
    const { accessJwt, refreshJwt } = await j(sess);

    // rotate tokens via refresh
    const r1 = await fetch(`http://localhost:${port}/xrpc/com.atproto.server.refreshSession`, {
      method: 'POST', headers: { authorization: `Bearer ${refreshJwt}` },
    });
    expect(r1.status).toBe(200);

    // old access should still authorize write routes until exp
    const authOld = { authorization: `Bearer ${accessJwt}` };
    const wr = await fetch(`http://localhost:${port}/xrpc/com.atproto.repo.createRecord`, {
      method: 'POST', headers: { 'content-type': 'application/json', ...authOld },
      body: JSON.stringify({ collection: 'app.bsky.feed.post', record: { text: 'still-valid' } }),
    });
    expect(wr.status).toBe(200);
  });
});

function readVarint(buf: Uint8Array, pos: number): [number, number] {
  let x = 0;
  let s = 0;
  let i = pos;
  for (;;) {
    const b = buf[i++];
    if (b === undefined) throw new Error('unexpected EOF');
    x |= (b & 0x7f) << s;
    if ((b & 0x80) === 0) break;
    s += 7;
  }
  return [x, i];
}

function readCarHeader(buf: Uint8Array): [any, number] {
  const [len, off] = readVarint(buf, 0);
  const header = dagCbor.decode(buf.subarray(off, off + len));
  return [header as any, off + len];
}
