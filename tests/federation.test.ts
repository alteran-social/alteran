import { describe, expect, it } from 'bun:test';
import { lexicons } from '@atproto/api';
import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { makeEnv } from './helpers/env';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { parseCarFile } from '../src/lib/car-reader';
import {
  encodeCommitFrame,
  type CommitMessage,
} from '../src/lib/firehose/frames';
import { createCommitPayload } from '../src/worker/sequencer/payload';
import { Sequencer } from '../src/worker/sequencer';
import * as CreateRecord from '../src/pages/xrpc/com.atproto.repo.createRecord';
import * as RepoGetRecord from '../src/pages/xrpc/com.atproto.repo.getRecord';
import * as UploadBlob from '../src/pages/xrpc/com.atproto.repo.uploadBlob';
import * as GetRepo from '../src/pages/xrpc/com.atproto.sync.getRepo';
import * as GetBlocks from '../src/pages/xrpc/com.atproto.sync.getBlocks';
import * as SyncGetRecord from '../src/pages/xrpc/com.atproto.sync.getRecord';
import * as ListBlobs from '../src/pages/xrpc/com.atproto.sync.listBlobs';

const FIXED_DATE = '2026-05-13T00:00:00.000Z';
const PNG_BYTES = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 1, 2, 3]);

type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

function apiContext(env: TestEnv, request: Request) {
  return { locals: { runtime: { env } }, request, url: new URL(request.url) } as any;
}

async function authHeader(env: TestEnv) {
  const { accessJwt } = await issueSessionTokens(env, String(env.PDS_DID));
  return { authorization: `Bearer ${accessJwt}` };
}

async function json<T = any>(res: Response): Promise<T> {
  return await res.json() as T;
}

function postRecord(text = 'hello', extra: Record<string, unknown> = {}) {
  return {
    $type: 'app.bsky.feed.post',
    text,
    createdAt: FIXED_DATE,
    ...extra,
  };
}

async function createPost(env: TestEnv, text = 'federation') {
  const request = new Request('https://pds.example/xrpc/com.atproto.repo.createRecord', {
    method: 'POST',
    headers: {
      ...(await authHeader(env)),
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      record: postRecord(text),
    }),
  });
  const res = await CreateRecord.POST(apiContext(env, request));
  expect(res.status).toBe(200);
  return json<{
    uri: string;
    cid: string;
    commit: { cid: string; rev: string };
  }>(res);
}

async function getRoute(route: { GET: (ctx: any) => Promise<Response> | Response }, env: TestEnv, url: string) {
  return route.GET(apiContext(env, new Request(url)));
}

async function latestCommit(env: TestEnv) {
  const row = await env.ALTERAN_DB.prepare(
    'SELECT seq, cid, rev, data, sig, ts FROM commit_log ORDER BY seq DESC LIMIT 1',
  ).first<{
    seq: number;
    cid: string;
    rev: string;
    data: string;
    sig: string;
    ts: number;
  }>();
  expect(row).toBeTruthy();
  return row!;
}

function makeSequencerState() {
  const storage = new Map<string, unknown>();
  const pending: Promise<unknown>[] = [];
  const state = {
    storage: {
      get: async (key: string) => storage.get(key),
      put: async (key: string, value: unknown) => {
        storage.set(key, value);
      },
    },
    blockConcurrencyWhile: (callback: () => Promise<unknown>) => {
      const promise = callback();
      pending.push(promise);
      return promise;
    },
    getWebSockets: () => [],
  };
  return {
    state,
    ready: async () => {
      await Promise.all(pending);
    },
  };
}

function decodeWireFrame<T = unknown>(bytes: Uint8Array): { header: any; body: T } {
  let headerLen = 0;
  for (let i = 1; i <= bytes.byteLength; i++) {
    try {
      dagCbor.decode(bytes.slice(0, i));
      headerLen = i;
      break;
    } catch {
      // Keep scanning until the first CBOR object boundary.
    }
  }
  if (headerLen === 0) throw new Error('could not find firehose header boundary');
  return {
    header: dagCbor.decode(bytes.slice(0, headerLen)),
    body: dagCbor.decode(bytes.slice(headerLen)) as T,
  };
}

describe('Repository federation surfaces', () => {
  it('exports getRepo and getBlocks as CAR files rooted at the local commit CID', async () => {
    const env = await makeEnv();
    const created = await createPost(env, 'repo export');

    const repoRes = await getRoute(
      GetRepo,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getRepo?did=${encodeURIComponent(String(env.PDS_DID))}`,
    );
    expect(repoRes.status).toBe(200);
    expect(repoRes.headers.get('content-type')).toContain('application/vnd.ipld.car');
    const repoCar = parseCarFile(new Uint8Array(await repoRes.arrayBuffer()));
    expect(repoCar.header.version).toBe(1);
    expect(String(repoCar.header.roots[0])).toBe(created.commit.cid);
    expect(repoCar.blocks.map((block) => block.cid.toString())).toContain(created.commit.cid);
    expect(repoCar.blocks.map((block) => block.cid.toString())).toContain(created.cid);

    const missingDidRes = await getRoute(
      GetBlocks,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlocks?cids=${encodeURIComponent(created.cid)}`,
    );
    expect(missingDidRes.status).toBe(400);
    expect(await json(missingDidRes)).toMatchObject({ error: 'InvalidRequest' });

    const malformedDidRes = await getRoute(
      GetBlocks,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlocks?did=not-a-did&cids=${encodeURIComponent(created.cid)}`,
    );
    expect(malformedDidRes.status).toBe(400);
    expect(await json(malformedDidRes)).toMatchObject({ error: 'InvalidRequest' });

    const paddedDidRes = await getRoute(
      GetBlocks,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlocks?did=${encodeURIComponent(` ${String(env.PDS_DID)}`)}&cids=${encodeURIComponent(created.cid)}`,
    );
    expect(paddedDidRes.status).toBe(400);
    expect(await json(paddedDidRes)).toMatchObject({ error: 'InvalidRequest' });

    const malformedCidRes = await getRoute(
      GetBlocks,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlocks?did=${encodeURIComponent(String(env.PDS_DID))}&cids=not-a-cid`,
    );
    expect(malformedCidRes.status).toBe(400);
    expect(await json(malformedCidRes)).toMatchObject({ error: 'InvalidRequest' });

    const emptyCidRes = await getRoute(
      GetBlocks,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlocks?did=${encodeURIComponent(String(env.PDS_DID))}&cids=&cids=${encodeURIComponent(created.cid)}`,
    );
    expect(emptyCidRes.status).toBe(400);
    expect(await json(emptyCidRes)).toMatchObject({ error: 'InvalidRequest' });

    const paddedCidRes = await getRoute(
      GetBlocks,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlocks?did=${encodeURIComponent(String(env.PDS_DID))}&cids=${encodeURIComponent(` ${created.cid}`)}`,
    );
    expect(paddedCidRes.status).toBe(400);
    expect(await json(paddedCidRes)).toMatchObject({ error: 'InvalidRequest' });

    const foreignRepoRes = await getRoute(
      GetBlocks,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlocks?did=did%3Aexample%3Aforeign&cids=${encodeURIComponent(created.cid)}`,
    );
    expect(foreignRepoRes.status).toBe(400);
    expect(await json(foreignRepoRes)).toMatchObject({ error: 'RepoNotFound' });

    const missingBlockRes = await getRoute(
      GetBlocks,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlocks?did=${encodeURIComponent(String(env.PDS_DID))}&cids=${encodeURIComponent(created.commit.cid)}`,
    );
    expect(missingBlockRes.status).toBe(400);
    expect(await json(missingBlockRes)).toMatchObject({ error: 'BlockNotFound' });

    const blocksUrl = new URL('https://pds.example/xrpc/com.atproto.sync.getBlocks');
    blocksUrl.searchParams.set('did', String(env.PDS_DID));
    blocksUrl.searchParams.append('cids', created.cid);
    const blocksRes = await getRoute(
      GetBlocks,
      env,
      blocksUrl.toString(),
    );
    expect(blocksRes.status).toBe(200);
    expect(blocksRes.headers.get('content-type')).toContain('application/vnd.ipld.car');
    const blocksCar = parseCarFile(new Uint8Array(await blocksRes.arrayBuffer()));
    expect(blocksCar.header.roots.map(String)).toEqual([created.cid]);
    expect(blocksCar.blocks.map((block) => block.cid.toString())).toEqual([created.cid]);
  });

  it('serves JSON getRecord and sync getRecord proof CARs for local records', async () => {
    const env = await makeEnv();
    const created = await createPost(env, 'record proof');
    const rkey = created.uri.split('/').pop() ?? '';

    const repoRecordRes = await getRoute(
      RepoGetRecord,
      env,
      `https://pds.example/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(String(env.PDS_DID))}&collection=app.bsky.feed.post&rkey=${rkey}`,
    );
    expect(repoRecordRes.status).toBe(200);
    const repoRecord = await json(repoRecordRes);
    expect(repoRecord.uri).toBe(created.uri);
    expect(repoRecord.cid).toBe(created.cid);
    expect(repoRecord.value).toMatchObject(postRecord('record proof'));

    const syncRecordRes = await getRoute(
      SyncGetRecord,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getRecord?did=${encodeURIComponent(String(env.PDS_DID))}&collection=app.bsky.feed.post&rkey=${rkey}`,
    );
    expect(syncRecordRes.status).toBe(200);
    expect(syncRecordRes.headers.get('content-type')).toContain('application/vnd.ipld.car');
    const proofCar = parseCarFile(new Uint8Array(await syncRecordRes.arrayBuffer()));
    const proofCids = proofCar.blocks.map((block) => block.cid.toString());
    expect(String(proofCar.header.roots[0])).toBe(created.commit.cid);
    expect(proofCids).toContain(created.commit.cid);
    expect(proofCids).toContain(created.cid);
  });

  it('lists only committed blob CIDs after upload and record reference', async () => {
    const env = await makeEnv();
    const uploadRes = await UploadBlob.POST(apiContext(env, new Request(
      'https://pds.example/xrpc/com.atproto.repo.uploadBlob',
      {
        method: 'POST',
        headers: {
          ...(await authHeader(env)),
          'content-type': 'image/png',
        },
        body: PNG_BYTES,
      },
    )));
    expect(uploadRes.status).toBe(200);
    const uploaded = await json(uploadRes);
    const blobCid = uploaded.blob.ref.$link;

    const created = await CreateRecord.POST(apiContext(env, new Request(
      'https://pds.example/xrpc/com.atproto.repo.createRecord',
      {
        method: 'POST',
        headers: {
          ...(await authHeader(env)),
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          repo: env.PDS_DID,
          collection: 'app.bsky.feed.post',
          record: postRecord('blob reference', {
            embed: {
              $type: 'app.bsky.embed.images',
              images: [{ image: uploaded.blob, alt: '' }],
            },
          }),
        }),
      },
    )));
    expect(created.status).toBe(200);

    const listed = await getRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${encodeURIComponent(String(env.PDS_DID))}`,
    );
    expect(listed.status).toBe(200);
    expect(await json<any>(listed)).toEqual({ cids: [blobCid] });
  });
});

describe('subscribeRepos event compatibility', () => {
  it('encodes commit events with lexicon-valid message fields and CAR roots', async () => {
    const env = await makeEnv();
    const created = await createPost(env, 'firehose event');
    const rkey = created.uri.split('/').pop() ?? '';
    const row = await latestCommit(env);
    const event = {
      seq: row.seq,
      did: String(env.PDS_DID),
      commitCid: row.cid,
      rev: row.rev,
      data: row.data,
      sig: row.sig,
      ts: row.ts,
      ops: [{
        action: 'create' as const,
        path: `app.bsky.feed.post/${rkey}`,
        cid: CID.parse(created.cid),
      }],
    };

    const message = await createCommitPayload(env, env.ALTERAN_DB, event);
    expect(message.repo).toBe(String(env.PDS_DID));
    expect(message.commit.toString()).toBe(created.commit.cid);
    expect(message.rev).toBe(created.commit.rev);
    expect(message.ops).toHaveLength(1);
    expect(message.ops[0].path).toBe(`app.bsky.feed.post/${rkey}`);

    const framed = encodeCommitFrame(message);
    const parsed = decodeWireFrame<CommitMessage>(framed);
    expect(parsed.header).toEqual({ op: 1, t: '#commit' });
    expect(parsed.body.commit.toString()).toBe(created.commit.cid);
    expect(parsed.body.blocks.byteLength).toBeGreaterThan(0);
    expect('$type' in (parsed.body as any)).toBe(false);

    const lexiconEventObject = {
      $type: 'com.atproto.sync.subscribeRepos#commit',
      ...message,
    };
    expect(() =>
      lexicons.assertValidXrpcMessage('com.atproto.sync.subscribeRepos', lexiconEventObject)
    ).not.toThrow();

    const diffCar = parseCarFile(message.blocks);
    expect(String(diffCar.header.roots[0])).toBe(created.commit.cid);
    expect(diffCar.blocks.map((block) => block.cid.toString())).toContain(created.commit.cid);
  });

  it('replays sequencer commit frames from the requested cursor', async () => {
    const env = await makeEnv();
    const firstPost = await createPost(env, 'cursor one');
    const first = await latestCommit(env);
    const secondPost = await createPost(env, 'cursor two');
    const second = await latestCommit(env);

    const { state, ready } = makeSequencerState();
    const sequencer = new Sequencer(state as any, env);
    await ready();
    await sequencer.fetch(new Request('https://sequencer.example/commit', {
      method: 'POST',
      body: JSON.stringify({
        did: String(env.PDS_DID),
        commitCid: second.cid,
        rev: second.rev,
        data: second.data,
        sig: second.sig,
      }),
    }));

    const sent: Uint8Array[] = [];
    const socket = {
      deserializeAttachment: () => ({ id: 'replay-test', cursor: first.seq }),
      send: (bytes: Uint8Array | ArrayBuffer | string) => {
        if (bytes instanceof Uint8Array) sent.push(bytes);
        else if (bytes instanceof ArrayBuffer) sent.push(new Uint8Array(bytes));
      },
    };

    await sequencer.webSocketOpen(socket as any);

    expect(sent).toHaveLength(2);
    const replayed = sent.map((bytes) => decodeWireFrame<CommitMessage>(bytes));
    expect(replayed[0].header).toEqual({ op: 1, t: '#commit' });
    expect(replayed[0].body.seq).toBe(first.seq);
    expect(replayed[0].body.commit.toString()).toBe(firstPost.commit.cid);
    expect(replayed[1].header).toEqual({ op: 1, t: '#commit' });
    expect(replayed[1].body.seq).toBeGreaterThan(first.seq);
    expect(replayed[1].body.commit.toString()).toBe(secondPost.commit.cid);
    expect(replayed[1].body.since).toBe(first.rev);
  });

  it('replays from the oldest available commit for explicit cursor zero', async () => {
    const env = await makeEnv();
    const firstPost = await createPost(env, 'cursor zero one');
    const first = await latestCommit(env);
    const secondPost = await createPost(env, 'cursor zero two');
    const second = await latestCommit(env);

    const { state, ready } = makeSequencerState();
    const sequencer = new Sequencer(state as any, env);
    await ready();

    const sent: Uint8Array[] = [];
    const socket = {
      deserializeAttachment: () => ({ id: 'cursor-zero-test', cursor: 0 }),
      send: (bytes: Uint8Array | ArrayBuffer | string) => {
        if (bytes instanceof Uint8Array) sent.push(bytes);
        else if (bytes instanceof ArrayBuffer) sent.push(new Uint8Array(bytes));
      },
    };

    await sequencer.webSocketOpen(socket as any);

    expect(sent).toHaveLength(2);
    const replayed = sent.map((bytes) => decodeWireFrame<CommitMessage>(bytes));
    expect(replayed.map((frame) => frame.header)).toEqual([
      { op: 1, t: '#commit' },
      { op: 1, t: '#commit' },
    ]);
    expect(replayed.map((frame) => frame.body.seq)).toEqual([first.seq, second.seq]);
    expect(replayed.map((frame) => frame.body.commit.toString())).toEqual([
      firstPost.commit.cid,
      secondPost.commit.cid,
    ]);
  });
});
