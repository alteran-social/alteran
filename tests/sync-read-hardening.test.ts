import { describe, expect, test } from 'bun:test';
import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import type { Env } from '../src/env';
import { putBlobRef } from '../src/db/dal';
import { getRoot } from '../src/db/repo';
import { parseCarFile } from '../src/lib/car-reader';
import { D1Blockstore } from '../src/lib/mst';
import { RepoManager } from '../src/services/repo-manager';
import { makeEnv } from './helpers/env';

import * as DescribeRepo from '../src/pages/xrpc/com.atproto.repo.describeRepo';
import * as RepoGetRecord from '../src/pages/xrpc/com.atproto.repo.getRecord';
import * as GetBlob from '../src/pages/xrpc/com.atproto.sync.getBlob';
import * as GetBlocks from '../src/pages/xrpc/com.atproto.sync.getBlocks';
import * as GetBlocksJson from '../src/pages/xrpc/com.atproto.sync.getBlocks.json';
import * as GetCheckout from '../src/pages/xrpc/com.atproto.sync.getCheckout';
import * as GetCheckoutJson from '../src/pages/xrpc/com.atproto.sync.getCheckout.json';
import * as GetHead from '../src/pages/xrpc/com.atproto.sync.getHead';
import * as GetLatestCommit from '../src/pages/xrpc/com.atproto.sync.getLatestCommit';
import * as GetRecord from '../src/pages/xrpc/com.atproto.sync.getRecord';
import * as GetRepo from '../src/pages/xrpc/com.atproto.sync.getRepo';
import * as GetRepoJson from '../src/pages/xrpc/com.atproto.sync.getRepo.json';
import * as GetRepoRange from '../src/pages/xrpc/com.atproto.sync.getRepo.range';
import * as GetRepoStatus from '../src/pages/xrpc/com.atproto.sync.getRepoStatus';
import * as ListBlobs from '../src/pages/xrpc/com.atproto.sync.listBlobs';

const LOCAL_DID = 'did:example:test';
const LOCAL_HANDLE = 'test.example';
const FOREIGN_DID = 'did:example:foreign';
const VALID_MISSING_CID = 'bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua';

function apiContext(env: Env, target: string) {
  const url = new URL(target);
  return {
    locals: { runtime: { env }, requestId: 'test' },
    request: new Request(url),
    url,
  } as any;
}

async function responseJson(response: Response) {
  return await response.json() as any;
}

function expectError(body: any, error: string) {
  expect(body.error).toBe(error);
  expect(typeof body.message).toBe('string');
}

async function createPost(env: Env, rkey: string, text = rkey) {
  const manager = new RepoManager(env);
  return manager.createRecord('app.bsky.feed.post', {
    text,
    createdAt: '2026-05-14T00:00:00.000Z',
  }, rkey);
}

async function putDagCborBlock(env: Env, value: unknown): Promise<CID> {
  const bytes = dagCbor.encode(value);
  const hash = await sha256.digest(bytes);
  const cid = CID.createV1(dagCbor.code, hash);
  const blockstore = new D1Blockstore(env);
  await blockstore.put(cid, bytes);
  return cid;
}

async function rawBlobCid(bytes: Uint8Array): Promise<CID> {
  return CID.createV1(0x55, await sha256.digest(bytes));
}

function legacyBlobKey(cid: CID): string {
  let digest = '';
  for (const byte of cid.multihash.digest) digest += String.fromCharCode(byte);
  const b64url = btoa(digest).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  return `blobs/by-cid/${b64url}`;
}

async function putBlob(env: Env, label: string): Promise<string> {
  const bytes = new TextEncoder().encode(label);
  const cid = await rawBlobCid(bytes);
  const key = `test-blobs/${cid.toString()}`;
  await env.ALTERAN_BLOBS.put(key, bytes, { httpMetadata: { contentType: 'text/plain' } });
  await putBlobRef(env, LOCAL_DID, cid.toString(), key, 'text/plain', bytes.length);
  return cid.toString();
}

describe('sync and repo read hardening', () => {
  test('getRepo serves a full local CAR and rejects since/non-local DID', async () => {
    const env = await makeEnv();
    const created = await createPost(env, 'repo-full');

    const response = await GetRepo.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getRepo?did=${LOCAL_DID}`));
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type') || '').toContain('application/vnd.ipld.car');

    const { header, blocks } = parseCarFile(new Uint8Array(await response.arrayBuffer()));
    expect(header.roots[0].toString()).toBe(created.commitCid);
    expect(blocks.some((block) => block.cid.toString() === created.cid)).toBe(true);

    const since = await GetRepo.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getRepo?did=${LOCAL_DID}&since=3kold`));
    expect(since.status).toBe(400);
    expectError(await responseJson(since), 'InvalidRequest');

    const foreign = await GetRepo.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getRepo?did=${FOREIGN_DID}`));
    expect(foreign.status).toBe(400);
    expectError(await responseJson(foreign), 'RepoNotFound');

    const malformedDid = await GetRepo.GET(apiContext(env, 'https://pds.example/xrpc/com.atproto.sync.getRepo?did=did:m123:val'));
    expect(malformedDid.status).toBe(400);
    expectError(await responseJson(malformedDid), 'InvalidRequest');
  });

  test('getCheckout is a full local CAR and rejects non-standard ranges', async () => {
    const env = await makeEnv();
    const created = await createPost(env, 'checkout-full');

    const response = await GetCheckout.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getCheckout?did=${LOCAL_DID}`));
    expect(response.status).toBe(200);

    const { header, blocks } = parseCarFile(new Uint8Array(await response.arrayBuffer()));
    expect(header.roots[0].toString()).toBe(created.commitCid);
    expect(blocks.some((block) => block.cid.toString() === created.cid)).toBe(true);

    const range = await GetCheckout.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getCheckout?did=${LOCAL_DID}&from=1&to=2`));
    expect(range.status).toBe(400);
    expectError(await responseJson(range), 'InvalidRequest');
  });

  test('getBlocks uses repeated XRPC cids and scoped local DID errors', async () => {
    const env = await makeEnv();
    const first = await putDagCborBlock(env, { text: 'first' });
    const second = await putDagCborBlock(env, { text: 'second' });

    const response = await GetBlocks.GET(apiContext(
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlocks?did=${LOCAL_DID}&cids=${first.toString()}&cids=${second.toString()}`,
    ));
    expect(response.status).toBe(200);

    const { header, blocks } = parseCarFile(new Uint8Array(await response.arrayBuffer()));
    expect(header.roots.map((cid) => cid.toString())).toEqual([first.toString(), second.toString()]);
    expect(blocks.map((block) => block.cid.toString()).sort()).toEqual([first.toString(), second.toString()].sort());

    const missingDid = await GetBlocks.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getBlocks?cids=${first.toString()}`));
    expect(missingDid.status).toBe(400);
    expectError(await responseJson(missingDid), 'InvalidRequest');

    const foreign = await GetBlocks.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getBlocks?did=${FOREIGN_DID}&cids=${first.toString()}`));
    expect(foreign.status).toBe(400);
    expectError(await responseJson(foreign), 'RepoNotFound');

    const malformed = await GetBlocks.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getBlocks?did=${LOCAL_DID}&cids=not-a-cid`));
    expect(malformed.status).toBe(400);
    expectError(await responseJson(malformed), 'InvalidRequest');

    const emptyItem = await GetBlocks.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getBlocks?did=${LOCAL_DID}&cids=&cids=${first.toString()}`));
    expect(emptyItem.status).toBe(400);
    expectError(await responseJson(emptyItem), 'InvalidRequest');

    const absent = await GetBlocks.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getBlocks?did=${LOCAL_DID}&cids=${VALID_MISSING_CID}`));
    expect(absent.status).toBe(400);
    expectError(await responseJson(absent), 'BlockNotFound');
  });

  test('sync.getRecord validates params and scopes proof CARs to local DID', async () => {
    const env = await makeEnv();
    const created = await createPost(env, 'record-proof');

    const response = await GetRecord.GET(apiContext(
      env,
      `https://pds.example/xrpc/com.atproto.sync.getRecord?did=${LOCAL_DID}&collection=app.bsky.feed.post&rkey=record-proof`,
    ));
    expect(response.status).toBe(200);
    const { header, blocks } = parseCarFile(new Uint8Array(await response.arrayBuffer()));
    expect(header.roots[0].toString()).toBe(created.commitCid);
    expect(blocks.some((block) => block.cid.toString() === created.cid)).toBe(true);

    const foreign = await GetRecord.GET(apiContext(
      env,
      `https://pds.example/xrpc/com.atproto.sync.getRecord?did=${FOREIGN_DID}&collection=app.bsky.feed.post&rkey=record-proof`,
    ));
    expect(foreign.status).toBe(400);
    expectError(await responseJson(foreign), 'RepoNotFound');

    const missingCollection = await GetRecord.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getRecord?did=${LOCAL_DID}&rkey=record-proof`));
    expect(missingCollection.status).toBe(400);
    expectError(await responseJson(missingCollection), 'InvalidRequest');
  });

  test('getLatestCommit, getRepoStatus, and getHead require the configured DID', async () => {
    const env = await makeEnv();
    const created = await createPost(env, 'head-state');

    const latest = await GetLatestCommit.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getLatestCommit?did=${LOCAL_DID}`));
    expect(latest.status).toBe(200);
    expect(await responseJson(latest)).toMatchObject({ cid: created.commitCid, rev: created.rev });

    const status = await GetRepoStatus.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getRepoStatus?did=${LOCAL_DID}`));
    expect(status.status).toBe(200);
    expect(await responseJson(status)).toMatchObject({ did: LOCAL_DID, active: true, rev: created.rev });

    const head = await GetHead.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getHead?did=${LOCAL_DID}`));
    expect(head.status).toBe(200);
    expect(await responseJson(head)).toEqual({ root: created.commitCid });

    const foreignLatest = await GetLatestCommit.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getLatestCommit?did=${FOREIGN_DID}`));
    expect(foreignLatest.status).toBe(400);
    expectError(await responseJson(foreignLatest), 'RepoNotFound');

    const foreignHead = await GetHead.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getHead?did=${FOREIGN_DID}`));
    expect(foreignHead.status).toBe(404);
    expectError(await responseJson(foreignHead), 'HeadNotFound');
  });

  test('repo.getRecord requires lexicon params, local repo, and matching optional cid', async () => {
    const env = await makeEnv();
    const first = await createPost(env, 'repo-record', 'from did');
    const second = await createPost(env, 'other-record', 'other cid');
    const manager = new RepoManager(env);
    const camelCase = await manager.createRecord('com.example.fooBar', {
      text: 'camel nsid',
      createdAt: '2026-05-14T00:00:00.000Z',
    }, 'camelCase');

    const byDid = await RepoGetRecord.GET(apiContext(
      env,
      `https://pds.example/xrpc/com.atproto.repo.getRecord?repo=${LOCAL_DID}&collection=app.bsky.feed.post&rkey=repo-record`,
    ));
    expect(byDid.status).toBe(200);
    expect(await responseJson(byDid)).toMatchObject({
      uri: first.uri,
      cid: first.cid,
      value: { text: 'from did', createdAt: '2026-05-14T00:00:00.000Z' },
    });

    const byHandle = await RepoGetRecord.GET(apiContext(
      env,
      `https://pds.example/xrpc/com.atproto.repo.getRecord?repo=${LOCAL_HANDLE}&collection=app.bsky.feed.post&rkey=repo-record&cid=${first.cid}`,
    ));
    expect(byHandle.status).toBe(200);
    expect((await responseJson(byHandle)).uri).toBe(first.uri);

    const uppercaseHandle = await RepoGetRecord.GET(apiContext(
      env,
      'https://pds.example/xrpc/com.atproto.repo.getRecord?repo=TEST.EXAMPLE&collection=com.example.fooBar&rkey=camelCase',
    ));
    expect(uppercaseHandle.status).toBe(200);
    expect(await responseJson(uppercaseHandle)).toMatchObject({
      uri: camelCase.uri,
      cid: camelCase.cid,
      value: { text: 'camel nsid', createdAt: '2026-05-14T00:00:00.000Z' },
    });

    const uriOnly = await RepoGetRecord.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.repo.getRecord?uri=${encodeURIComponent(first.uri)}`));
    expect(uriOnly.status).toBe(400);
    expectError(await responseJson(uriOnly), 'InvalidRequest');

    const foreign = await RepoGetRecord.GET(apiContext(
      env,
      `https://pds.example/xrpc/com.atproto.repo.getRecord?repo=${FOREIGN_DID}&collection=app.bsky.feed.post&rkey=repo-record`,
    ));
    expect(foreign.status).toBe(400);
    expectError(await responseJson(foreign), 'RecordNotFound');

    const cidMismatch = await RepoGetRecord.GET(apiContext(
      env,
      `https://pds.example/xrpc/com.atproto.repo.getRecord?repo=${LOCAL_DID}&collection=app.bsky.feed.post&rkey=repo-record&cid=${second.cid}`,
    ));
    expect(cidMismatch.status).toBe(400);
    expectError(await responseJson(cidMismatch), 'RecordNotFound');

    const emptyCid = await RepoGetRecord.GET(apiContext(
      env,
      `https://pds.example/xrpc/com.atproto.repo.getRecord?repo=${LOCAL_DID}&collection=app.bsky.feed.post&rkey=repo-record&cid=`,
    ));
    expect(emptyCid.status).toBe(400);
    expectError(await responseJson(emptyCid), 'InvalidRequest');
  });

  test('describeRepo requires a local DID or handle', async () => {
    const env = await makeEnv();

    const byHandle = await DescribeRepo.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.repo.describeRepo?repo=${LOCAL_HANDLE}`));
    expect(byHandle.status).toBe(200);
    expect(await responseJson(byHandle)).toMatchObject({ did: LOCAL_DID, handle: LOCAL_HANDLE, handleIsCorrect: true });

    const byDid = await DescribeRepo.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.repo.describeRepo?repo=${LOCAL_DID}`));
    expect(byDid.status).toBe(200);
    expect((await responseJson(byDid)).did).toBe(LOCAL_DID);

    const uppercaseHandle = await DescribeRepo.GET(apiContext(env, 'https://pds.example/xrpc/com.atproto.repo.describeRepo?repo=TEST.EXAMPLE'));
    expect(uppercaseHandle.status).toBe(200);
    expect((await responseJson(uppercaseHandle)).did).toBe(LOCAL_DID);

    const missing = await DescribeRepo.GET(apiContext(env, 'https://pds.example/xrpc/com.atproto.repo.describeRepo'));
    expect(missing.status).toBe(400);
    expectError(await responseJson(missing), 'InvalidRequest');

    const foreign = await DescribeRepo.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.repo.describeRepo?repo=${FOREIGN_DID}`));
    expect(foreign.status).toBe(400);
    expectError(await responseJson(foreign), 'RepoNotFound');
  });

  test('getBlob validates DID and blob availability with lexicon-shaped errors', async () => {
    const env = await makeEnv();
    const cid = await putBlob(env, 'hello blob');

    const response = await GetBlob.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${LOCAL_DID}&cid=${cid}`));
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('text/plain');
    expect(await response.text()).toBe('hello blob');

    const missingCid = await GetBlob.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${LOCAL_DID}`));
    expect(missingCid.status).toBe(400);
    expectError(await responseJson(missingCid), 'InvalidRequest');

    const foreign = await GetBlob.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${FOREIGN_DID}&cid=${cid}`));
    expect(foreign.status).toBe(400);
    expectError(await responseJson(foreign), 'RepoNotFound');

    const absent = await GetBlob.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${LOCAL_DID}&cid=${VALID_MISSING_CID}`));
    expect(absent.status).toBe(400);
    expectError(await responseJson(absent), 'BlobNotFound');

    await putBlobRef(env, FOREIGN_DID, cid, 'test-blobs/foreign-only', 'text/plain', 10);
    const foreignOnlyMetadata = await GetBlob.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${LOCAL_DID}&cid=${cid}`));
    expect(foreignOnlyMetadata.status).toBe(400);
    expectError(await responseJson(foreignOnlyMetadata), 'BlobNotFound');

    const legacyBytes = new TextEncoder().encode('legacy unassociated blob');
    const legacyCid = await rawBlobCid(legacyBytes);
    await env.ALTERAN_BLOBS.put(legacyBlobKey(legacyCid), legacyBytes);
    const legacyOnly = await GetBlob.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${LOCAL_DID}&cid=${legacyCid.toString()}`));
    expect(legacyOnly.status).toBe(400);
    expectError(await responseJson(legacyOnly), 'BlobNotFound');
  });

  test('listBlobs scopes DID, paginates by cursor, and rejects unsupported since', async () => {
    const env = await makeEnv();
    const cids = [await putBlob(env, 'blob-a'), await putBlob(env, 'blob-b'), await putBlob(env, 'blob-c')].sort();

    const first = await ListBlobs.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${LOCAL_DID}&limit=1`));
    expect(first.status).toBe(200);
    const firstBody = await responseJson(first);
    expect(firstBody).toEqual({ cids: [cids[0]], cursor: cids[0] });

    const second = await ListBlobs.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${LOCAL_DID}&limit=2&cursor=${firstBody.cursor}`));
    expect(second.status).toBe(200);
    expect(await responseJson(second)).toEqual({ cids: cids.slice(1) });

    const since = await ListBlobs.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${LOCAL_DID}&since=3kold`));
    expect(since.status).toBe(400);
    expectError(await responseJson(since), 'InvalidRequest');

    const invalidLimit = await ListBlobs.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${LOCAL_DID}&limit=0`));
    expect(invalidLimit.status).toBe(400);
    expectError(await responseJson(invalidLimit), 'InvalidRequest');

    const foreign = await ListBlobs.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${FOREIGN_DID}`));
    expect(foreign.status).toBe(400);
    expectError(await responseJson(foreign), 'RepoNotFound');
  });

  test('non-standard public sync helper routes return stable 404 JSON', async () => {
    const env = await makeEnv();
    const routes = [
      GetRepoRange.GET(apiContext(env, 'https://pds.example/xrpc/com.atproto.sync.getRepo.range?from=1&to=2')),
      GetRepoJson.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getRepo.json?did=${LOCAL_DID}`)),
      GetCheckoutJson.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getCheckout.json?did=${LOCAL_DID}`)),
      GetBlocksJson.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getBlocks.json?cids=${VALID_MISSING_CID}`)),
    ];

    for (const route of routes) {
      const response = await route;
      expect(response.status).toBe(404);
      expectError(await responseJson(response), 'NotFound');
    }
  });

  test('full snapshot root matches the persisted repo root', async () => {
    const env = await makeEnv();
    await createPost(env, 'persisted-root');
    const root = await getRoot(env);
    expect(root).not.toBeNull();

    const response = await GetRepo.GET(apiContext(env, `https://pds.example/xrpc/com.atproto.sync.getRepo?did=${LOCAL_DID}`));
    const { header } = parseCarFile(new Uint8Array(await response.arrayBuffer()));
    expect(header.roots[0].toString()).toBe(root!.commitCid);
  });
});
