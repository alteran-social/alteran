import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import * as dagCbor from '@ipld/dag-cbor';
import {
  ApplyWrites,
  CreateRecord,
  DeleteRecord,
  FIXED_DATE,
  PutRecord,
  UploadBlob,
  apiContext,
  callRoute,
  issueOAuthAccess,
  json,
  listRecords,
  makeEnv,
  profileRecord,
  readRecordBlock,
} from './helpers/repo-write';

const COLLECTION = 'academy.rawkode.tartan.signature';
const SCOPE = `atproto repo:${COLLECTION}?action=create repo:${COLLECTION}?action=delete`;
const URL_BASE = 'https://pds.example/xrpc';

type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

function signatureRecord(seed: number) {
  const digest = new Uint8Array(32).fill(seed);
  return {
    json: {
      $type: COLLECTION,
      namespace: 'git',
      algorithm: 'sha256',
      digest: { $bytes: btoa(String.fromCharCode(...digest)) },
      createdAt: FIXED_DATE,
    },
    ipld: {
      $type: COLLECTION,
      namespace: 'git',
      algorithm: 'sha256',
      digest,
      createdAt: FIXED_DATE,
    },
  };
}

async function expectedCid(ipld: unknown): Promise<string> {
  return CID.createV1(dagCbor.code, await sha256.digest(dagCbor.encode(ipld))).toString();
}

async function scopedCall(
  route: { POST: (ctx: any) => Promise<Response> },
  env: TestEnv,
  body: unknown,
  scope = SCOPE,
) {
  return callRoute(route, env, body, String(env.PDS_DID), await issueOAuthAccess(env, scope, URL_BASE), URL_BASE);
}

describe('granular repo scope for an unknown collection', () => {
  it('creates a record through createRecord', async () => {
    const env = await makeEnv();
    const res = await scopedCall(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: COLLECTION,
      record: signatureRecord(1).json,
    });
    expect(res.status).toBe(200);
    expect((await json(res)).validationStatus).toBe('unknown');
  });

  it('creates a full 200-record batch through applyWrites on default limits', async () => {
    const env = await makeEnv();
    const writes = Array.from({ length: 200 }, (_, index) => ({
      $type: 'com.atproto.repo.applyWrites#create',
      collection: COLLECTION,
      rkey: `signature-${index}`,
      value: { ...signatureRecord(index).json, subject: `commit-${index}-${'f'.repeat(40)}` },
    }));
    expect(JSON.stringify({ writes }).length).toBeGreaterThan(64 * 1024);
    const res = await scopedCall(ApplyWrites, env, { repo: env.PDS_DID, writes });
    expect(res.status).toBe(200);
    expect((await json(res)).results.length).toBe(200);
  });

  it('deletes a record through deleteRecord', async () => {
    const env = await makeEnv();
    const created = await json(await scopedCall(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: COLLECTION,
      record: signatureRecord(2).json,
    }));
    const rkey = String(created.uri).split('/').pop();
    const res = await scopedCall(DeleteRecord, env, { repo: env.PDS_DID, collection: COLLECTION, rkey });
    expect(res.status).toBe(200);
    expect((await listRecords(env)).length).toBe(0);
  });

  it('deletes a record through applyWrites', async () => {
    const env = await makeEnv();
    const created = await json(await scopedCall(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: COLLECTION,
      record: signatureRecord(3).json,
    }));
    const rkey = String(created.uri).split('/').pop();
    const res = await scopedCall(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [{ $type: 'com.atproto.repo.applyWrites#delete', collection: COLLECTION, rkey }],
    });
    expect(res.status).toBe(200);
    expect((await listRecords(env)).length).toBe(0);
  });

  it('refuses to update a record in the granted collection', async () => {
    const env = await makeEnv();
    const res = await scopedCall(PutRecord, env, {
      repo: env.PDS_DID,
      collection: COLLECTION,
      rkey: 'self',
      record: signatureRecord(4).json,
    });
    expect(res.status).toBe(403);
  });

  it('refuses an applyWrites update in the granted collection', async () => {
    const env = await makeEnv();
    const res = await scopedCall(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [{
        $type: 'com.atproto.repo.applyWrites#update',
        collection: COLLECTION,
        rkey: 'self',
        value: signatureRecord(5).json,
      }],
    });
    expect(res.status).toBe(403);
  });

  it('refuses to create a record in another collection', async () => {
    const env = await makeEnv();
    const res = await scopedCall(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.actor.profile',
      rkey: 'self',
      record: profileRecord(),
    });
    expect(res.status).toBe(403);
  });

  it('refuses a batch that mixes the granted collection with another one', async () => {
    const env = await makeEnv();
    const res = await scopedCall(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [
        { $type: 'com.atproto.repo.applyWrites#create', collection: COLLECTION, value: signatureRecord(6).json },
        { $type: 'com.atproto.repo.applyWrites#create', collection: 'app.bsky.actor.profile', rkey: 'self', value: profileRecord() },
      ],
    });
    expect(res.status).toBe(403);
    expect((await listRecords(env)).length).toBe(0);
  });

  it('refuses to upload a blob', async () => {
    const env = await makeEnv();
    const headers = await issueOAuthAccess(env, SCOPE, `${URL_BASE}/com.atproto.repo.uploadBlob`);
    const res = await UploadBlob.POST(apiContext(env, new Request(`${URL_BASE}/com.atproto.repo.uploadBlob`, {
      method: 'POST',
      headers: { ...headers, 'content-type': 'image/png' },
      body: new Uint8Array([1, 2, 3]),
    })));
    expect(res.status).toBe(403);
  });
});

describe('record block encoding', () => {
  it('stores $bytes as a DAG-CBOR byte string under the canonical record CID', async () => {
    const env = await makeEnv();
    const record = signatureRecord(7);
    const created = await json(await scopedCall(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: COLLECTION,
      record: record.json,
    }));
    expect(created.cid).toBe(await expectedCid(record.ipld));
    const block = await readRecordBlock(env, created.cid);
    expect(block.digest).toBeInstanceOf(Uint8Array);
    expect(Array.from(block.digest as Uint8Array)).toEqual(Array.from(record.ipld.digest));
  });

  it('stores applyWrites $bytes values under the canonical record CID', async () => {
    const env = await makeEnv();
    const record = signatureRecord(8);
    const applied = await json(await scopedCall(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [{ $type: 'com.atproto.repo.applyWrites#create', collection: COLLECTION, value: record.json }],
    }));
    expect(applied.results[0].cid).toBe(await expectedCid(record.ipld));
  });
});
