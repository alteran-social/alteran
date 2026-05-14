import { expect } from "@std/expect";
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import * as dagCbor from '@ipld/dag-cbor';
import { makeEnv } from './env';
import { issueSessionTokens } from '../../src/lib/session-tokens';
import { makeDpopKey, signResourceDpop } from './oauth';
import { createOAuthSession, storeRefreshToken } from '../../src/db/account';
import {
  getBlobQuota,
  listRecords,
  putBlobRef,
  registerBlobRefWithQuota,
  setAccountActive,
  sweepEligibleUnreferencedBlobKeys,
  updateBlobQuota,
} from '../../src/db/dal';
import * as CreateRecord from '../../src/pages/xrpc/com.atproto.repo.createRecord';
import * as PutRecord from '../../src/pages/xrpc/com.atproto.repo.putRecord';
import * as DeleteRecord from '../../src/pages/xrpc/com.atproto.repo.deleteRecord';
import * as ApplyWrites from '../../src/pages/xrpc/com.atproto.repo.applyWrites';
import * as UploadBlob from '../../src/pages/xrpc/com.atproto.repo.uploadBlob';
import * as GetBlob from '../../src/pages/xrpc/com.atproto.sync.getBlob';
import * as ListBlobs from '../../src/pages/xrpc/com.atproto.sync.listBlobs';
import { RepoManager } from '../../src/services/repo-manager';

const FIXED_DATE = '2026-05-13T00:00:00.000Z';
const WRONG_CID = 'bafkreigh2akiscaildc4q7fapfs3krvmxz2s5tapqyqdr6fhyjn4zpd6du';

function apiContext(env: Awaited<ReturnType<typeof makeEnv>>, request: Request) {
  return { locals: { runtime: { env } }, request } as any;
}

function apiGetContext(env: Awaited<ReturnType<typeof makeEnv>>, request: Request) {
  return { locals: { runtime: { env } }, request, url: new URL(request.url) } as any;
}

async function authHeader(env: Awaited<ReturnType<typeof makeEnv>>, did = String(env.PDS_DID)) {
  const { accessJwt } = await issueSessionTokens(env, did);
  return { authorization: `Bearer ${accessJwt}` };
}

async function issueOAuthAccess(
  env: Awaited<ReturnType<typeof makeEnv>>,
  scope: string,
  url: string,
) {
  const key = await makeDpopKey();
  const sessionId = crypto.randomUUID().replace(/-/g, '');
  const accessJti = crypto.randomUUID().replace(/-/g, '');
  const { accessJwt, refreshPayload, refreshExpiry, accessPayload } = await issueSessionTokens(
    env,
    String(env.PDS_DID),
    {
      accessScope: scope,
      clientId: 'https://client.example/metadata',
      dpopJkt: key.jkt,
      oauthSessionId: sessionId,
      accessJti,
    },
  );
  await createOAuthSession(env, {
    id: sessionId,
    did: String(env.PDS_DID),
    clientId: 'https://client.example/metadata',
    clientAuthMethod: 'none',
    clientAuthKeyId: null,
    dpopJkt: key.jkt,
    scope,
    currentRefreshTokenId: refreshPayload.jti,
    accessJti: String(accessPayload.jti),
    expiresAt: refreshExpiry,
  });
  await storeRefreshToken(env, {
    id: refreshPayload.jti,
    did: String(env.PDS_DID),
    expiresAt: refreshExpiry,
    tokenKind: 'oauth',
    oauthSessionId: sessionId,
    clientId: 'https://client.example/metadata',
    clientAuthMethod: 'none',
    dpopJkt: key.jkt,
    oauthScope: scope,
    accessJti: String(accessPayload.jti),
  });
  return {
    authorization: `DPoP ${accessJwt}`,
    dpop: await signResourceDpop(env, key, 'POST', url, accessJwt),
  };
}

function postRecord(text = 'hello', extra: Record<string, unknown> = {}) {
  return {
    $type: 'app.bsky.feed.post',
    text,
    createdAt: FIXED_DATE,
    ...extra,
  };
}

function profileRecord(extra: Record<string, unknown> = {}) {
  return {
    $type: 'app.bsky.actor.profile',
    displayName: 'Tester',
    ...extra,
  };
}

async function callRoute(
  route: { POST: (ctx: any) => Promise<Response> },
  env: Awaited<ReturnType<typeof makeEnv>>,
  body: unknown,
  did = String(env.PDS_DID),
  headers?: Record<string, string>,
  url = 'https://pds.example/xrpc',
) {
  const request = new Request(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(headers ?? await authHeader(env, did)),
    },
    body: JSON.stringify(body),
  });
  return route.POST(apiContext(env, request));
}

async function json(res: Response) {
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

async function callGetRoute(
  route: { GET: (ctx: any) => Promise<Response> },
  env: Awaited<ReturnType<typeof makeEnv>>,
  url: string,
) {
  const request = new Request(url, { method: 'GET' });
  return route.GET(apiGetContext(env, request));
}

async function readRecordBlock(env: Awaited<ReturnType<typeof makeEnv>>, cid: string) {
  const row = await env.ALTERAN_DB.prepare(
    'SELECT bytes FROM blockstore WHERE cid = ? LIMIT 1',
  ).bind(cid).first<{ bytes: string }>();
  expect(row?.bytes).toBeTruthy();
  const bytes = Uint8Array.from(atob(row!.bytes), (char) => char.charCodeAt(0));
  return dagCbor.decode(bytes) as Record<string, any>;
}

async function createPost(env: Awaited<ReturnType<typeof makeEnv>>, body: Record<string, unknown> = {}) {
  const res = await callRoute(CreateRecord, env, {
    repo: env.PDS_DID,
    collection: 'app.bsky.feed.post',
    record: postRecord(),
    ...body,
  });
  expect(res.status).toBe(200);
  return json(res);
}

async function rawBlob(bytes = new TextEncoder().encode('blob')) {
  const digest = await sha256.digest(bytes);
  const cid = CID.createV1(0x55, digest).toString();
  return {
    cid,
    size: bytes.byteLength,
    mimeType: 'image/png',
    object: {
      $type: 'blob',
      ref: { $link: cid },
      mimeType: 'image/png',
      size: bytes.byteLength,
    },
  };
}

function blobBody(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function cidWithCodec(codec: number) {
  const digest = await sha256.digest(new TextEncoder().encode(`codec:${codec}`));
  return CID.createV1(codec, digest).toString();
}

export {
  ApplyWrites,
  CreateRecord,
  DeleteRecord,
  FIXED_DATE,
  GetBlob,
  ListBlobs,
  PutRecord,
  RepoManager,
  UploadBlob,
  WRONG_CID,
  apiContext,
  apiGetContext,
  authHeader,
  blobBody,
  callGetRoute,
  callRoute,
  cidWithCodec,
  createPost,
  getBlobQuota,
  issueOAuthAccess,
  json,
  listRecords,
  makeEnv,
  postRecord,
  profileRecord,
  putBlobRef,
  rawBlob,
  readRecordBlock,
  registerBlobRefWithQuota,
  setAccountActive,
  sweepEligibleUnreferencedBlobKeys,
  updateBlobQuota,
};
