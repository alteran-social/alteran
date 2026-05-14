/**
 * Repository Import Tests
 * Tests for com.atproto.repo.importRepo endpoint
 */

import { describe, test, expect, beforeEach } from 'bun:test';
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';
import { sha256 } from 'multiformats/hashes/sha2';
import { parseCarFile } from '../src/lib/car-reader';
import { AuthScope } from '../src/lib/auth-scope';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { createOAuthSession, storeRefreshToken } from '../src/db/account';
import { putBlobRef } from '../src/db/dal';
import { MST, type ReadableBlockstore } from '../src/lib/mst';
import { createCommit, signCommit, serializeCommit, commitCid } from '../src/lib/commit';
import { encodeRecordBlock } from '../src/services/repo/blockstore-ops';
import { encodeBlocksToCAR, encodeExistingBlocksToCAR } from '../src/services/car';
import { Secp256k1Keypair } from '@atproto/crypto';
import * as ImportRepo from '../src/pages/xrpc/com.atproto.repo.importRepo';
import * as ListMissingBlobs from '../src/pages/xrpc/com.atproto.repo.listMissingBlobs';
import { makeDpopKey, signResourceDpop } from './helpers/oauth';
import { makeEnv } from './helpers/env';

const FIXED_DATE = '2026-05-13T00:00:00.000Z';
const IMPORT_URL = 'https://pds.example/xrpc/com.atproto.repo.importRepo';

type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function makeImportEnv(overrides: Partial<TestEnv> = {}): Promise<TestEnv> {
  const keypair = await Secp256k1Keypair.create({ exportable: true });
  const privateKey = bytesToHex(await keypair.export());
  return makeEnv({ REPO_SIGNING_KEY: privateKey, ...overrides } as Partial<TestEnv>);
}

class TestBlockstore implements ReadableBlockstore {
  constructor(private readonly blocks: Map<string, Uint8Array>) {}

  async get(cid: CID): Promise<Uint8Array | null> {
    return this.blocks.get(cid.toString()) ?? null;
  }

  async has(cid: CID): Promise<boolean> {
    return this.blocks.has(cid.toString());
  }

  async getMany(cids: CID[]): Promise<{ blocks: Map<string, Uint8Array>; missing: CID[] }> {
    const blocks = new Map<string, Uint8Array>();
    const missing: CID[] = [];
    for (const cid of cids) {
      const bytes = await this.get(cid);
      if (bytes) {
        blocks.set(cid.toString(), bytes);
      } else {
        missing.push(cid);
      }
    }
    return { blocks, missing };
  }

  async readObj<T>(cid: CID): Promise<T> {
    const bytes = await this.get(cid);
    if (!bytes) throw new Error(`missing block ${cid.toString()}`);
    return dagCbor.decode(bytes) as T;
  }
}

function apiContext(env: TestEnv, request: Request) {
  return { locals: { runtime: { env } }, request } as any;
}

function apiGetContext(env: TestEnv, request: Request) {
  return { locals: { runtime: { env } }, request, url: new URL(request.url) } as any;
}

async function authHeader(env: TestEnv, did = String(env.PDS_DID), scope: AuthScope = AuthScope.Access) {
  const { accessJwt } = await issueSessionTokens(env, did, { scope });
  return { authorization: `Bearer ${accessJwt}` };
}

async function issueOAuthAccess(env: TestEnv, scope: string) {
  const key = await makeDpopKey();
  const sessionId = crypto.randomUUID().replace(/-/g, '');
  const accessJti = crypto.randomUUID().replace(/-/g, '');
  const { accessJwt, refreshPayload, refreshExpiry, accessPayload } = await issueSessionTokens(
    env,
    String(env.PDS_DID),
    {
      scope,
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
    dpop: await signResourceDpop(env, key, 'POST', IMPORT_URL, accessJwt),
  };
}

async function json(res: Response) {
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

function postRecord(text = 'imported', extra: Record<string, unknown> = {}) {
  return {
    $type: 'app.bsky.feed.post',
    text,
    createdAt: FIXED_DATE,
    ...extra,
  };
}

async function rawBlob(bytes = new TextEncoder().encode('blob')) {
  const digest = await sha256.digest(bytes);
  const cid = CID.createV1(0x55, digest).toString();
  return {
    cid,
    bytes,
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

async function encodeDagCborBlock(value: unknown) {
  const bytes = dagCbor.encode(value);
  const hash = await sha256.digest(bytes);
  return { cid: CID.createV1(dagCbor.code, hash), bytes };
}

async function countRows(
  env: TestEnv,
  table: 'repo_root' | 'record' | 'blob_usage' | 'commit_log' | 'blockstore',
) {
  const row = await env.ALTERAN_DB.prepare(
    `SELECT COUNT(*) AS count FROM ${table}`,
  ).first<{ count: number }>();
  return Number(row?.count ?? 0);
}

async function makeImportCar(
  env: TestEnv,
  options: {
    did?: string;
    rev?: string;
    records?: Array<{ path: string; record: Record<string, unknown> }>;
    prev?: CID | null;
    roots?: CID[];
    sign?: boolean;
  } = {},
) {
  const did = options.did ?? String(env.PDS_DID);
  const rev = options.rev ?? '3jzfcijpj2z2a';
  const records = options.records ?? [{
    path: 'app.bsky.feed.post/3jzfcijpj2z2b',
    record: postRecord(),
  }];
  const recordBlocks: Array<{ path: string; cid: CID; bytes: Uint8Array; record: Record<string, unknown> }> = [];
  const blockMap = new Map<string, Uint8Array>();

  for (const record of records) {
    const encoded = await encodeRecordBlock(record.record);
    recordBlocks.push({ ...record, cid: encoded.cid, bytes: encoded.bytes });
    blockMap.set(encoded.cid.toString(), encoded.bytes);
  }

  let mst = await MST.create(new TestBlockstore(blockMap), []);
  for (const record of [...recordBlocks].sort((a, b) => a.path.localeCompare(b.path))) {
    mst = await mst.add(record.path, record.cid);
  }
  const mstRoot = await mst.getPointer();
  const mstBlocks = Array.from((await mst.getUnstoredBlocks()).blocks, ([cid, bytes]) => ({ cid, bytes }));

  const unsignedCommit = createCommit(did, mstRoot, rev, options.prev ?? null);
  const signedCommit = options.sign === false
    ? { ...unsignedCommit, sig: new Uint8Array(64) }
    : await signCommit(unsignedCommit, String(env.REPO_SIGNING_KEY));
  const commitBytes = serializeCommit(signedCommit);
  const commitCidValue = await commitCid(signedCommit);
  const blocks = [
    { cid: commitCidValue, bytes: commitBytes },
    ...mstBlocks,
    ...recordBlocks.map(({ cid, bytes }) => ({ cid, bytes })),
  ];

  return {
    bytes: encodeExistingBlocksToCAR(options.roots ?? [commitCidValue], blocks),
    blocks,
    commitCid: commitCidValue,
    mstRoot,
    records: recordBlocks,
  };
}

async function makeNonCanonicalMstCar(env: TestEnv) {
  const pathA = 'app.bsky.feed.post/3jzfcijpj2z2b';
  const pathB = 'app.bsky.feed.post/3jzfcijpj2z2c';
  const recordA = await encodeRecordBlock(postRecord('a'));
  const recordB = await encodeRecordBlock(postRecord('b'));
  const node = await encodeDagCborBlock({
    l: null,
    e: [
      { p: 0, k: new TextEncoder().encode(pathB), v: recordB.cid, t: null },
      { p: 0, k: new TextEncoder().encode(pathA), v: recordA.cid, t: null },
    ],
  });
  const unsignedCommit = createCommit(String(env.PDS_DID), node.cid, '3jzfcijpj2z2a', null);
  const signedCommit = await signCommit(unsignedCommit, String(env.REPO_SIGNING_KEY));
  const commitBytes = serializeCommit(signedCommit);
  const commitCidValue = await commitCid(signedCommit);
  const blocks = [
    { cid: commitCidValue, bytes: commitBytes },
    node,
    { cid: recordA.cid, bytes: recordA.bytes },
    { cid: recordB.cid, bytes: recordB.bytes },
  ];
  return {
    bytes: encodeExistingBlocksToCAR([commitCidValue], blocks),
    blocks,
    commitCid: commitCidValue,
  };
}

async function importRepo(
  env: TestEnv,
  body: Uint8Array,
  headers: Record<string, string> = {},
) {
  const request = new Request(IMPORT_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/vnd.ipld.car',
      'content-length': String(body.byteLength),
      ...(await authHeader(env)),
      ...headers,
    },
    body,
  });
  return ImportRepo.POST(apiContext(env, request));
}

async function listMissing(env: TestEnv) {
  const request = new Request('https://pds.example/xrpc/com.atproto.repo.listMissingBlobs', {
    method: 'GET',
    headers: await authHeader(env),
  });
  return ListMissingBlobs.GET(apiGetContext(env, request));
}

describe('Repository Import', () => {
  describe('CAR File Parsing', () => {
    test('should parse CAR with commit and MST structure', async () => {
      // Create a simple MST structure
      const record1 = { $type: 'app.bsky.feed.post', text: 'Hello' };
      const record1Bytes = dagCbor.encode(record1);
      const record1Hash = await sha256.digest(record1Bytes);
      const record1Cid = CID.createV1(dagCbor.code, record1Hash);

      const record2 = { $type: 'app.bsky.feed.post', text: 'World' };
      const record2Bytes = dagCbor.encode(record2);
      const record2Hash = await sha256.digest(record2Bytes);
      const record2Cid = CID.createV1(dagCbor.code, record2Hash);

      // Create MST node
      const mstNode = {
        l: null,
        e: [
          {
            p: 0,
            k: new Uint8Array([0x61]), // 'a'
            v: record1Cid,
            t: null,
          },
          {
            p: 0,
            k: new Uint8Array([0x62]), // 'b'
            v: record2Cid,
            t: null,
          },
        ],
      };
      const mstBytes = dagCbor.encode(mstNode);
      const mstHash = await sha256.digest(mstBytes);
      const mstCid = CID.createV1(dagCbor.code, mstHash);

      // Create commit
      const commit = {
        did: 'did:plc:test',
        version: 3,
        data: mstCid,
        rev: '3l4example',
        prev: null,
        sig: new Uint8Array(64), // Mock signature
      };
      const commitBytes = dagCbor.encode(commit);
      const commitHash = await sha256.digest(commitBytes);
      const commitCid = CID.createV1(dagCbor.code, commitHash);

      // Build CAR
      const blocks = [
        { cid: commitCid, bytes: commitBytes },
        { cid: mstCid, bytes: mstBytes },
        { cid: record1Cid, bytes: record1Bytes },
        { cid: record2Cid, bytes: record2Bytes },
      ];
      const carBytes = encodeBlocksToCAR(commitCid, blocks);

      // Parse CAR
      const { header, blocks: parsedBlocks } = parseCarFile(carBytes);

      expect(header.version).toBe(1);
      expect(header.roots).toHaveLength(1);
      expect(header.roots[0].toString()).toBe(commitCid.toString());
      expect(parsedBlocks).toHaveLength(4);

      // Verify commit block
      const parsedCommit = parsedBlocks.find(b => b.cid.equals(commitCid));
      expect(parsedCommit).toBeDefined();
      const decodedCommit = dagCbor.decode(parsedCommit!.bytes);
      expect(decodedCommit).toMatchObject({
        did: 'did:plc:test',
        version: 3,
      });

      // Verify MST block
      const parsedMst = parsedBlocks.find(b => b.cid.equals(mstCid));
      expect(parsedMst).toBeDefined();
      const decodedMst = dagCbor.decode(parsedMst!.bytes) as any;
      expect(decodedMst.e).toHaveLength(2);

      // Verify record blocks
      const parsedRecord1 = parsedBlocks.find(b => b.cid.equals(record1Cid));
      expect(parsedRecord1).toBeDefined();
      const decodedRecord1 = dagCbor.decode(parsedRecord1!.bytes);
      expect(decodedRecord1).toEqual(record1);
    });

    test('should handle nested MST structure', async () => {
      // Create leaf records
      const record1 = { $type: 'app.bsky.feed.post', text: 'A' };
      const record1Bytes = dagCbor.encode(record1);
      const record1Hash = await sha256.digest(record1Bytes);
      const record1Cid = CID.createV1(dagCbor.code, record1Hash);

      const record2 = { $type: 'app.bsky.feed.post', text: 'B' };
      const record2Bytes = dagCbor.encode(record2);
      const record2Hash = await sha256.digest(record2Bytes);
      const record2Cid = CID.createV1(dagCbor.code, record2Hash);

      // Create child MST node
      const childMst = {
        l: null,
        e: [
          {
            p: 0,
            k: new Uint8Array([0x62]), // 'b'
            v: record2Cid,
            t: null,
          },
        ],
      };
      const childMstBytes = dagCbor.encode(childMst);
      const childMstHash = await sha256.digest(childMstBytes);
      const childMstCid = CID.createV1(dagCbor.code, childMstHash);

      // Create parent MST node with left subtree
      const parentMst = {
        l: childMstCid,
        e: [
          {
            p: 0,
            k: new Uint8Array([0x61]), // 'a'
            v: record1Cid,
            t: null,
          },
        ],
      };
      const parentMstBytes = dagCbor.encode(parentMst);
      const parentMstHash = await sha256.digest(parentMstBytes);
      const parentMstCid = CID.createV1(dagCbor.code, parentMstHash);

      // Create commit
      const commit = {
        did: 'did:plc:test',
        version: 3,
        data: parentMstCid,
        rev: '3l4example',
        prev: null,
        sig: new Uint8Array(64),
      };
      const commitBytes = dagCbor.encode(commit);
      const commitHash = await sha256.digest(commitBytes);
      const commitCid = CID.createV1(dagCbor.code, commitHash);

      // Build CAR with nested structure
      const blocks = [
        { cid: commitCid, bytes: commitBytes },
        { cid: parentMstCid, bytes: parentMstBytes },
        { cid: childMstCid, bytes: childMstBytes },
        { cid: record1Cid, bytes: record1Bytes },
        { cid: record2Cid, bytes: record2Bytes },
      ];
      const carBytes = encodeBlocksToCAR(commitCid, blocks);

      // Parse CAR
      const { blocks: parsedBlocks } = parseCarFile(carBytes);

      expect(parsedBlocks).toHaveLength(5);

      // Verify parent MST has left subtree reference
      const parsedParentMst = parsedBlocks.find(b => b.cid.equals(parentMstCid));
      expect(parsedParentMst).toBeDefined();
      const decodedParentMst = dagCbor.decode(parsedParentMst!.bytes) as any;
      expect(decodedParentMst.l).toBeDefined();
      expect(decodedParentMst.l.toString()).toBe(childMstCid.toString());
    });

    test('should handle MST with right subtrees', async () => {
      // Create records
      const record1 = { $type: 'app.bsky.feed.post', text: 'First' };
      const record1Bytes = dagCbor.encode(record1);
      const record1Hash = await sha256.digest(record1Bytes);
      const record1Cid = CID.createV1(dagCbor.code, record1Hash);

      const record2 = { $type: 'app.bsky.feed.post', text: 'Second' };
      const record2Bytes = dagCbor.encode(record2);
      const record2Hash = await sha256.digest(record2Bytes);
      const record2Cid = CID.createV1(dagCbor.code, record2Hash);

      // Create right subtree
      const rightMst = {
        l: null,
        e: [
          {
            p: 0,
            k: new Uint8Array([0x63]), // 'c'
            v: record2Cid,
            t: null,
          },
        ],
      };
      const rightMstBytes = dagCbor.encode(rightMst);
      const rightMstHash = await sha256.digest(rightMstBytes);
      const rightMstCid = CID.createV1(dagCbor.code, rightMstHash);

      // Create parent MST with entry having right subtree
      const parentMst = {
        l: null,
        e: [
          {
            p: 0,
            k: new Uint8Array([0x61]), // 'a'
            v: record1Cid,
            t: rightMstCid, // Right subtree
          },
        ],
      };
      const parentMstBytes = dagCbor.encode(parentMst);
      const parentMstHash = await sha256.digest(parentMstBytes);
      const parentMstCid = CID.createV1(dagCbor.code, parentMstHash);

      // Create commit
      const commit = {
        did: 'did:plc:test',
        version: 3,
        data: parentMstCid,
        rev: '3l4example',
        prev: null,
        sig: new Uint8Array(64),
      };
      const commitBytes = dagCbor.encode(commit);
      const commitHash = await sha256.digest(commitBytes);
      const commitCid = CID.createV1(dagCbor.code, commitHash);

      // Build CAR
      const blocks = [
        { cid: commitCid, bytes: commitBytes },
        { cid: parentMstCid, bytes: parentMstBytes },
        { cid: rightMstCid, bytes: rightMstBytes },
        { cid: record1Cid, bytes: record1Bytes },
        { cid: record2Cid, bytes: record2Bytes },
      ];
      const carBytes = encodeBlocksToCAR(commitCid, blocks);

      // Parse CAR
      const { blocks: parsedBlocks } = parseCarFile(carBytes);

      expect(parsedBlocks).toHaveLength(5);

      // Verify parent MST entry has right subtree
      const parsedParentMst = parsedBlocks.find(b => b.cid.equals(parentMstCid));
      expect(parsedParentMst).toBeDefined();
      const decodedParentMst = dagCbor.decode(parsedParentMst!.bytes) as any;
      expect(decodedParentMst.e[0].t).toBeDefined();
      expect(decodedParentMst.e[0].t.toString()).toBe(rightMstCid.toString());
    });
  });

  describe('Block Storage Logic', () => {
    test('should identify commit block from CAR root', async () => {
      const commit = {
        did: 'did:plc:test',
        version: 3,
        data: CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua'),
        rev: '3l4example',
        prev: null,
        sig: new Uint8Array(64),
      };
      const commitBytes = dagCbor.encode(commit);
      const commitHash = await sha256.digest(commitBytes);
      const commitCid = CID.createV1(dagCbor.code, commitHash);

      const blocks = [{ cid: commitCid, bytes: commitBytes }];
      const carBytes = encodeBlocksToCAR(commitCid, blocks);

      const { header, blocks: parsedBlocks } = parseCarFile(carBytes);

      expect(header.roots[0].toString()).toBe(commitCid.toString());
      expect(parsedBlocks[0].cid.toString()).toBe(commitCid.toString());

      const decoded = dagCbor.decode(parsedBlocks[0].bytes) as any;
      expect(decoded.did).toBe('did:plc:test');
      expect(decoded.data).toBeDefined();
    });

    test('should extract MST root CID from commit', async () => {
      const mstCid = CID.parse('bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua');
      const commit = {
        did: 'did:plc:test',
        version: 3,
        data: mstCid,
        rev: '3l4example',
        prev: null,
        sig: new Uint8Array(64),
      };
      const commitBytes = dagCbor.encode(commit);

      const decoded = dagCbor.decode(commitBytes) as any;
      expect(decoded.data.toString()).toBe(mstCid.toString());
    });

    test('should count records correctly', async () => {
      // Create multiple records
      const records = [
        { $type: 'app.bsky.feed.post', text: 'Post 1' },
        { $type: 'app.bsky.feed.post', text: 'Post 2' },
        { $type: 'app.bsky.feed.like', subject: 'at://did:plc:test/app.bsky.feed.post/123' },
      ];

      let recordCount = 0;
      for (const record of records) {
        const bytes = dagCbor.encode(record);
        const decoded = dagCbor.decode(bytes) as any;
        if (decoded && typeof decoded === 'object' && decoded.$type) {
          recordCount++;
        }
      }

      expect(recordCount).toBe(3);
    });
  });

  describe('Error Handling', () => {
    test('should reject CAR with no blocks', () => {
      const emptyCarBytes = new Uint8Array([
        0x0a, // varint: header length = 10
        0xa2, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x01, // CBOR: {version: 1}
        0x65, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x80, // CBOR: roots: []
      ]);

      expect(() => parseCarFile(emptyCarBytes)).toThrow();
    });

    test('should reject commit without data CID', () => {
      const invalidCommit = {
        did: 'did:plc:test',
        version: 3,
        // Missing 'data' field
        rev: '3l4example',
        prev: null,
        sig: new Uint8Array(64),
      };

      const bytes = dagCbor.encode(invalidCommit);
      const decoded = dagCbor.decode(bytes) as any;

      expect(decoded.data).toBeUndefined();
    });
  });

  describe('com.atproto.repo.importRepo endpoint', () => {
    test('imports a valid CAR, indexes records, and links already uploaded blobs', async () => {
      const env = await makeImportEnv();
      const blob = await rawBlob(new TextEncoder().encode('indexed import blob'));
      const key = `blobs/by-cid/${blob.cid}`;
      await env.ALTERAN_BLOBS.put(key, blob.bytes, {
        httpMetadata: { contentType: blob.mimeType },
      });
      await putBlobRef(env, String(env.PDS_DID), blob.cid, key, blob.mimeType, blob.size);

      const car = await makeImportCar(env, {
        records: [{
          path: 'app.bsky.feed.post/3jzfcijpj2z2b',
          record: postRecord('with blob', {
            embed: {
              $type: 'app.bsky.embed.images',
              images: [{ image: blob.object, alt: '' }],
            },
          }),
        }],
      });
      const extra = await encodeDagCborBlock({ unused: true });
      const carWithExtra = encodeExistingBlocksToCAR(
        [car.commitCid],
        [...car.blocks, extra],
      );

      const res = await importRepo(env, carWithExtra);
      expect(res.status).toBe(200);

      const root = await env.ALTERAN_DB.prepare(
        'SELECT commit_cid, rev FROM repo_root WHERE did = ? LIMIT 1',
      ).bind(env.PDS_DID).first<{ commit_cid: string; rev: string }>();
      expect(root).toEqual({
        commit_cid: car.commitCid.toString(),
        rev: '3jzfcijpj2z2a',
      });

      const uri = `at://${env.PDS_DID}/app.bsky.feed.post/3jzfcijpj2z2b`;
      const record = await env.ALTERAN_DB.prepare(
        'SELECT cid, json FROM record WHERE uri = ? LIMIT 1',
      ).bind(uri).first<{ cid: string; json: string }>();
      expect(record?.cid).toBe(car.records[0].cid.toString());
      expect(JSON.parse(record!.json)).toMatchObject({
        $type: 'app.bsky.feed.post',
        text: 'with blob',
      });

      const usage = await env.ALTERAN_DB.prepare(
        `SELECT key, record_cid, commit_cid, commit_rev
         FROM blob_usage
         WHERE did = ? AND record_uri = ? LIMIT 1`,
      ).bind(env.PDS_DID, uri).first<{
        key: string;
        record_cid: string;
        commit_cid: string;
        commit_rev: string;
      }>();
      expect(usage).toEqual({
        key,
        record_cid: car.records[0].cid.toString(),
        commit_cid: car.commitCid.toString(),
        commit_rev: '3jzfcijpj2z2a',
      });
      const blobRow = await env.ALTERAN_DB.prepare(
        'SELECT state FROM blob WHERE did = ? AND cid = ? LIMIT 1',
      ).bind(env.PDS_DID, blob.cid).first<{ state: string }>();
      expect(blobRow?.state).toBe('permanent');
      const extraBlock = await env.ALTERAN_DB.prepare(
        'SELECT 1 FROM blockstore WHERE cid = ? LIMIT 1',
      ).bind(extra.cid.toString()).first();
      expect(extraBlock).toBeNull();
    });

    test('rejects CARs with no root and tolerates additional roots', async () => {
      const env = await makeImportEnv();
      const car = await makeImportCar(env);
      const noRoots = encodeExistingBlocksToCAR([], car.blocks);

      const res = await importRepo(env, noRoots);
      expect(res.status).toBe(400);
      expect((await json(res)).error).toBe('InvalidRequest');

      const withExtraRoot = encodeExistingBlocksToCAR([car.commitCid, car.mstRoot], car.blocks);
      const imported = await importRepo(env, withExtraRoot);
      expect(imported.status).toBe(200);
    });

    test('rejects invalid CAR bytes', async () => {
      const env = await makeImportEnv();
      const res = await importRepo(env, new Uint8Array([0, 1, 2, 3]));

      expect(res.status).toBe(400);
      expect((await json(res)).error).toBe('InvalidRequest');
    });

    test('rejects commits with invalid signatures', async () => {
      const env = await makeImportEnv();
      const car = await makeImportCar(env, { sign: false });

      const res = await importRepo(env, car.bytes);
      expect(res.status).toBe(400);
      expect((await json(res)).error).toBe('InvalidRequest');
    });

    test('verifies did:web commit signatures with the current DID document key', async () => {
      const did = 'did:web:example.com';
      const env = await makeImportEnv({ PDS_DID: did });
      const keypair = await Secp256k1Keypair.import(String(env.REPO_SIGNING_KEY));
      const publicKeyMultibase = keypair.did().slice('did:key:'.length);
      const originalFetch = globalThis.fetch;
      globalThis.fetch = (async (input: RequestInfo | URL) => {
        const url = input instanceof Request ? input.url : String(input);
        expect(url).toBe('https://example.com/.well-known/did.json');
        return new Response(JSON.stringify({
          id: did,
          verificationMethod: [{
            id: `${did}#atproto`,
            type: 'Multikey',
            controller: did,
            publicKeyMultibase,
          }],
        }), { headers: { 'content-type': 'application/json' } });
      }) as unknown as typeof fetch;
      try {
        const car = await makeImportCar(env);
        const res = await importRepo(env, car.bytes);
        expect(res.status).toBe(200);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    test('does not fall back to the local signing key for invalid network DID documents', async () => {
      const did = 'did:web:example.com';
      const env = await makeImportEnv({ PDS_DID: did });
      const keypair = await Secp256k1Keypair.import(String(env.REPO_SIGNING_KEY));
      const publicKeyMultibase = keypair.did().slice('did:key:'.length);
      const originalFetch = globalThis.fetch;
      globalThis.fetch = (async () =>
        new Response(JSON.stringify({
          id: did,
          verificationMethod: [{
            id: `${did}#atproto`,
            type: 'Multikey',
            controller: 'did:web:attacker.example',
            publicKeyMultibase,
          }],
        }), { headers: { 'content-type': 'application/json' } })) as unknown as typeof fetch;
      try {
        const car = await makeImportCar(env);
        const res = await importRepo(env, car.bytes);
        expect(res.status).toBe(400);
        expect((await json(res)).error).toBe('InvalidRequest');
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    test('rejects commits with non-compliant prev CIDs', async () => {
      const env = await makeImportEnv();
      const rawHash = await sha256.digest(new TextEncoder().encode('bad previous commit CID'));
      const rawPrev = CID.createV1(0x55, rawHash);
      const car = await makeImportCar(env, { prev: rawPrev });

      const res = await importRepo(env, car.bytes);
      expect(res.status).toBe(400);
      expect((await json(res)).error).toBe('InvalidRequest');
    });

    test('rejects non-canonical MSTs before applying state', async () => {
      const env = await makeImportEnv();
      const car = await makeNonCanonicalMstCar(env);

      const res = await importRepo(env, car.bytes);
      expect(res.status).toBe(400);
      expect((await json(res)).error).toBe('InvalidRequest');
      expect(await countRows(env, 'repo_root')).toBe(0);
      expect(await countRows(env, 'record')).toBe(0);
      expect(await countRows(env, 'commit_log')).toBe(0);
      expect(await countRows(env, 'blockstore')).toBe(0);
    });

    test('rejects malformed record blocks', async () => {
      const env = await makeImportEnv();
      const car = await makeImportCar(env, {
        records: [{
          path: 'app.bsky.feed.post/3jzfcijpj2z2b',
          record: { text: 'missing type', createdAt: FIXED_DATE },
        }],
      });

      const res = await importRepo(env, car.bytes);
      expect(res.status).toBe(400);
      expect((await json(res)).error).toBe('InvalidRequest');
    });

    test('rejects unauthenticated and non-owner imports', async () => {
      const env = await makeImportEnv();
      const car = await makeImportCar(env);

      const unauthenticated = await ImportRepo.POST(apiContext(env, new Request(IMPORT_URL, {
        method: 'POST',
        headers: {
          'content-type': 'application/vnd.ipld.car',
          'content-length': String(car.bytes.byteLength),
        },
        body: car.bytes,
      })));
      expect(unauthenticated.status).toBe(401);

      const appPassword = await importRepo(env, car.bytes, await authHeader(
        env,
        String(env.PDS_DID),
        AuthScope.AppPass,
      ));
      expect(appPassword.status).toBe(401);
      expect((await json(appPassword)).error).toBe('InvalidToken');
    });

    test('allows OAuth account repo manage but rejects read-only account repo scope', async () => {
      const allowedEnv = await makeImportEnv();
      const allowedCar = await makeImportCar(allowedEnv);
      const allowedHeaders = await issueOAuthAccess(
        allowedEnv,
        'atproto account:repo?action=manage',
      );
      const allowed = await importRepo(allowedEnv, allowedCar.bytes, allowedHeaders);
      expect(allowed.status).toBe(200);

      const deniedEnv = await makeImportEnv();
      const deniedCar = await makeImportCar(deniedEnv);
      const deniedHeaders = await issueOAuthAccess(
        deniedEnv,
        'atproto account:repo',
      );
      const denied = await importRepo(deniedEnv, deniedCar.bytes, deniedHeaders);
      expect(denied.status).toBe(401);
      expect((await json(denied)).error).toBe('InvalidToken');
    });

    test('rejects imports for a non-local DID', async () => {
      const env = await makeImportEnv();
      const car = await makeImportCar(env, { did: 'did:example:other' });

      const res = await importRepo(env, car.bytes);
      expect(res.status).toBe(400);
      expect((await json(res)).error).toBe('InvalidRequest');
    });

    test('reports missing imported blobs with record context', async () => {
      const env = await makeImportEnv();
      const missing = await rawBlob(new TextEncoder().encode('missing import blob'));
      const rkey = '3jzfcijpj2z2b';
      const car = await makeImportCar(env, {
        records: [{
          path: `app.bsky.feed.post/${rkey}`,
          record: postRecord('missing blob', {
            embed: {
              $type: 'app.bsky.embed.images',
              images: [{ image: missing.object, alt: '' }],
            },
          }),
        }],
      });

      const imported = await importRepo(env, car.bytes);
      expect(imported.status).toBe(200);

      const listed = await listMissing(env);
      expect(listed.status).toBe(200);
      expect(await json(listed)).toEqual({
        blobs: [{
          $type: 'com.atproto.repo.listMissingBlobs#recordBlob',
          cid: missing.cid,
          recordUri: `at://${env.PDS_DID}/app.bsky.feed.post/${rkey}`,
        }],
      });
    });

    test('imports legacy blob records and reports missing blob context', async () => {
      const env = await makeImportEnv();
      const missing = await rawBlob(new TextEncoder().encode('missing legacy import blob'));
      const rkey = '3jzfcijpj2z2b';
      const car = await makeImportCar(env, {
        records: [{
          path: `app.bsky.feed.post/${rkey}`,
          record: postRecord('legacy missing blob', {
            embed: {
              $type: 'app.bsky.embed.images',
              images: [{
                image: { cid: missing.cid, mimeType: missing.mimeType },
                alt: '',
              }],
            },
          }),
        }],
      });

      const imported = await importRepo(env, car.bytes);
      expect(imported.status).toBe(200);

      const listed = await listMissing(env);
      expect(listed.status).toBe(200);
      expect(await json(listed)).toEqual({
        blobs: [{
          $type: 'com.atproto.repo.listMissingBlobs#recordBlob',
          cid: missing.cid,
          recordUri: `at://${env.PDS_DID}/app.bsky.feed.post/${rkey}`,
        }],
      });
    });

    test('rolls back all imported state when the apply batch fails', async () => {
      const env = await makeImportEnv();
      const car = await makeImportCar(env);
      await env.ALTERAN_DB.prepare(
        'CREATE UNIQUE INDEX commit_log_cid_unique_test ON commit_log(cid)',
      ).run();
      await env.ALTERAN_DB.prepare(
        'INSERT INTO commit_log (cid, rev, data, sig, ts) VALUES (?, ?, ?, ?, ?)',
      ).bind(car.commitCid.toString(), '3jzfcijpj2z2z', '{}', '', Date.now()).run();
      const beforeCommitLog = await countRows(env, 'commit_log');

      const res = await importRepo(env, car.bytes);
      expect(res.status).toBe(500);
      expect(await countRows(env, 'repo_root')).toBe(0);
      expect(await countRows(env, 'record')).toBe(0);
      expect(await countRows(env, 'blob_usage')).toBe(0);
      expect(await countRows(env, 'commit_log')).toBe(beforeCommitLog);
      expect(await countRows(env, 'blockstore')).toBe(0);
    });

    test('requires Content-Length and checks it against the body size', async () => {
      const env = await makeImportEnv();
      const car = await makeImportCar(env);

      const missingLength = await ImportRepo.POST(apiContext(env, new Request(IMPORT_URL, {
        method: 'POST',
        headers: {
          'content-type': 'application/vnd.ipld.car',
          ...(await authHeader(env)),
        },
        body: car.bytes,
      })));
      expect(missingLength.status).toBe(400);
      expect((await json(missingLength)).error).toBe('InvalidRequest');

      const mismatchedLength = await importRepo(env, car.bytes, {
        'content-length': String(car.bytes.byteLength + 1),
      });
      expect(mismatchedLength.status).toBe(400);
      expect((await json(mismatchedLength)).error).toBe('InvalidRequest');
    });
  });
});
