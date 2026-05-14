import { describe, expect, it } from 'bun:test';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import * as dagCbor from '@ipld/dag-cbor';
import { makeEnv } from './helpers/env';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { makeDpopKey, signResourceDpop } from './helpers/oauth';
import { createOAuthSession, storeRefreshToken } from '../src/db/account';
import { getBlobQuota, putBlobRef, listRecords, putRecordStatements, setAccountActive, updateBlobQuota } from '../src/db/dal';
import * as CreateRecord from '../src/pages/xrpc/com.atproto.repo.createRecord';
import * as PutRecord from '../src/pages/xrpc/com.atproto.repo.putRecord';
import * as DeleteRecord from '../src/pages/xrpc/com.atproto.repo.deleteRecord';
import * as ApplyWrites from '../src/pages/xrpc/com.atproto.repo.applyWrites';
import * as GetBlob from '../src/pages/xrpc/com.atproto.sync.getBlob';
import * as ListBlobs from '../src/pages/xrpc/com.atproto.sync.listBlobs';
import { RepoManager } from '../src/services/repo-manager';
import { D1Blockstore, MST } from '../src/lib/mst';
import { bumpRoot } from '../src/db/repo';
import { collectMstBlocks, encodeRecordBlock } from '../src/services/repo/blockstore-ops';

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

async function countRows(
  env: Awaited<ReturnType<typeof makeEnv>>,
  table: 'repo_root' | 'record' | 'blob_usage' | 'commit_log' | 'blockstore',
) {
  const row = await env.ALTERAN_DB.prepare(
    `SELECT COUNT(*) AS count FROM ${table}`,
  ).first<{ count: number }>();
  return Number(row?.count ?? 0);
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

async function cidWithCodec(codec: number) {
  const digest = await sha256.digest(new TextEncoder().encode(`codec:${codec}`));
  return CID.createV1(codec, digest).toString();
}

describe('repo write validation', () => {
  it('rejects non-local repo values for all write routes', async () => {
    const env = await makeEnv();
    const cases = [
      [CreateRecord, {
        repo: 'did:example:remote',
        collection: 'app.bsky.feed.post',
        record: postRecord(),
      }],
      [PutRecord, {
        repo: 'did:example:remote',
        collection: 'app.bsky.feed.post',
        rkey: '3m2biurz7cl27',
        record: postRecord(),
      }],
      [DeleteRecord, {
        repo: 'did:example:remote',
        collection: 'app.bsky.feed.post',
        rkey: '3m2biurz7cl27',
      }],
      [ApplyWrites, {
        repo: 'did:example:remote',
        writes: [{
          $type: 'com.atproto.repo.applyWrites#create',
          collection: 'app.bsky.feed.post',
          value: postRecord(),
        }],
      }],
    ] as const;

    for (const [route, body] of cases) {
      const res = await callRoute(route, env, body);
      expect(res.status).toBe(400);
      expect((await json(res)).error).toBe('InvalidRequest');
    }
  });

  it('rejects authenticated DIDs that do not own the local repo', async () => {
    const env = await makeEnv();
    const res = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      record: postRecord(),
    }, 'did:example:someone-else');

    expect(res.status).toBe(400);
    expect((await json(res)).error).toBe('InvalidRequest');
  });

  it('accepts the configured handle case-insensitively as the repo identifier', async () => {
    const env = await makeEnv();
    const res = await callRoute(CreateRecord, env, {
      repo: 'TEST.EXAMPLE',
      collection: 'app.bsky.feed.post',
      record: postRecord('by handle'),
    });

    expect(res.status).toBe(200);
    expect((await json(res)).uri).toMatch(/^at:\/\/did:example:test\/app\.bsky\.feed\.post\//);
  });

  it('preserves validate tri-state behavior', async () => {
    const env = await makeEnv();

    const valid = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      record: postRecord('valid'),
    });
    expect(valid.status).toBe(200);
    expect((await json(valid)).validationStatus).toBe('valid');

    const skipped = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      validate: false,
      record: { $type: 'app.bsky.feed.post' },
    });
    expect(skipped.status).toBe(200);
    expect((await json(skipped)).validationStatus).toBeUndefined();

    const unknownSkipped = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'com.example.skipped',
      rkey: 'example',
      validate: false,
      record: { $type: 'com.example.skipped', value: 'no schema' },
    });
    expect(unknownSkipped.status).toBe(200);
    expect((await json(unknownSkipped)).validationStatus).toBeUndefined();

    const knownInvalid = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      record: { $type: 'app.bsky.feed.post', createdAt: FIXED_DATE },
    });
    expect(knownInvalid.status).toBe(400);
    expect((await json(knownInvalid)).error).toBe('InvalidRequest');

    const unknownUnset = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'com.example.record',
      rkey: 'example',
      record: { $type: 'com.example.record', value: 'ok' },
    });
    expect(unknownUnset.status).toBe(200);
    expect((await json(unknownUnset)).validationStatus).toBe('unknown');

    const unknownRequired = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'com.example.required',
      rkey: 'example',
      validate: true,
      record: { $type: 'com.example.required', value: 'no schema' },
    });
    expect(unknownRequired.status).toBe(400);
    expect((await json(unknownRequired)).error).toBe('InvalidRequest');
  });

  it('rejects type and rkey validation failures without patching records', async () => {
    const env = await makeEnv();

    const missingType = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      record: { text: 'missing type', createdAt: FIXED_DATE },
    });
    expect(missingType.status).toBe(400);

    const typeMismatch = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      record: { $type: 'app.bsky.actor.profile', text: 'wrong', createdAt: FIXED_DATE },
    });
    expect(typeMismatch.status).toBe(400);

    const badRkey = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: 'bad/key',
      record: postRecord(),
    });
    expect(badRkey.status).toBe(400);

    const badLiteral = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.actor.profile',
      rkey: 'not-self',
      record: profileRecord(),
    });
    expect(badLiteral.status).toBe(400);
  });

  it('validates raw data-model protocol wrapper objects', async () => {
    const env = await makeEnv();
    const validLink = await cidWithCodec(0x71);
    const blob = await rawBlob();
    await env.ALTERAN_BLOBS.put(`blobs/by-cid/${blob.cid}`, new TextEncoder().encode('blob'), {
      httpMetadata: { contentType: blob.mimeType },
    });
    await putBlobRef(env, String(env.PDS_DID), blob.cid, `blobs/by-cid/${blob.cid}`, 'image/png', blob.size);

    const valid = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'com.example.record',
      rkey: 'raw-valid',
      record: {
        $type: 'com.example.record',
        link: { $link: validLink },
        bytes: { $bytes: 'YWJjZA' },
        blob: blob.object,
        $unknown: 'ignored protocol extension',
      },
    });
    expect(valid.status).toBe(200);
    const validBody = await json(valid);
    expect(validBody.validationStatus).toBe('unknown');
    const stored = await readRecordBlock(env, validBody.cid);
    expect(stored.link.toString()).toBe(validLink);
    expect(stored.bytes).toBeInstanceOf(Uint8Array);
    expect(stored.blob.ref.toString()).toBe(blob.cid);

    const invalidLink = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'com.example.record',
      rkey: 'bad-link',
      record: {
        $type: 'com.example.record',
        link: { $link: await cidWithCodec(0x0129) },
      },
    });
    expect(invalidLink.status).toBe(400);
    expect((await json(invalidLink)).error).toBe('InvalidRequest');

    const invalidBytes = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'com.example.record',
      rkey: 'bad-bytes',
      record: {
        $type: 'com.example.record',
        bytes: { $bytes: 'not_url_safe-' },
      },
    });
    expect(invalidBytes.status).toBe(400);
    expect((await json(invalidBytes)).error).toBe('InvalidRequest');

    const invalidFloat = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'com.example.record',
      rkey: 'bad-float',
      record: {
        $type: 'com.example.record',
        value: 1.5,
      },
    });
    expect(invalidFloat.status).toBe(400);
    expect((await json(invalidFloat)).error).toBe('InvalidRequest');

    const legacyBlob = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'com.example.record',
      rkey: 'legacy-blob',
      validate: false,
      record: {
        $type: 'com.example.record',
        nested: { cid: validLink, mimeType: 'image/png' },
      },
    });
    expect(legacyBlob.status).toBe(400);
    expect((await json(legacyBlob)).error).toBe('InvalidRequest');
  });

  it('rejects non-JSON write request content types', async () => {
    const env = await makeEnv();
    const request = new Request('https://pds.example/xrpc/com.atproto.repo.createRecord', {
      method: 'POST',
      headers: {
        'content-type': 'text/plain',
        ...(await authHeader(env)),
      },
      body: JSON.stringify({
        repo: env.PDS_DID,
        collection: 'app.bsky.feed.post',
        record: postRecord(),
      }),
    });

    const res = await CreateRecord.POST(apiContext(env, request));
    expect(res.status).toBe(400);
    expect(res.headers.get('content-type')).toContain('application/json');
    expect((await json(res)).error).toBe('BadRequest');
  });

  it('checks route-level repo scopes before rate or account-state reads', async () => {
    const env = await makeEnv({ PDS_RATE_LIMIT_PER_MIN: '0' });
    const url = 'https://pds.example/xrpc/com.atproto.repo.applyWrites';
    const headers = await issueOAuthAccess(env, 'atproto repo:app.bsky.feed.post?action=create', url);

    const res = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [{
        $type: 'com.atproto.repo.applyWrites#delete',
        collection: 'app.bsky.feed.post',
        rkey: 'missing',
      }],
    }, String(env.PDS_DID), headers, url);

    expect(res.status).toBe(401);
    expect(res.headers.get('content-type')).toContain('application/json');
    expect((await json(res)).error).toBe('InvalidToken');
    const rateRows = await env.ALTERAN_DB.prepare('SELECT count(*) AS count FROM sqlite_master WHERE name = ?')
      .bind('rate_limit')
      .first<{ count: number }>();
    expect(rateRows?.count).toBe(0);
  });

  it('charges malformed authenticated write bodies against the DID write bucket', async () => {
    const env = await makeEnv({ PDS_RATE_LIMIT_PER_MIN: '1' });
    const malformed = new Request('https://pds.example/xrpc/com.atproto.repo.createRecord', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(await authHeader(env)),
      },
      body: '{',
    });

    const bad = await CreateRecord.POST(apiContext(env, malformed));
    expect(bad.status).toBe(400);
    expect((await json(bad)).error).toBe('BadRequest');

    const limited = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      record: postRecord('after malformed body'),
    });
    expect(limited.status).toBe(429);

    const row = await env.ALTERAN_DB.prepare(
      'SELECT count FROM rate_limit WHERE ip = ? AND bucket = ?',
    ).bind(env.PDS_DID, 'writes').first<{ count: number }>();
    expect(row?.count).toBe(1);
  });

  it('charges schema-invalid authenticated writes against the DID write bucket', async () => {
    const env = await makeEnv({ PDS_RATE_LIMIT_PER_MIN: '1' });

    const invalid = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
    });
    expect(invalid.status).toBe(400);

    const limited = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      record: postRecord('after invalid input'),
    });
    expect(limited.status).toBe(429);
  });

  it('charges applyWrites quota by operation before mutation', async () => {
    const env = await makeEnv({ PDS_RATE_LIMIT_PER_MIN: '2' });

    const res = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [
        {
          $type: 'com.atproto.repo.applyWrites#create',
          collection: 'app.bsky.feed.post',
          value: postRecord('one'),
        },
        {
          $type: 'com.atproto.repo.applyWrites#create',
          collection: 'app.bsky.feed.post',
          value: postRecord('two'),
        },
        {
          $type: 'com.atproto.repo.applyWrites#create',
          collection: 'app.bsky.feed.post',
          value: postRecord('three'),
        },
      ],
    });

    expect(res.status).toBe(429);
    expect(await listRecords(env)).toHaveLength(0);
  });

  it('enforces swapCommit and swapRecord preconditions', async () => {
    const env = await makeEnv();

    const badCommit = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      swapCommit: WRONG_CID,
      record: postRecord('bad swap'),
    });
    expect(badCommit.status).toBe(400);
    expect((await json(badCommit)).error).toBe('InvalidSwap');

    const created = await createPost(env, { rkey: '3m2biurz7cl27' });
    const badRecord = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3m2biurz7cl27',
      swapRecord: WRONG_CID,
      record: postRecord('updated'),
    });
    expect(created.cid).not.toBe(WRONG_CID);
    expect(badRecord.status).toBe(400);
    expect((await json(badRecord)).error).toBe('InvalidSwap');

    const nullCreate = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2b',
      swapRecord: null,
      record: postRecord('created by put'),
    });
    expect(nullCreate.status).toBe(200);

    const nullMismatch = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2b',
      swapRecord: null,
      record: postRecord('should fail'),
    });
    expect(nullMismatch.status).toBe(400);
    expect((await json(nullMismatch)).error).toBe('InvalidSwap');

    const noOpBadCommit = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3m2biurz7cl27',
      swapCommit: WRONG_CID,
      record: postRecord(),
    });
    expect(noOpBadCommit.status).toBe(400);
    expect((await json(noOpBadCommit)).error).toBe('InvalidSwap');

    const noOpBadRecord = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3m2biurz7cl27',
      swapRecord: WRONG_CID,
      record: postRecord(),
    });
    expect(noOpBadRecord.status).toBe(400);
    expect((await json(noOpBadRecord)).error).toBe('InvalidSwap');

    const missingDeleteBadCommit = await callRoute(DeleteRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: 'missing-record',
      swapCommit: WRONG_CID,
    });
    expect(missingDeleteBadCommit.status).toBe(400);
    expect((await json(missingDeleteBadCommit)).error).toBe('InvalidSwap');

    const missingDeleteBadRecord = await callRoute(DeleteRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: 'missing-record',
      swapRecord: WRONG_CID,
    });
    expect(missingDeleteBadRecord.status).toBe(400);
    expect((await json(missingDeleteBadRecord)).error).toBe('InvalidSwap');
  });

  it('retries no-swap repo-head conflicts without losing writes', async () => {
    const env = await makeEnv();
    await createPost(env, { rkey: '3m2biurz7cl27' });

    const originalDb = env.ALTERAN_DB;
    const originalBatch = originalDb.batch.bind(originalDb);
    const wrappedDb = Object.create(originalDb);
    let failNextRootBatch = true;
    let rootBatchAttempts = 0;

    wrappedDb.batch = async (statements: unknown[]) => {
      if (statements.length > 2) {
        rootBatchAttempts++;
        if (failNextRootBatch) {
          failNextRootBatch = false;
          return [{ success: true, meta: { changes: 0 } }];
        }
      }
      return originalBatch(statements as any);
    };
    (env as any).ALTERAN_DB = wrappedDb;

    try {
      const retried = await callRoute(CreateRecord, env, {
        repo: env.PDS_DID,
        collection: 'app.bsky.feed.post',
        rkey: '3jzfcijpj2z2f',
        record: postRecord('retried create'),
      });
      expect(retried.status).toBe(200);
      expect(rootBatchAttempts).toBe(2);
      expect(await listRecords(env)).toHaveLength(2);
      const commits = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();
      expect(commits.results).toHaveLength(2);

      const head = await json(retried);
      failNextRootBatch = true;
      const explicitSwap = await callRoute(CreateRecord, env, {
        repo: env.PDS_DID,
        collection: 'app.bsky.feed.post',
        rkey: '3jzfcijpj2z2g',
        swapCommit: head.commit.cid,
        record: postRecord('explicit swap conflict'),
      });
      expect(explicitSwap.status).toBe(400);
      expect((await json(explicitSwap)).error).toBe('InvalidSwap');
      expect(rootBatchAttempts).toBe(3);
      expect(await listRecords(env)).toHaveLength(2);
    } finally {
      (env as any).ALTERAN_DB = originalDb;
    }
  });

  it('keeps staged blocks invisible when explicit swap guards fail', async () => {
    const env = await makeEnv();
    const created = await createPost(env, { rkey: '3m2biurz7cl27' });
    const beforeBlocks = await countRows(env, 'blockstore');
    const beforeCommits = await countRows(env, 'commit_log');

    const originalDb = env.ALTERAN_DB;
    const originalBatch = originalDb.batch.bind(originalDb);
    const wrappedDb = Object.create(originalDb);
    let racedRoot = false;

    wrappedDb.batch = async (statements: unknown[]) => {
      if (statements.length > 2 && !racedRoot) {
        racedRoot = true;
        await originalDb.prepare(
          'UPDATE repo_root SET commit_cid = ?, rev = ? WHERE did = ?',
        ).bind(WRONG_CID, '3m2biurz7cl29', env.PDS_DID).run();
      }
      return originalBatch(statements as any);
    };
    (env as any).ALTERAN_DB = wrappedDb;

    try {
      const stale = await callRoute(PutRecord, env, {
        repo: env.PDS_DID,
        collection: 'app.bsky.feed.post',
        rkey: '3jzfcijpj2z2b',
        swapCommit: created.commit.cid,
        record: postRecord('stale guarded write'),
      });
      expect(stale.status).toBe(400);
      expect((await json(stale)).error).toBe('InvalidSwap');
    } finally {
      (env as any).ALTERAN_DB = originalDb;
    }

    expect(await listRecords(env)).toHaveLength(1);
    expect(await countRows(env, 'commit_log')).toBe(beforeCommits);
    expect(await countRows(env, 'blockstore')).toBe(beforeBlocks);
  });

  it('blocks deactivated accounts on single-record write routes', async () => {
    const env = await makeEnv();
    await createPost(env, { rkey: '3m2biurz7cl27' });
    await setAccountActive(env, String(env.PDS_DID), false);

    const create = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      record: postRecord('blocked create'),
    });
    expect(create.status).toBe(403);
    expect((await json(create)).error).toBe('AccountDeactivated');

    const put = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3m2biurz7cl27',
      record: postRecord('blocked put'),
    });
    expect(put.status).toBe(403);
    expect((await json(put)).error).toBe('AccountDeactivated');

    const del = await callRoute(DeleteRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3m2biurz7cl27',
    });
    expect(del.status).toBe(403);
    expect((await json(del)).error).toBe('AccountDeactivated');
  });

  it('omits commit and sequenced side effects for identical putRecord writes', async () => {
    const env = await makeEnv();
    const created = await createPost(env, { rkey: '3m2biurz7cl27' });
    const before = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();

    const noOp = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3m2biurz7cl27',
      swapCommit: created.commit.cid,
      swapRecord: created.cid,
      record: postRecord(),
    });
    expect(noOp.status).toBe(200);
    const body = await json(noOp);
    expect(body.commit).toBeUndefined();

    const after = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();
    expect(after.results).toHaveLength(before.results.length);
  });

  it('omits commits for missing deleteRecord no-ops', async () => {
    const env = await makeEnv();
    await createPost(env, { rkey: '3m2biurz7cl27' });
    const before = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();

    const missing = await callRoute(DeleteRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: 'missing-record',
    });
    expect(missing.status).toBe(200);
    expect(await json(missing)).toEqual({});
    expect(await listRecords(env)).toHaveLength(1);

    const after = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();
    expect(after.results).toHaveLength(before.results.length);
  });

  it('atomically rechecks explicit swapCommit for no-op writes', async () => {
    const env = await makeEnv();
    const created = await createPost(env, { rkey: '3m2biurz7cl27' });
    const originalDb = env.ALTERAN_DB;
    const originalPrepare = originalDb.prepare.bind(originalDb);
    const wrappedDb = Object.create(originalDb);
    let failHeadCheck = true;

    wrappedDb.prepare = (sql: string) => {
      if (failHeadCheck && sql.includes('SET commit_cid = commit_cid')) {
        failHeadCheck = false;
        return {
          bind: () => ({
            run: async () => ({ success: true, meta: { changes: 0 } }),
          }),
        };
      }
      return originalPrepare(sql);
    };
    (env as any).ALTERAN_DB = wrappedDb;

    try {
      const noOp = await callRoute(PutRecord, env, {
        repo: env.PDS_DID,
        collection: 'app.bsky.feed.post',
        rkey: '3m2biurz7cl27',
        swapCommit: created.commit.cid,
        swapRecord: created.cid,
        record: postRecord(),
      });
      expect(noOp.status).toBe(400);
      expect((await json(noOp)).error).toBe('InvalidSwap');

      failHeadCheck = true;
      const missingDelete = await callRoute(DeleteRecord, env, {
        repo: env.PDS_DID,
        collection: 'app.bsky.feed.post',
        rkey: 'missing-record',
        swapCommit: created.commit.cid,
      });
      expect(missingDelete.status).toBe(400);
      expect((await json(missingDelete)).error).toBe('InvalidSwap');
    } finally {
      (env as any).ALTERAN_DB = originalDb;
    }
  });

  it('uses swapRecord intent to scope putRecord without state reads', async () => {
    const env = await makeEnv();
    const url = 'https://pds.example/xrpc/com.atproto.repo.putRecord';
    const headers = await issueOAuthAccess(env, 'atproto repo:app.bsky.feed.post?action=update', url);

    const res = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3m2biurz7cl27',
      record: postRecord(),
    }, String(env.PDS_DID), headers, url);

    expect(res.status).toBe(401);
    expect((await json(res)).error).toBe('InvalidToken');
    expect(await listRecords(env)).toHaveLength(0);

    const createHeaders = await issueOAuthAccess(env, 'atproto repo:app.bsky.feed.post?action=create', url);
    const create = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3m2biurz7cl26',
      swapRecord: null,
      record: postRecord('created by create-only put'),
    }, String(env.PDS_DID), createHeaders, url);
    expect(create.status).toBe(200);
    const created = await json(create);

    const updateHeaders = await issueOAuthAccess(env, 'atproto repo:app.bsky.feed.post?action=update', url);
    const update = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3m2biurz7cl26',
      swapRecord: created.cid,
      record: postRecord('updated by update-only put'),
    }, String(env.PDS_DID), updateHeaders, url);
    expect(update.status).toBe(200);
  });

  it('validates blob refs and tracks valid blob usage', async () => {
    const env = await makeEnv();
    const blob = await rawBlob();
    const record = postRecord('blob', {
      embed: {
        $type: 'app.bsky.embed.images',
        images: [
          { image: blob.object, alt: '' },
          { image: blob.object, alt: 'same blob again' },
        ],
      },
    });

    const missing = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      record,
    });
    expect(missing.status).toBe(400);
    expect((await json(missing)).error).toBe('BlobNotFound');

    await putBlobRef(env, String(env.PDS_DID), blob.cid, `blobs/by-cid/${blob.cid}`, 'image/png', blob.size + 1);
    const mismatch = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2c',
      record,
    });
    expect(mismatch.status).toBe(400);
    expect((await json(mismatch)).error).toBe('InvalidSize');

    const env2 = await makeEnv();
    await putBlobRef(env2, String(env2.PDS_DID), blob.cid, `blobs/by-cid/${blob.cid}`, 'image/png', blob.size);
    const staleMetadata = await callRoute(CreateRecord, env2, {
      repo: env2.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2b',
      record,
    });
    expect(staleMetadata.status).toBe(400);
    expect((await json(staleMetadata)).error).toBe('BlobNotFound');

    await env2.ALTERAN_BLOBS.put(`blobs/by-cid/${blob.cid}`, new TextEncoder().encode('blob'), {
      httpMetadata: { contentType: blob.mimeType },
    });
    const valid = await callRoute(CreateRecord, env2, {
      repo: env2.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2c',
      record,
    });
    expect(valid.status).toBe(200);
    const body = await json(valid);
    const usage = await env2.ALTERAN_DB.prepare(
      'SELECT key FROM blob_usage WHERE did = ? AND record_uri = ?',
    ).bind(env2.PDS_DID, body.uri).all<{ key: string }>();
    expect(usage.results.map((row) => row.key)).toEqual([`blobs/by-cid/${blob.cid}`]);

    const emptyBlob = await rawBlob(new Uint8Array());
    await env2.ALTERAN_BLOBS.put(`blobs/by-cid/${emptyBlob.cid}`, new Uint8Array(), {
      httpMetadata: { contentType: emptyBlob.mimeType },
    });
    await putBlobRef(env2, String(env2.PDS_DID), emptyBlob.cid, `blobs/by-cid/${emptyBlob.cid}`, 'image/png', 0);
    const zeroSize = await callRoute(CreateRecord, env2, {
      repo: env2.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2d',
      record: postRecord('empty blob', {
        embed: {
          $type: 'app.bsky.embed.images',
          images: [{ image: emptyBlob.object, alt: '' }],
        },
      }),
    });
    expect(zeroSize.status).toBe(200);
  });

  it('rejects blob writes when metadata disappears between validation and commit', async () => {
    const env = await makeEnv();
    const blobBytes = new TextEncoder().encode('raced blob');
    const blob = await rawBlob(blobBytes);
    const key = `blobs/by-cid/${blob.cid}`;
    await env.ALTERAN_BLOBS.put(key, blobBytes, {
      httpMetadata: { contentType: blob.mimeType },
    });
    await putBlobRef(env, String(env.PDS_DID), blob.cid, key, blob.mimeType, blob.size);
    const beforeBlocks = await countRows(env, 'blockstore');

    const originalDb = env.ALTERAN_DB;
    const originalBatch = originalDb.batch.bind(originalDb);
    const wrappedDb = Object.create(originalDb);
    let deletedBeforeCommit = false;

    wrappedDb.batch = async (statements: unknown[]) => {
      if (statements.length > 2 && !deletedBeforeCommit) {
        deletedBeforeCommit = true;
        await originalDb.prepare('DELETE FROM blob WHERE key = ?').bind(key).run();
        await env.ALTERAN_BLOBS.delete(key);
      }
      return originalBatch(statements as any);
    };
    (env as any).ALTERAN_DB = wrappedDb;

    try {
      const created = await callRoute(CreateRecord, env, {
        repo: env.PDS_DID,
        collection: 'app.bsky.feed.post',
        rkey: '3jzfcijpj2z2h',
        record: postRecord('with raced blob', {
          embed: {
            $type: 'app.bsky.embed.images',
            images: [{ image: blob.object, alt: '' }],
          },
        }),
      });
      expect(created.status).toBe(400);
      expect((await json(created)).error).toBe('BlobNotFound');
      expect(await listRecords(env)).toHaveLength(0);
      const usage = await env.ALTERAN_DB.prepare('SELECT key FROM blob_usage').all();
      expect(usage.results).toHaveLength(0);
      const commits = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();
      expect(commits.results).toHaveLength(0);
      expect(await countRows(env, 'blockstore')).toBe(beforeBlocks);
    } finally {
      (env as any).ALTERAN_DB = originalDb;
    }
  });

  it('exposes only committed blobs and hides dereferenced recent blobs', async () => {
    const env = await makeEnv();
    const blobBytes = new TextEncoder().encode('visible after commit');
    const blob = await rawBlob(blobBytes);
    const key = `blobs/by-cid/${blob.cid}`;
    await env.ALTERAN_BLOBS.put(key, blobBytes, {
      httpMetadata: { contentType: blob.mimeType },
    });
    await putBlobRef(env, String(env.PDS_DID), blob.cid, key, blob.mimeType, blob.size);
    await updateBlobQuota(env, String(env.PDS_DID), blob.size, 1);

    const listBefore = await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${env.PDS_DID}`,
    );
    expect(await json(listBefore)).toEqual({ cids: [] });

    const getBefore = await callGetRoute(
      GetBlob,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${env.PDS_DID}&cid=${blob.cid}`,
    );
    expect(getBefore.status).toBe(400);

    const created = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2e',
      record: postRecord('with blob', {
        embed: {
          $type: 'app.bsky.embed.images',
          images: [{ image: blob.object, alt: '' }],
        },
      }),
    });
    expect(created.status).toBe(200);

    const listCommitted = await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${env.PDS_DID}`,
    );
    expect(await json(listCommitted)).toEqual({ cids: [blob.cid], cursor: blob.cid });

    const getCommitted = await callGetRoute(
      GetBlob,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${env.PDS_DID}&cid=${blob.cid}`,
    );
    expect(getCommitted.status).toBe(200);
    expect(await getCommitted.text()).toBe('visible after commit');

    const getWrongDid = await callGetRoute(
      GetBlob,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlob?did=did:example:other&cid=${blob.cid}`,
    );
    expect(getWrongDid.status).toBe(400);
    await putBlobRef(env, 'did:example:other', blob.cid, key, blob.mimeType, blob.size);
    const otherList = await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=did:example:other`,
    );
    expect(await json(otherList)).toEqual({ cids: [] });

    await setAccountActive(env, String(env.PDS_DID), false);
    const getInactive = await callGetRoute(
      GetBlob,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${env.PDS_DID}&cid=${blob.cid}`,
    );
    expect(getInactive.status).toBe(403);
    const listInactive = await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${env.PDS_DID}`,
    );
    expect(listInactive.status).toBe(403);
    await setAccountActive(env, String(env.PDS_DID), true);

    const deleted = await callRoute(DeleteRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2e',
    });
    expect(deleted.status).toBe(200);

    const listAfter = await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${env.PDS_DID}`,
    );
    expect(await json(listAfter)).toEqual({ cids: [] });

    const getAfter = await callGetRoute(
      GetBlob,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${env.PDS_DID}&cid=${blob.cid}`,
    );
    expect(getAfter.status).toBe(400);
    expect(await env.ALTERAN_BLOBS.get(key)).not.toBeNull();
    const row = await env.ALTERAN_DB.prepare(
      'SELECT cid FROM blob WHERE did = ? AND key = ? LIMIT 1',
    ).bind(env.PDS_DID, key).first();
    expect(row).not.toBeNull();
    const quota = await getBlobQuota(env, String(env.PDS_DID));
    expect(quota.total_bytes).toBe(blob.size);
    expect(quota.blob_count).toBe(1);
  });

  it('derives blob usage for direct RepoManager writes', async () => {
    const env = await makeEnv();
    const blobBytes = new TextEncoder().encode('direct repo blob');
    const blob = await rawBlob(blobBytes);
    const key = `blobs/by-cid/${blob.cid}`;
    await env.ALTERAN_BLOBS.put(key, blobBytes, {
      httpMetadata: { contentType: blob.mimeType },
    });
    await putBlobRef(env, String(env.PDS_DID), blob.cid, key, blob.mimeType, blob.size);

    const repo = new RepoManager(env);
    await repo.createRecord(
      'app.bsky.feed.post',
      postRecord('direct with blob', {
        embed: {
          $type: 'app.bsky.embed.images',
          images: [{ image: blob.object, alt: '' }],
        },
      }),
      '3jzfcijpj2z2i',
    );

    const list = await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${env.PDS_DID}`,
    );
    expect(await json(list)).toEqual({ cids: [blob.cid], cursor: blob.cid });
  });

  it('generates omitted rkeys before createRecord validation', async () => {
    const env = await makeEnv();
    const body = await createPost(env);

    expect(body.uri).toMatch(/^at:\/\/did:example:test\/app\.bsky\.feed\.post\/[a-z2-7]{13}$/);
    expect(body.validationStatus).toBe('valid');
  });

  it('preflights applyWrites before mutation and supports generated create rkeys', async () => {
    const env = await makeEnv();

    const invalidBatch = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [
        {
          $type: 'com.atproto.repo.applyWrites#create',
          collection: 'app.bsky.feed.post',
          value: postRecord('first'),
        },
        {
          $type: 'com.atproto.repo.applyWrites#create',
          collection: 'app.bsky.feed.post',
          value: { $type: 'app.bsky.feed.post', createdAt: FIXED_DATE },
        },
      ],
    });
    expect(invalidBatch.status).toBe(400);
    expect(await listRecords(env)).toHaveLength(0);

    const validBatch = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [
        {
          $type: 'com.atproto.repo.applyWrites#create',
          collection: 'app.bsky.feed.post',
          value: postRecord('one'),
        },
        {
          $type: 'com.atproto.repo.applyWrites#create',
          collection: 'com.example.record',
          rkey: 'custom:key',
          value: { $type: 'com.example.record', text: 'two' },
        },
      ],
    });
    expect(validBatch.status).toBe(200);
    const body = await json(validBatch);
    expect(typeof body.commit.cid).toBe('string');
    expect(body.results).toHaveLength(2);
    expect(body.results[0].uri).toMatch(/^at:\/\/did:example:test\/app\.bsky\.feed\.post\/[a-z2-7]{13}$/);
    expect(body.results[1].uri).toBe('at://did:example:test/com.example.record/custom:key');
    expect(await listRecords(env)).toHaveLength(2);
    const commits = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();
    expect(commits.results).toHaveLength(1);
  });

  it('rejects oversized and missing-update applyWrites batches before mutation', async () => {
    const env = await makeEnv();
    const tooMany = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: Array.from({ length: 201 }, () => ({
        $type: 'com.atproto.repo.applyWrites#create',
        collection: 'com.example.record',
        value: { $type: 'com.example.record', value: 'x' },
      })),
    });
    expect(tooMany.status).toBe(400);
    expect((await json(tooMany)).error).toBe('InvalidRequest');
    expect(await listRecords(env)).toHaveLength(0);

    const missingUpdate = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [{
        $type: 'com.atproto.repo.applyWrites#update',
        collection: 'com.example.record',
        rkey: 'missing',
        value: { $type: 'com.example.record', value: 'x' },
      }],
    });
    expect(missingUpdate.status).toBe(400);
    expect((await json(missingUpdate)).error).toBe('InvalidRequest');
    expect(await listRecords(env)).toHaveLength(0);
  });

  it('no-ops missing applyWrites deletes while preserving result order', async () => {
    const env = await makeEnv();

    const missingOnly = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [{
        $type: 'com.atproto.repo.applyWrites#delete',
        collection: 'com.example.record',
        rkey: 'missing',
      }],
    });
    expect(missingOnly.status).toBe(200);
    const missingOnlyBody = await json(missingOnly);
    expect(missingOnlyBody).toEqual({
      results: [{ $type: 'com.atproto.repo.applyWrites#deleteResult' }],
    });
    expect(await listRecords(env)).toHaveLength(0);
    let commits = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();
    expect(commits.results).toHaveLength(0);

    const mixed = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      validate: false,
      writes: [
        {
          $type: 'com.atproto.repo.applyWrites#delete',
          collection: 'com.example.record',
          rkey: 'still-missing',
        },
        {
          $type: 'com.atproto.repo.applyWrites#create',
          collection: 'com.example.record',
          rkey: 'created',
          value: { $type: 'com.example.record', value: 'created' },
        },
      ],
    });
    expect(mixed.status).toBe(200);
    const mixedBody = await json(mixed);
    expect(typeof mixedBody.commit.cid).toBe('string');
    expect(mixedBody.results).toEqual([
      { $type: 'com.atproto.repo.applyWrites#deleteResult' },
      {
        $type: 'com.atproto.repo.applyWrites#createResult',
        uri: 'at://did:example:test/com.example.record/created',
        cid: mixedBody.results[1].cid,
      },
    ]);
    expect(await listRecords(env)).toHaveLength(1);
    commits = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();
    expect(commits.results).toHaveLength(1);
  });

  it('enforces swapCommit on no-op-only applyWrites batches', async () => {
    const env = await makeEnv();
    const created = await createPost(env, { rkey: '3m2biurz7cl27' });

    const ok = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      swapCommit: created.commit.cid,
      writes: [{
        $type: 'com.atproto.repo.applyWrites#delete',
        collection: 'app.bsky.feed.post',
        rkey: 'missing-record',
      }],
    });
    expect(ok.status).toBe(200);
    expect(await json(ok)).toEqual({
      results: [{ $type: 'com.atproto.repo.applyWrites#deleteResult' }],
    });

    const stale = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      swapCommit: WRONG_CID,
      writes: [{
        $type: 'com.atproto.repo.applyWrites#delete',
        collection: 'app.bsky.feed.post',
        rkey: 'missing-record',
      }],
    });
    expect(stale.status).toBe(400);
    expect((await json(stale)).error).toBe('InvalidSwap');
  });

  it('rolls back staged blockstore and row mutations when the commit batch fails', async () => {
    const env = await makeEnv();
    const did = String(env.PDS_DID);
    const blockstore = new D1Blockstore(env);
    const baseMst = await MST.create(blockstore, []);
    const record = postRecord('atomic batch');
    const { cid: recordCid, bytes: recordBytes } = await encodeRecordBlock(record);
    const path = 'app.bsky.feed.post/atomic-record';
    const uri = `at://${did}/${path}`;
    const nextMst = await baseMst.add(path, recordCid);
    const nextRoot = await nextMst.getPointer();
    const newMstBlocks = await collectMstBlocks(blockstore, nextMst);

    await expect(bumpRoot(env, undefined, nextRoot, {
      ops: [{ action: 'create', path, cid: recordCid }],
      newMstBlocks: Array.from(newMstBlocks),
      newRecordBlocks: [[recordCid, recordBytes]],
      sideEffectStatements: (guard) => [
        ...putRecordStatements(env, {
          uri,
          did,
          cid: recordCid.toString(),
          json: JSON.stringify(record),
        }, guard),
        env.ALTERAN_DB.prepare(
          'INSERT INTO __repo_write_atomicity_failure__ (id) VALUES (?)',
        ).bind('boom'),
      ],
    })).rejects.toThrow();

    expect(await countRows(env, 'repo_root')).toBe(0);
    expect(await countRows(env, 'record')).toBe(0);
    expect(await countRows(env, 'blob_usage')).toBe(0);
    expect(await countRows(env, 'commit_log')).toBe(0);
    expect(await countRows(env, 'blockstore')).toBe(0);
  });

  it('enforces encoded commit event size limits before visible mutation', async () => {
    const recordEnv = await makeEnv({
      PDS_MAX_JSON_BYTES: '1250000',
    });
    const oversizedRecord = await callRoute(CreateRecord, recordEnv, {
      repo: 'did:example:test',
      collection: 'com.example.large',
      rkey: 'oversized-record',
      validate: false,
      record: {
        $type: 'com.example.large',
        payload: 'x'.repeat(1_000_050),
      },
    });
    expect(oversizedRecord.status).toBe(400);
    let body = await json(oversizedRecord);
    expect(body.error).toBe('InvalidRequest');
    expect(body.message).toContain('record block exceeds');
    expect(await listRecords(recordEnv)).toHaveLength(0);
    let commits = await recordEnv.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();
    expect(commits.results).toHaveLength(0);
    expect(await countRows(recordEnv, 'blockstore')).toBe(0);

    const env = await makeEnv({ PDS_MAX_JSON_BYTES: '3200000' });
    const largePayload = 'x'.repeat(700_000);
    const oversizedCommit = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      validate: false,
      writes: [0, 1, 2].map((index) => ({
        $type: 'com.atproto.repo.applyWrites#create',
        collection: 'com.example.large',
        rkey: `large-${index}`,
        value: {
          $type: 'com.example.large',
          payload: `${index}:${largePayload}`,
        },
      })),
    });
    expect(oversizedCommit.status).toBe(400);
    body = await json(oversizedCommit);
    expect(body.error).toBe('InvalidRequest');
    expect(body.message).toContain('commit blocks exceed');
    expect(await listRecords(env)).toHaveLength(0);
    commits = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();
    expect(commits.results).toHaveLength(0);
    expect(await countRows(env, 'blockstore')).toBe(0);
  });
});
