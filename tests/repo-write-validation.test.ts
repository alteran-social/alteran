import { describe, expect, it } from 'bun:test';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import { makeEnv } from './helpers/env';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { putBlobRef, listRecords } from '../src/db/dal';
import * as CreateRecord from '../src/pages/xrpc/com.atproto.repo.createRecord';
import * as PutRecord from '../src/pages/xrpc/com.atproto.repo.putRecord';
import * as DeleteRecord from '../src/pages/xrpc/com.atproto.repo.deleteRecord';
import * as ApplyWrites from '../src/pages/xrpc/com.atproto.repo.applyWrites';

const FIXED_DATE = '2026-05-13T00:00:00.000Z';
const WRONG_CID = 'bafkreigh2akiscaildc4q7fapfs3krvmxz2s5tapqyqdr6fhyjn4zpd6du';

function apiContext(env: Awaited<ReturnType<typeof makeEnv>>, request: Request) {
  return { locals: { runtime: { env } }, request } as any;
}

async function authHeader(env: Awaited<ReturnType<typeof makeEnv>>, did = String(env.PDS_DID)) {
  const { accessJwt } = await issueSessionTokens(env, did);
  return { authorization: `Bearer ${accessJwt}` };
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
) {
  const request = new Request('https://pds.example/xrpc', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(await authHeader(env, did)),
    },
    body: JSON.stringify(body),
  });
  return route.POST(apiContext(env, request));
}

async function json(res: Response) {
  const text = await res.text();
  return text ? JSON.parse(text) : null;
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
    expect((await json(skipped)).validationStatus).toBe('unknown');

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

    const valid = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'com.example.record',
      rkey: 'raw-valid',
      record: {
        $type: 'com.example.record',
        link: { $link: validLink },
        bytes: { $bytes: 'YWJjZA' },
      },
    });
    expect(valid.status).toBe(200);

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

    await putBlobRef(env, String(env.PDS_DID), blob.cid, `blobs/by-cid/${blob.cid}`, 'image/png', blob.size + 1);
    const mismatch = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2c',
      record,
    });
    expect(mismatch.status).toBe(400);

    const env2 = await makeEnv();
    await putBlobRef(env2, String(env2.PDS_DID), blob.cid, `blobs/by-cid/${blob.cid}`, 'image/png', blob.size);
    const valid = await callRoute(CreateRecord, env2, {
      repo: env2.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2c',
      record,
    });
    expect(valid.status).toBe(200);
    const body = await json(valid);
    const usage = await env2.ALTERAN_DB.prepare(
      'SELECT key FROM blob_usage WHERE record_uri = ?',
    ).bind(body.uri).all<{ key: string }>();
    expect(usage.results.map((row) => row.key)).toEqual([`blobs/by-cid/${blob.cid}`]);
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
});
