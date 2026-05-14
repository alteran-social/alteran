import { describe, expect, it } from 'bun:test';
import {
  ApplyWrites,
  CreateRecord,
  DeleteRecord,
  FIXED_DATE,
  PutRecord,
  apiContext,
  authHeader,
  blobBody,
  callRoute,
  cidWithCodec,
  issueOAuthAccess,
  json,
  listRecords,
  makeEnv,
  postRecord,
  profileRecord,
  putBlobRef,
  rawBlob,
  readRecordBlock,
} from './helpers/repo-write';

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

  it('enforces strict ATProto datetime fields for known records', async () => {
    const env = await makeEnv();
    const res = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      record: postRecord('loose datetime', {
        createdAt: '2024-01-01T00:00:00',
      }),
    });

    expect(res.status).toBe(400);
    expect((await json(res)).error).toBe('InvalidRequest');
  });

  it('normalizes missing type and rejects mismatched types and rkeys', async () => {
    const env = await makeEnv();

    const missingType = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      record: { text: 'missing type', createdAt: FIXED_DATE },
    });
    expect(missingType.status).toBe(200);
    const missingTypeBody = await json(missingType);
    const missingTypeStored = await readRecordBlock(env, missingTypeBody.cid);
    expect(missingTypeStored.$type).toBe('app.bsky.feed.post');

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
    await env.ALTERAN_BLOBS.put(`blobs/by-cid/${blob.cid}`, blobBody(new TextEncoder().encode('blob')), {
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

  it('rejects forbidden object keys at the raw record boundary', async () => {
    const env = await makeEnv();
    const record = JSON.parse('{"$type":"com.example.record","__proto__":{"polluted":true}}');

    const res = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'com.example.record',
      rkey: 'forbidden-key',
      validate: false,
      record,
    });

    expect(res.status).toBe(400);
    expect((await json(res)).error).toBe('InvalidRequest');
  });

  it('enforces lexicon blob accept and maxSize constraints', async () => {
    const env = await makeEnv();
    const gifBlob = await rawBlob(new TextEncoder().encode('gif-ish'));
    const gifKey = `blobs/by-cid/${gifBlob.cid}`;
    await env.ALTERAN_BLOBS.put(gifKey, blobBody(new TextEncoder().encode('gif-ish')), {
      httpMetadata: { contentType: 'image/gif' },
    });
    await putBlobRef(env, String(env.PDS_DID), gifBlob.cid, gifKey, 'image/gif', gifBlob.size);

    const wrongMime = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.actor.profile',
      rkey: 'self',
      record: profileRecord({
        avatar: { ...gifBlob.object, mimeType: 'image/gif' },
      }),
    });
    expect(wrongMime.status).toBe(400);
    expect((await json(wrongMime)).error).toBe('InvalidMimeType');

    const largeBytes = new Uint8Array(1_000_001);
    const largeBlob = await rawBlob(largeBytes);
    const largeKey = `blobs/by-cid/${largeBlob.cid}`;
    await env.ALTERAN_BLOBS.put(largeKey, blobBody(largeBytes), {
      httpMetadata: { contentType: 'image/png' },
    });
    await putBlobRef(env, String(env.PDS_DID), largeBlob.cid, largeKey, 'image/png', largeBlob.size);

    const tooLarge = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.actor.profile',
      rkey: 'self',
      record: profileRecord({ avatar: largeBlob.object }),
    });
    expect(tooLarge.status).toBe(413);
    expect((await json(tooLarge)).error).toBe('BlobTooLarge');
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

});
