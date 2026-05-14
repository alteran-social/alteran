import { describe, expect, it } from 'bun:test';
import {
  CreateRecord,
  DeleteRecord,
  GetBlob,
  ListBlobs,
  RepoManager,
  UploadBlob,
  apiContext,
  authHeader,
  blobBody,
  callGetRoute,
  callRoute,
  getBlobQuota,
  json,
  listRecords,
  makeEnv,
  postRecord,
  putBlobRef,
  rawBlob,
  setAccountActive,
  updateBlobQuota,
} from './helpers/repo-write';

describe('repo write blobs', () => {
  it('returns canonical metadata for duplicate uploads', async () => {
    const env = await makeEnv();
    const bytes = new TextEncoder().encode('duplicate upload');

    const first = await UploadBlob.POST(apiContext(env, new Request(
      'https://pds.example/xrpc/com.atproto.repo.uploadBlob',
      {
        method: 'POST',
        headers: {
          'content-type': 'image/png',
          ...(await authHeader(env)),
        },
        body: blobBody(bytes),
      },
    )));
    expect(first.status).toBe(200);
    const firstBody = await json(first);
    expect(firstBody.blob.mimeType).toBe('image/png');

    const second = await UploadBlob.POST(apiContext(env, new Request(
      'https://pds.example/xrpc/com.atproto.repo.uploadBlob',
      {
        method: 'POST',
        headers: {
          'content-type': 'image/jpeg',
          ...(await authHeader(env)),
        },
        body: blobBody(bytes),
      },
    )));
    expect(second.status).toBe(200);
    expect(await json(second)).toEqual(firstBody);

    const quota = await getBlobQuota(env, String(env.PDS_DID));
    expect(quota.total_bytes).toBe(bytes.byteLength);
    expect(quota.blob_count).toBe(1);
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

    await env2.ALTERAN_BLOBS.put(`blobs/by-cid/${blob.cid}`, blobBody(new TextEncoder().encode('blob')), {
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
    await env2.ALTERAN_BLOBS.put(`blobs/by-cid/${emptyBlob.cid}`, blobBody(new Uint8Array()), {
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
    await env.ALTERAN_BLOBS.put(key, blobBody(blobBytes), {
      httpMetadata: { contentType: blob.mimeType },
    });
    await putBlobRef(env, String(env.PDS_DID), blob.cid, key, blob.mimeType, blob.size);

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
    } finally {
      (env as any).ALTERAN_DB = originalDb;
    }
  });

  it('exposes only committed blobs and hides dereferenced recent blobs', async () => {
    const env = await makeEnv();
    const blobBytes = new TextEncoder().encode('visible after commit');
    const blob = await rawBlob(blobBytes);
    const key = `blobs/by-cid/${blob.cid}`;
    await env.ALTERAN_BLOBS.put(key, blobBody(blobBytes), {
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
    expect((await json(getWrongDid)).error).toBe('RepoNotFound');
    await putBlobRef(env, 'did:example:other', blob.cid, key, blob.mimeType, blob.size);
    const otherList = await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=did:example:other`,
    );
    expect(otherList.status).toBe(400);
    expect((await json(otherList)).error).toBe('RepoNotFound');

    await setAccountActive(env, String(env.PDS_DID), false);
    const getInactive = await callGetRoute(
      GetBlob,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${env.PDS_DID}&cid=${blob.cid}`,
    );
    expect(getInactive.status).toBe(400);
    const listInactive = await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${env.PDS_DID}`,
    );
    expect(listInactive.status).toBe(400);
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
    await env.ALTERAN_BLOBS.put(key, blobBody(blobBytes), {
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

});
