import { describe, expect, it } from 'bun:test';
import {
  CreateRecord,
  GetBlob,
  ListBlobs,
  PutRecord,
  WRONG_CID,
  blobBody,
  callGetRoute,
  callRoute,
  getBlobQuota,
  json,
  makeEnv,
  postRecord,
  putBlobRef,
  rawBlob,
  registerBlobRefWithQuota,
  sweepEligibleUnreferencedBlobKeys,
  updateBlobQuota,
} from './helpers/repo-write';

async function storeBlob(env: Awaited<ReturnType<typeof makeEnv>>, text: string) {
  const bytes = new TextEncoder().encode(text);
  const blob = await rawBlob(bytes);
  const key = `blobs/by-cid/${blob.cid}`;
  await env.ALTERAN_BLOBS.put(key, blobBody(bytes), {
    httpMetadata: { contentType: blob.mimeType },
  });
  await putBlobRef(env, String(env.PDS_DID), blob.cid, key, blob.mimeType, blob.size);
  return { blob, key };
}

function postWithImage(text: string, blob: Awaited<ReturnType<typeof rawBlob>>) {
  return postRecord(text, {
    embed: {
      $type: 'app.bsky.embed.images',
      images: [{ image: blob.object, alt: '' }],
    },
  });
}

describe('sync blob endpoints', () => {
  it('lists current blob refs changed after a repo revision', async () => {
    const env = await makeEnv();
    const firstBlob = await storeBlob(env, 'first since blob');
    const secondBlob = await storeBlob(env, 'second since blob');
    const thirdBlob = await storeBlob(env, 'third since blob');

    const first = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2j',
      record: postWithImage('first', firstBlob.blob),
    });
    expect(first.status).toBe(200);
    const firstRev = (await json(first)).commit.rev;

    const second = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2k',
      record: postWithImage('second', secondBlob.blob),
    });
    expect(second.status).toBe(200);

    const third = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2l',
      record: postWithImage('third', thirdBlob.blob),
    });
    expect(third.status).toBe(200);
    const thirdRev = (await json(third)).commit.rev;

    const sinceFirst = await json(await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${env.PDS_DID}&since=${firstRev}`,
    ));
    const expected = [secondBlob.blob.cid, thirdBlob.blob.cid].sort();
    expect(sinceFirst.cids).toEqual(expected);

    const afterCursor = await json(await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${env.PDS_DID}&since=${firstRev}&cursor=${expected[0]}`,
    ));
    expect(afterCursor.cids).toEqual([expected[1]]);

    const sinceHead = await json(await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${env.PDS_DID}&since=${thirdRev}`,
    ));
    expect(sinceHead).toEqual({ cids: [] });

    const future = await json(await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${env.PDS_DID}&since=4zzzzzzzzzzzz`,
    ));
    expect(future).toEqual({ cids: [] });
  });

  it('lists a reverted current blob when the record changed after since', async () => {
    const env = await makeEnv();
    const firstBlob = await storeBlob(env, 'revert first');
    const secondBlob = await storeBlob(env, 'revert second');

    const created = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2m',
      record: postWithImage('first', firstBlob.blob),
    });
    expect(created.status).toBe(200);
    const createdRev = (await json(created)).commit.rev;

    const updated = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2m',
      record: postWithImage('second', secondBlob.blob),
    });
    expect(updated.status).toBe(200);

    const reverted = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2m',
      record: postWithImage('first again', firstBlob.blob),
    });
    expect(reverted.status).toBe(200);

    const listed = await json(await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${env.PDS_DID}&since=${createdRev}`,
    ));
    expect(listed).toEqual({ cids: [firstBlob.blob.cid], cursor: firstBlob.blob.cid });
  });

  it('keeps listBlobs visible and returns BlobNotFound when the R2 object is missing', async () => {
    const env = await makeEnv();
    const { blob, key } = await storeBlob(env, 'missing object');
    const created = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2n',
      record: postWithImage('missing object', blob),
    });
    expect(created.status).toBe(200);

    await env.ALTERAN_BLOBS.delete(key);

    const listed = await json(await callGetRoute(
      ListBlobs,
      env,
      `https://pds.example/xrpc/com.atproto.sync.listBlobs?did=${env.PDS_DID}`,
    ));
    expect(listed).toEqual({ cids: [blob.cid], cursor: blob.cid });

    const fetched = await callGetRoute(
      GetBlob,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${env.PDS_DID}&cid=${blob.cid}`,
    );
    expect(fetched.status).toBe(400);
    expect((await json(fetched)).error).toBe('BlobNotFound');
  });

  it('validates sync blob parameters before storage lookup', async () => {
    const env = await makeEnv();

    const missingDid = await callGetRoute(
      GetBlob,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlob?cid=${WRONG_CID}`,
    );
    expect(missingDid.status).toBe(400);
    expect((await json(missingDid)).error).toBe('InvalidRequest');

    const invalidCid = await callGetRoute(
      GetBlob,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${env.PDS_DID}&cid=not-a-cid`,
    );
    expect(invalidCid.status).toBe(400);
    expect((await json(invalidCid)).error).toBe('InvalidRequest');

    const missingListDid = await callGetRoute(
      ListBlobs,
      env,
      'https://pds.example/xrpc/com.atproto.sync.listBlobs',
    );
    expect(missingListDid.status).toBe(400);
    expect((await json(missingListDid)).error).toBe('InvalidRequest');
  });

  it('does not double count duplicate blob registrations against quota', async () => {
    const env = await makeEnv({ PDS_BLOB_QUOTA_BYTES: '10' });
    const first = await rawBlob(new TextEncoder().encode('same'));
    const key = `blobs/by-cid/${first.cid}`;

    const registered = await registerBlobRefWithQuota(
      env,
      String(env.PDS_DID),
      first.cid,
      key,
      first.mimeType,
      first.size,
    );
    expect(registered.tag).toBe('registered');
    if (registered.tag !== 'registered') throw new Error('expected blob registration');
    expect(registered.blob.mime).toBe(first.mimeType);

    const duplicate = await registerBlobRefWithQuota(
      env,
      String(env.PDS_DID),
      first.cid,
      key,
      first.mimeType,
      first.size,
    );
    expect(duplicate.tag).toBe('alreadyExists');
    if (duplicate.tag !== 'alreadyExists') throw new Error('expected duplicate blob');
    expect(duplicate.blob.cid).toBe(first.cid);
    let quota = await getBlobQuota(env, String(env.PDS_DID));
    expect(quota.total_bytes).toBe(first.size);
    expect(quota.blob_count).toBe(1);

    const second = await rawBlob(new TextEncoder().encode('too large'));
    expect(await registerBlobRefWithQuota(
      env,
      String(env.PDS_DID),
      second.cid,
      `blobs/by-cid/${second.cid}`,
      second.mimeType,
      second.size,
    )).toEqual({ tag: 'quotaExceeded' });
    quota = await getBlobQuota(env, String(env.PDS_DID));
    expect(quota.total_bytes).toBe(first.size);
    expect(quota.blob_count).toBe(1);
  });

  it('does not sweep metadata for recently written object storage', async () => {
    const env = await makeEnv();
    const { blob, key } = await storeBlob(env, 'aged orphan');
    await updateBlobQuota(env, String(env.PDS_DID), blob.size, 1);
    await env.ALTERAN_DB.prepare(
      'UPDATE blob SET uploaded_at = ? WHERE did = ? AND key = ?',
    ).bind(Date.now() - 2 * 60 * 60 * 1000, env.PDS_DID, key).run();

    expect(await sweepEligibleUnreferencedBlobKeys(env, {
      did: String(env.PDS_DID),
      limit: 10,
    })).toBe(0);
    expect(await env.ALTERAN_DB.prepare(
      'SELECT 1 FROM blob WHERE did = ? AND key = ? LIMIT 1',
    ).bind(env.PDS_DID, key).first()).not.toBeNull();
    expect(await env.ALTERAN_BLOBS.head(key)).not.toBeNull();
    const quota = await getBlobQuota(env, String(env.PDS_DID));
    expect(quota.total_bytes).toBe(blob.size);
    expect(quota.blob_count).toBe(1);
  });

  it('sweeps aged unreferenced blob metadata when object storage is already gone', async () => {
    const env = await makeEnv();
    const { blob, key } = await storeBlob(env, 'missing aged orphan');
    await updateBlobQuota(env, String(env.PDS_DID), blob.size, 1);
    await env.ALTERAN_BLOBS.delete(key);
    await env.ALTERAN_DB.prepare(
      'UPDATE blob SET uploaded_at = ? WHERE did = ? AND key = ?',
    ).bind(Date.now() - 2 * 60 * 60 * 1000, env.PDS_DID, key).run();

    expect(await sweepEligibleUnreferencedBlobKeys(env, {
      did: String(env.PDS_DID),
      limit: 10,
    })).toBe(1);
    expect(await env.ALTERAN_DB.prepare(
      'SELECT 1 FROM blob WHERE did = ? AND key = ? LIMIT 1',
    ).bind(env.PDS_DID, key).first()).toBeNull();
    expect(await env.ALTERAN_BLOBS.head(key)).toBeNull();
    const quota = await getBlobQuota(env, String(env.PDS_DID));
    expect(quota.total_bytes).toBe(0);
    expect(quota.blob_count).toBe(0);
  });
});
