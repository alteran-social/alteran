import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import {
  CreateRecord,
  DeleteRecord,
  GetBlob,
  PutRecord,
  WRONG_CID,
  blobBody,
  callGetRoute,
  callRoute,
  createPost,
  issueOAuthAccess,
  json,
  listRecords,
  makeEnv,
  postRecord,
  putBlobRef,
  rawBlob,
  setAccountActive,
} from './helpers/repo-write';

describe('repo write swap and retry', () => {
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

  it('does not leak blocks or side effects when explicit swap fails during commit', async () => {
    const env = await makeEnv();
    const first = await createPost(env, { rkey: '3jzfcijpj2z2j' });
    const second = await createPost(env, { rkey: '3jzfcijpj2z2k' });
    const beforeBlocks = await env.ALTERAN_DB.prepare('SELECT cid FROM blockstore').all();
    const beforeCommits = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();

    const originalDb = env.ALTERAN_DB;
    const originalBatch = originalDb.batch.bind(originalDb);
    const wrappedDb = Object.create(originalDb);
    let movedHead = false;

    wrappedDb.batch = async (statements: unknown[]) => {
      if (statements.length > 2 && !movedHead) {
        movedHead = true;
        await originalDb.prepare(
          'UPDATE repo_root SET commit_cid = ?, rev = ? WHERE did = ?',
        ).bind(first.commit.cid, first.commit.rev, env.PDS_DID).run();
      }
      return originalBatch(statements as any);
    };
    (env as any).ALTERAN_DB = wrappedDb;

    try {
      const failed = await callRoute(CreateRecord, env, {
        repo: env.PDS_DID,
        collection: 'app.bsky.feed.post',
        rkey: '3m2biurz7cl23',
        swapCommit: second.commit.cid,
        record: postRecord('should not land'),
      });
      expect(failed.status).toBe(400);
      expect((await json(failed)).error).toBe('InvalidSwap');

      const afterBlocks = await env.ALTERAN_DB.prepare('SELECT cid FROM blockstore').all();
      const afterCommits = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();
      const leakedRecord = await env.ALTERAN_DB.prepare(
        'SELECT uri FROM record WHERE uri LIKE ?',
      ).bind('%/3m2biurz7cl23').first();
      const leakedUsage = await env.ALTERAN_DB.prepare(
        'SELECT key FROM blob_usage WHERE record_uri LIKE ?',
      ).bind('%/3m2biurz7cl23').all();

      expect(afterBlocks.results).toHaveLength(beforeBlocks.results.length);
      expect(afterCommits.results).toHaveLength(beforeCommits.results.length);
      expect(leakedRecord).toBeNull();
      expect(leakedUsage.results).toHaveLength(0);
    } finally {
      (env as any).ALTERAN_DB = originalDb;
    }
  });

  it('repairs missing blob usage on no-op put retries', async () => {
    const env = await makeEnv();
    const bytes = new TextEncoder().encode('historical no-op blob');
    const blob = await rawBlob(bytes);
    const key = 'historical/non-derived-key';
    await env.ALTERAN_BLOBS.put(key, blobBody(bytes), {
      httpMetadata: { contentType: blob.mimeType },
    });
    await putBlobRef(env, String(env.PDS_DID), blob.cid, key, blob.mimeType, blob.size);
    const record = postRecord('uses historical blob', {
      embed: {
        $type: 'app.bsky.embed.images',
        images: [{ image: blob.object, alt: '' }],
      },
    });
    const created = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2m',
      record,
    });
    expect(created.status).toBe(200);
    const body = await json(created);
    await env.ALTERAN_DB.prepare(
      'DELETE FROM blob_usage WHERE did = ? AND record_uri = ?',
    ).bind(env.PDS_DID, body.uri).run();
    const beforeCommits = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();

    const retried = await callRoute(PutRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2m',
      record,
    });
    expect(retried.status).toBe(200);
    expect((await json(retried)).commit).toBeUndefined();
    const afterCommits = await env.ALTERAN_DB.prepare('SELECT cid FROM commit_log').all();
    expect(afterCommits.results).toHaveLength(beforeCommits.results.length);

    const usage = await env.ALTERAN_DB.prepare(
      'SELECT key, cid FROM blob_usage WHERE did = ? AND record_uri = ?',
    ).bind(env.PDS_DID, body.uri).all<{ key: string; cid: string }>();
    expect(usage.results).toEqual([{ key, cid: blob.cid }]);

    const getBlob = await callGetRoute(
      GetBlob,
      env,
      `https://pds.example/xrpc/com.atproto.sync.getBlob?did=${env.PDS_DID}&cid=${blob.cid}`,
    );
    expect(getBlob.status).toBe(200);
    expect(await getBlob.text()).toBe('historical no-op blob');
  });

  it('does not clear blob usage when no-op repair loses blob metadata', async () => {
    const env = await makeEnv();
    const bytes = new TextEncoder().encode('raced no-op blob');
    const blob = await rawBlob(bytes);
    const key = 'historical/raced-no-op-key';
    await env.ALTERAN_BLOBS.put(key, blobBody(bytes), {
      httpMetadata: { contentType: blob.mimeType },
    });
    await putBlobRef(env, String(env.PDS_DID), blob.cid, key, blob.mimeType, blob.size);
    const record = postRecord('uses raced blob', {
      embed: {
        $type: 'app.bsky.embed.images',
        images: [{ image: blob.object, alt: '' }],
      },
    });
    const created = await callRoute(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: 'app.bsky.feed.post',
      rkey: '3jzfcijpj2z2n',
      record,
    });
    expect(created.status).toBe(200);
    const body = await json(created);

    const originalDatabase = env.ALTERAN_DB;
    const originalBatch = originalDatabase.batch.bind(originalDatabase);
    const wrappedDatabase = Object.create(originalDatabase);
    let batchCount = 0;
    wrappedDatabase.batch = async (statements: unknown[]) => {
      batchCount++;
      if (batchCount === 2) {
        await originalDatabase.prepare(
          'DELETE FROM blob WHERE did = ? AND key = ?',
        ).bind(env.PDS_DID, key).run();
        await env.ALTERAN_BLOBS.delete(key);
      }
      return originalBatch(statements as any);
    };
    (env as any).ALTERAN_DB = wrappedDatabase;

    try {
      const retried = await callRoute(PutRecord, env, {
        repo: env.PDS_DID,
        collection: 'app.bsky.feed.post',
        rkey: '3jzfcijpj2z2n',
        record,
      });
      expect(retried.status).toBe(400);
      expect((await json(retried)).error).toBe('BlobNotFound');

      const usage = await originalDatabase.prepare(
        'SELECT key, cid FROM blob_usage WHERE did = ? AND record_uri = ?',
      ).bind(env.PDS_DID, body.uri).all<{ key: string; cid: string }>();
      expect(usage.results).toEqual([{ key, cid: blob.cid }]);
    } finally {
      (env as any).ALTERAN_DB = originalDatabase;
    }
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

  it('atomically rechecks explicit swapCommit for no-op writes', async () => {
    const env = await makeEnv();
    const created = await createPost(env, { rkey: '3m2biurz7cl27' });
    const originalDb = env.ALTERAN_DB;
    const originalBatch = originalDb.batch.bind(originalDb);
    const originalPrepare = originalDb.prepare.bind(originalDb);
    const wrappedDb = Object.create(originalDb);
    let failNoOpHeadCheck = true;
    let failDeleteHeadCheck = false;
    let noOpBatchCount = 0;

    wrappedDb.batch = async (statements: unknown[]) => {
      noOpBatchCount++;
      if (failNoOpHeadCheck && noOpBatchCount === 2) {
        failNoOpHeadCheck = false;
        return [{ success: true, meta: { changes: 0 } }];
      }
      return originalBatch(statements as any);
    };
    wrappedDb.prepare = (sql: string) => {
      if (failDeleteHeadCheck && sql.includes('SET commit_cid = commit_cid')) {
        failDeleteHeadCheck = false;
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

      failNoOpHeadCheck = false;
      noOpBatchCount = 0;
      failDeleteHeadCheck = true;
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

});
