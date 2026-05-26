import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import {
  ApplyWrites,
  callRoute,
  createPost,
  FIXED_DATE,
  json,
  listRecords,
  makeEnv,
  postRecord,
} from "./helpers/repo-write";

describe("repo applyWrites", () => {
  it("generates omitted rkeys before createRecord validation", async () => {
    const env = await makeEnv();
    const body = await createPost(env);

    expect(body.uri).toMatch(
      /^at:\/\/did:example:test\/app\.bsky\.feed\.post\/[a-z2-7]{13}$/,
    );
    expect(body.validationStatus).toBe("valid");
  });

  it("preflights applyWrites before mutation and supports generated create rkeys", async () => {
    const env = await makeEnv();

    const invalidBatch = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [
        {
          $type: "com.atproto.repo.applyWrites#create",
          collection: "app.bsky.feed.post",
          value: postRecord("first"),
        },
        {
          $type: "com.atproto.repo.applyWrites#create",
          collection: "app.bsky.feed.post",
          value: { $type: "app.bsky.feed.post", createdAt: FIXED_DATE },
        },
      ],
    });
    expect(invalidBatch.status).toBe(400);
    expect(await listRecords(env)).toHaveLength(0);

    const validBatch = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [
        {
          $type: "com.atproto.repo.applyWrites#create",
          collection: "app.bsky.feed.post",
          value: postRecord("one"),
        },
        {
          $type: "com.atproto.repo.applyWrites#create",
          collection: "com.example.record",
          rkey: "custom:key",
          value: { $type: "com.example.record", text: "two" },
        },
      ],
    });
    expect(validBatch.status).toBe(200);
    const body = await json(validBatch);
    expect(typeof body.commit.cid).toBe("string");
    expect(body.results).toHaveLength(2);
    expect(body.results[0].uri).toMatch(
      /^at:\/\/did:example:test\/app\.bsky\.feed\.post\/[a-z2-7]{13}$/,
    );
    expect(body.results[1].uri).toBe(
      "at://did:example:test/com.example.record/custom:key",
    );
    expect(await listRecords(env)).toHaveLength(2);
    const commits = await env.ALTERAN_DB.prepare("SELECT cid FROM commit_log")
      .all();
    expect(commits.results).toHaveLength(1);
  });

  it("applies same-path writes against the in-batch state", async () => {
    const env = await makeEnv();

    const response = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [
        {
          $type: "com.atproto.repo.applyWrites#create",
          collection: "com.example.record",
          rkey: "same",
          value: { $type: "com.example.record", text: "first" },
        },
        {
          $type: "com.atproto.repo.applyWrites#delete",
          collection: "com.example.record",
          rkey: "same",
        },
        {
          $type: "com.atproto.repo.applyWrites#create",
          collection: "com.example.record",
          rkey: "same",
          value: { $type: "com.example.record", text: "second" },
        },
      ],
    });

    expect(response.status).toBe(200);
    const body = await json(response);
    expect(body.results).toHaveLength(3);
    expect(await listRecords(env)).toHaveLength(1);
  });

  it("rejects oversized and missing-record applyWrites batches before mutation", async () => {
    const env = await makeEnv();
    const tooMany = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: Array.from({ length: 201 }, () => ({
        $type: "com.atproto.repo.applyWrites#create",
        collection: "com.example.record",
        value: { $type: "com.example.record", value: "x" },
      })),
    });
    expect(tooMany.status).toBe(400);
    expect((await json(tooMany)).error).toBe("InvalidRequest");
    expect(await listRecords(env)).toHaveLength(0);

    const missingDelete = await callRoute(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [{
        $type: "com.atproto.repo.applyWrites#delete",
        collection: "com.example.record",
        rkey: "missing",
      }],
    });
    expect(missingDelete.status).toBe(400);
    expect((await json(missingDelete)).error).toBe("InvalidRequest");
    expect(await listRecords(env)).toHaveLength(0);
  });
});
