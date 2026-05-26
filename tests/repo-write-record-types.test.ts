import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import {
  ApplyWrites,
  callRoute,
  CreateRecord,
  FIXED_DATE,
  json,
  makeEnv,
  postRecord,
  PutRecord,
} from "./helpers/repo-write";

describe("repo write record type validation", () => {
  it("rejects missing types on create, put, and applyWrites", async () => {
    const env = await makeEnv();
    const createRecord = { text: "missing create type", createdAt: FIXED_DATE };
    const putRecord = { text: "missing put type", createdAt: FIXED_DATE };
    const applyCreateRecord = {
      text: "missing apply create type",
      createdAt: FIXED_DATE,
      nested: { tags: ["one"] },
    };
    const applyUpdateRecord = {
      text: "missing apply update type",
      createdAt: FIXED_DATE,
      nested: { tags: ["one"] },
    };

    await expectInvalidRecordType(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: "app.bsky.feed.post",
      record: createRecord,
    }, "record $type is required");

    await expectInvalidRecordType(PutRecord, env, {
      repo: env.PDS_DID,
      collection: "app.bsky.feed.post",
      rkey: "3m2biurz7cl27",
      record: putRecord,
    }, "record $type is required");

    await expectInvalidRecordType(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [{
        $type: "com.atproto.repo.applyWrites#create",
        collection: "app.bsky.feed.post",
        value: applyCreateRecord,
      }],
    }, "record $type is required");

    await createExistingRecord(env);
    await expectInvalidRecordType(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [{
        $type: "com.atproto.repo.applyWrites#update",
        collection: "app.bsky.feed.post",
        rkey: "3m2biurz7cl27",
        value: applyUpdateRecord,
      }],
    }, "record $type is required");
  });

  it("rejects mismatched types on create, put, and applyWrites", async () => {
    const env = await makeEnv();
    const mismatched = {
      $type: "app.bsky.actor.profile",
      text: "wrong",
      createdAt: FIXED_DATE,
    };

    await expectInvalidRecordType(CreateRecord, env, {
      repo: env.PDS_DID,
      collection: "app.bsky.feed.post",
      record: mismatched,
    }, "record $type must match collection");

    await expectInvalidRecordType(PutRecord, env, {
      repo: env.PDS_DID,
      collection: "app.bsky.feed.post",
      rkey: "3m2biurz7cl27",
      record: mismatched,
    }, "record $type must match collection");

    await expectInvalidRecordType(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [{
        $type: "com.atproto.repo.applyWrites#create",
        collection: "app.bsky.feed.post",
        value: mismatched,
      }],
    }, "record $type must match collection");

    await createExistingRecord(env);
    await expectInvalidRecordType(ApplyWrites, env, {
      repo: env.PDS_DID,
      writes: [{
        $type: "com.atproto.repo.applyWrites#update",
        collection: "app.bsky.feed.post",
        rkey: "3m2biurz7cl27",
        value: mismatched,
      }],
    }, "record $type must match collection");
  });
});

async function expectInvalidRecordType(
  route: { POST: (ctx: unknown) => Promise<Response> },
  env: Awaited<ReturnType<typeof makeEnv>>,
  body: unknown,
  message: string,
): Promise<void> {
  const response = await callRoute(route, env, body);
  expect(response.status).toBe(400);
  expect(await json(response)).toMatchObject({
    error: "InvalidRequest",
    message,
  });
}

async function createExistingRecord(
  env: Awaited<ReturnType<typeof makeEnv>>,
): Promise<void> {
  const response = await callRoute(CreateRecord, env, {
    repo: env.PDS_DID,
    collection: "app.bsky.feed.post",
    rkey: "3m2biurz7cl27",
    record: postRecord("existing"),
  });
  expect(response.status).toBe(200);
}
