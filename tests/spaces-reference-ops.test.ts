import * as dagCbor from "@ipld/dag-cbor";
import { isValidDid } from "@atproto/syntax-spaces";
import { expect } from "@std/expect";
import { makeSpaceEnv as makeEnv } from "./helpers/space-env";
import { readSpaceRepoOps } from "./helpers/space-storage";
import { applySpaceWrites, createLocalSpace } from "./helpers/space-storage";

const configPath = Deno.env.get("ALTERAN_REFERENCE_INTEROP_CONFIG");
const COLLECTION = "com.example.note";

Deno.test({
  name: "reference PDS: incremental operations and commit digest match",
  ignore: !configPath,
  sanitizeOps: false,
  sanitizeResources: false,
  sanitizeExit: false,
  async fn() {
    const config = JSON.parse(await Deno.readTextFile(configPath!)) as {
      pds: unknown;
      did: unknown;
      accessJwt: unknown;
    };
    const pds = loopbackOrigin(config.pds);
    if (
      !isValidDid(config.did) || typeof config.accessJwt !== "string" ||
      !config.accessJwt
    ) {
      throw new Error("Invalid disposable reference account");
    }
    const repo = config.did;
    const skey = `interop-ops-${crypto.randomUUID()}`;
    const space = `at://${repo}/space/${COLLECTION}/${skey}`;
    const authorization = `Bearer ${config.accessJwt}`;
    const rpc = async (method: string, init: RequestInit = {}) => {
      const headers = new Headers(init.headers);
      headers.set("Authorization", authorization);
      const response = await fetch(`${pds}/xrpc/${method}`, {
        ...init,
        headers,
        redirect: "manual",
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) {
        const failure = await response.json().catch(() => ({})) as {
          error?: unknown;
        };
        const code = typeof failure.error === "string"
          ? failure.error
          : "UnknownError";
        throw new Error(
          `Reference PDS returned HTTP ${response.status}: ${code}`,
        );
      }
      return response;
    };
    const post = (method: string, body: unknown) =>
      rpc(method, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    const record = (text: string) => ({ $type: COLLECTION, text });
    const create = (rkey: string, text: string) => ({
      action: "create" as const,
      collection: COLLECTION,
      rkey,
      record: record(text),
    });
    const update = (rkey: string, text: string) => ({
      action: "update" as const,
      collection: COLLECTION,
      rkey,
      record: record(text),
    });
    let created = false;
    try {
      await post("com.atproto.space.createSpace", {
        spaceType: COLLECTION,
        skey,
        policy: { $type: "com.atproto.personalspace.policy" },
      });
      created = true;
      await post("com.atproto.space.createRecord", {
        space,
        repo,
        collection: COLLECTION,
        rkey: "baseline",
        record: record("initial"),
        validate: false,
      });
      const baseline = await (await rpc(
        `com.atproto.space.getLatestCommit?${new URLSearchParams({
          space,
          repo,
        })}`,
      )).json() as {
        commit: { rev: string };
      };

      const env = await makeEnv({ PDS_DID: repo });
      await createLocalSpace(env, space);
      const localBaseline = await applySpaceWrites(env, space, repo, [
        create("baseline", "initial"),
      ]);
      if (!localBaseline) throw new Error("Missing local baseline");

      for (
        const [method, rkey, text] of [
          ["createRecord", "a", "one"],
          ["createRecord", "b", "two"],
          ["putRecord", "a", "new"],
        ] as const
      ) {
        await post(`com.atproto.space.${method}`, {
          space,
          repo,
          collection: COLLECTION,
          rkey,
          record: record(text),
          validate: false,
        });
        await applySpaceWrites(env, space, repo, [
          method === "putRecord" ? update(rkey, text) : create(rkey, text),
        ]);
      }
      await post("com.atproto.space.deleteRecord", {
        space,
        repo,
        collection: COLLECTION,
        rkey: "b",
      });
      await applySpaceWrites(env, space, repo, [{
        action: "delete",
        collection: COLLECTION,
        rkey: "b",
      }]);

      type ReferenceOperation = {
        collection: string;
        rkey: string;
        cid: string | null;
        prev: string | null;
        value?: unknown;
      };
      const reference: ReferenceOperation[] = [];
      let referenceCursor: string | undefined;
      let referenceData: Uint8Array | undefined;
      for (let count = 0; count < 10; count++) {
        const parameters = new URLSearchParams({
          space,
          repo,
          since: baseline.commit.rev,
          limit: "1",
        });
        if (referenceCursor) parameters.set("cursor", referenceCursor);
        const response =
          await (await rpc(`com.atproto.space.listRepoOps?${parameters}`))
            .json() as {
              ops: ReferenceOperation[];
              cursor?: string;
              commit: { data: { $bytes: string } };
            };
        reference.push(...response.ops);
        referenceData = decodeBase64(response.commit.data.$bytes);
        referenceCursor = response.cursor;
        if (!referenceCursor) break;
      }
      if (referenceCursor || !referenceData) {
        throw new Error("Reference pagination did not complete");
      }

      const local: ReferenceOperation[] = [];
      let localCursor: string | undefined;
      let localData: Uint8Array | undefined;
      for (let count = 0; count < 10; count++) {
        const response = await readSpaceRepoOps(env, space, repo, {
          since: localBaseline.rev,
          cursor: localCursor,
          limit: 1,
        });
        if (response.tag !== "page") {
          throw new Error("Local operation history unavailable");
        }
        local.push(...response.operations.map((operation) => ({
          collection: operation.collection,
          rkey: operation.rkey,
          cid: operation.cid,
          prev: operation.prev,
          ...(operation.value
            ? { value: dagCbor.decode(operation.value) }
            : {}),
        })));
        localData = response.commit.data;
        localCursor = response.cursor ?? undefined;
        if (!localCursor) break;
      }
      if (localCursor || !localData) {
        throw new Error("Local pagination did not complete");
      }
      expect(local).toEqual(
        reference.map(({ collection, rkey, cid, prev, value }) => ({
          collection,
          rkey,
          cid,
          prev,
          ...(value === undefined ? {} : { value }),
        })),
      );
      expect(local).toHaveLength(4);
      expect([...localData]).toEqual([...referenceData]);
    } finally {
      if (created) await post("com.atproto.space.deleteSpace", { space });
    }
  },
});

function loopbackOrigin(value: unknown): string {
  if (typeof value !== "string") throw new Error("A loopback URL is required");
  const url = new URL(value);
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
    url.username || url.password || url.pathname !== "/" || url.search ||
    url.hash
  ) {
    throw new Error("Reference PDS must use a loopback HTTP origin");
  }
  return url.origin;
}

function decodeBase64(value: string): Uint8Array {
  const bytes = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(bytes, (character) => character.charCodeAt(0));
}
