import { expect } from "@std/expect";
import { P256Keypair, Secp256k1Keypair } from "@atproto/crypto-spaces";
import { encode } from "@atproto/lex-cbor";
import {
  blocksToCarFile,
  getRecords,
  MemoryBlockstore,
  Repo,
  WriteOpAction,
} from "@atproto/repo";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";
import { describe, it } from "./helpers/bdd";
import {
  type LexiconProofInput,
  verifyLexiconProofAtTrustedHead,
} from "../src/lib/spaces/lexicon-proof";
import {
  collect,
  COLLECTION,
  compressedKey,
  DID,
  encodedKey,
  NSID,
  schema,
  signedTree,
  target,
} from "./fixtures/spaces/lexicon-proof";

describe("adversarial Lexicon proofs", () => {
  it("rejects an otherwise signed commit with an unsigned extra field", async () => {
    const key = await P256Keypair.create();
    const fixture = await signedTree(
      key,
      async (blocks, recordCid) =>
        await blocks.add({
          l: null,
          e: [{ p: 0, k: encodedKey(target), v: recordCid, t: null }],
        }) as unknown as CID,
    );
    const root = await fixture.blocks.add({
      ...fixture.commit,
      attacker: true,
    });
    const proof = await blocksToCarFile(root, fixture.blocks);
    expect(
      (await verifyLexiconProofAtTrustedHead({
        ...fixture.input,
        currentCommitCid: root.toString(),
        proof,
      })).tag,
    )
      .toBe("invalid");
  });

  it("rejects the reference verifier's signed out-of-order MST counterexample", async () => {
    const fixture = await signedTree(
      await Secp256k1Keypair.create(),
      async (blocks, recordCid) =>
        await blocks.add({
          l: null,
          e: [
            { p: 0, k: encodedKey(target), v: recordCid, t: null },
            {
              p: 0,
              k: encodedKey(`${COLLECTION}/com.example.aaa`),
              v: recordCid,
              t: null,
            },
          ],
        }) as unknown as CID,
    );
    expect((await verifyLexiconProofAtTrustedHead(fixture.input)).tag).toBe(
      "invalid",
    );
  });

  it("rejects a signed node with a non-maximal compressed prefix", async () => {
    const fixture = await signedTree(
      await P256Keypair.create(),
      async (blocks, recordCid) =>
        await blocks.add({
          l: null,
          e: [
            { p: 0, k: encodedKey(target), v: recordCid, t: null },
            {
              p: 0,
              k: encodedKey(`${COLLECTION}/com.example.zzz`),
              v: recordCid,
              t: null,
            },
          ],
        }) as unknown as CID,
    );
    expect((await verifyLexiconProofAtTrustedHead(fixture.input)).tag).toBe(
      "invalid",
    );
  });

  it("enforces ancestor ranges and contiguous layers on a signed path", async () => {
    const key = await P256Keypair.create();
    const parent = `${COLLECTION}/com.example.zzz1`; // layer 1; target is layer 0
    const invalidOutside = `${COLLECTION}/com.example.zzz3`; // layer 0, after parent
    const make = (outside: boolean, parentKey: string) =>
      signedTree(key, async (blocks, recordCid) => {
        const entries = [{
          p: 0,
          k: encodedKey(target),
          v: recordCid,
          t: null,
        }];
        if (outside) {
          entries.push({
            ...compressedKey(target, invalidOutside),
            v: recordCid,
            t: null,
          });
        }
        const child = await blocks.add({ l: null, e: entries });
        return await blocks.add({
          l: child,
          e: [{ p: 0, k: encodedKey(parentKey), v: recordCid, t: null }],
        }) as unknown as CID;
      });
    expect(
      (await verifyLexiconProofAtTrustedHead((await make(false, parent)).input))
        .tag,
    ).toBe("proven");
    expect(
      (await verifyLexiconProofAtTrustedHead((await make(true, parent)).input))
        .tag,
    ).toBe("invalid");
    expect(
      (await verifyLexiconProofAtTrustedHead(
        (await make(false, `${COLLECTION}/com.example.zzz2`)).input,
      )).tag,
    )
      .toBe("invalid"); // layer 3 must not link directly to layer 0
  });

  it("rejects repeated subtree references in a signed node", async () => {
    const fixture = await signedTree(
      await P256Keypair.create(),
      async (blocks, recordCid) => {
        const child = await blocks.add({
          l: null,
          e: [{ p: 0, k: encodedKey(target), v: recordCid, t: null }],
        });
        return await blocks.add({
          l: child,
          e: [{
            p: 0,
            k: encodedKey(`${COLLECTION}/com.example.zzz1`),
            v: recordCid,
            t: child,
          }],
        }) as unknown as CID;
      },
    );
    expect((await verifyLexiconProofAtTrustedHead(fixture.input)).tag).toBe(
      "invalid",
    );
  });

  it("rejects nodes beyond the CBOR item budget and overly nested record CBOR", async () => {
    const key = await P256Keypair.create();
    const wide = await signedTree(
      key,
      async (blocks, recordCid) =>
        await blocks.add({
          l: null,
          e: Array.from({ length: 5500 }, () => ({
            p: 0,
            k: encodedKey(target),
            v: recordCid,
            t: null,
          })),
        }) as unknown as CID,
    );
    expect((await verifyLexiconProofAtTrustedHead(wide.input)).tag).toBe(
      "invalid",
    );

    type Nested = null | Nested[];
    let nested: Nested = null;
    for (let i = 0; i < 70; i++) nested = [nested];
    const storage = new MemoryBlockstore();
    const record = { ...schema(), extra: nested };
    const repo = await Repo.create(storage, DID, key, [{
      action: WriteOpAction.Create,
      collection: COLLECTION,
      rkey: NSID,
      record,
    }]);
    const proof = await collect(
      getRecords(storage, repo.cid, [{ collection: COLLECTION, rkey: NSID }]),
    );
    expect(
      (await verifyLexiconProofAtTrustedHead({
        nsid: NSID,
        publisherDid: DID,
        signingKey: key.did(),
        currentCommitCid: repo.cid.toString(),
        proof,
      })).tag,
    )
      .toBe("invalid");
  });

  it("rejects noncanonical CBOR even when the block CID and signature match", async () => {
    const fixture = await signedTree(
      await P256Keypair.create(),
      async (blocks, recordCid) => {
        const canonical = encode({
          l: null,
          e: [{ p: 0, k: encodedKey(target), v: recordCid, t: null }],
        });
        const noncanonical = Uint8Array.from([
          0xb8,
          0x02,
          ...canonical.slice(1),
        ]);
        const cid = CID.createV1(0x71, await sha256.digest(noncanonical));
        blocks.set(cid, noncanonical);
        return cid;
      },
    );
    expect((await verifyLexiconProofAtTrustedHead(fixture.input)).tag).toBe(
      "invalid",
    );
  });

  it("rejects a signed record with a wrong or invalid Space declaration", async () => {
    const key = await P256Keypair.create();
    for (
      const record of [
        schema("com.example.other"),
        {
          ...schema(),
          defs: {
            main: {
              type: "record",
              key: "any",
              record: { type: "object", properties: {} },
            },
          },
        },
        {
          ...schema(),
          defs: { main: { type: "space", key: "any", collections: ["*"] } },
        },
      ]
    ) {
      const storage = new MemoryBlockstore();
      const repo = await Repo.create(storage, DID, key, [{
        action: WriteOpAction.Create,
        collection: COLLECTION,
        rkey: NSID,
        record,
      }]);
      const proof = await collect(
        getRecords(storage, repo.cid, [{ collection: COLLECTION, rkey: NSID }]),
      );
      const input: LexiconProofInput = {
        nsid: NSID,
        publisherDid: DID,
        signingKey: key.did(),
        currentCommitCid: repo.cid.toString(),
        proof,
      };
      expect((await verifyLexiconProofAtTrustedHead(input)).tag).toBe(
        "invalid",
      );
    }
  });
});
