import { expect } from "@std/expect";
import { P256Keypair, Secp256k1Keypair } from "@atproto/crypto-spaces";
import { decode, encode } from "@atproto/lex-cbor";
import {
  blocksToCarFile,
  def,
  getRecords,
  MemoryBlockstore,
  nodeDataDef,
  type RecordCreateOp,
  Repo,
  writeCarStream,
  WriteOpAction,
} from "@atproto/repo";
import { CID } from "multiformats/cid";
import { base58btc } from "multiformats/bases/base58";
import { sha256 as sha256Sync } from "@noble/hashes/sha2.js";
import { describe, it } from "./helpers/bdd";
import { verifyLexiconProofAtTrustedHead } from "../src/lib/spaces/lexicon-proof";
import {
  collect,
  COLLECTION,
  DID,
  encodedKey,
  NSID,
  schema,
  signedTree,
  target,
  validFixture,
} from "./fixtures/spaces/lexicon-proof";

describe("offline Lexicon proof verification", () => {
  it("verifies current signed CAR paths for both supported curves", async () => {
    for (
      const key of [await Secp256k1Keypair.create(), await P256Keypair.create()]
    ) {
      const input = await validFixture(key, 30);
      const result = await verifyLexiconProofAtTrustedHead(input);
      expect(result.tag).toBe("proven");
      if (result.tag === "proven") {
        expect(result.uri).toBe(`at://${DID}/${COLLECTION}/${NSID}`);
        expect(result.headCid).toBe(
          CID.parse(input.currentCommitCid).toString(),
        );
        expect(result.revision).toMatch(
          /^[234567abcdefghijklmnopqrstuvwxyz]{13}$/,
        );
        expect(result.definitions).toBe("main-only");
        expect(result.main).toMatchObject({
          spaceType: NSID,
          publisherDid: DID,
          key: "any",
          collections: ["com.example.note"],
        });
        expect(CID.parse(result.main.recordCid).code).toBe(0x71);
      }
    }
  });

  it("accepts a complete declaration with localized title and named definitions", async () => {
    const key = await P256Keypair.create();
    const storage = new MemoryBlockstore();
    const value = {
      ...schema(),
      defs: {
        main: {
          ...schema().defs.main,
          title: "A forum",
          "title:lang": { en: "A forum", fr: "Un forum" },
        },
        extra: {
          type: "object",
          properties: { label: { type: "string", maxLength: 64 } },
        },
      },
    };
    const repo = await Repo.create(storage, DID, key, [{
      action: WriteOpAction.Create,
      collection: COLLECTION,
      rkey: NSID,
      record: value,
    }]);
    const proof = await collect(
      getRecords(storage, repo.cid, [{ collection: COLLECTION, rkey: NSID }]),
    );
    const result = await verifyLexiconProofAtTrustedHead({
      nsid: NSID,
      publisherDid: DID,
      signingKey: key.did(),
      currentCommitCid: repo.cid.toString(),
      proof,
    });
    expect(result.tag).toBe("proven");
    if (result.tag === "proven") {
      expect(result.definitions).toBe("additional");
      expect(result.main.title).toBe("A forum");
    }
  });

  it("proves the record without asserting all named definitions are semantically valid", async () => {
    const key = await P256Keypair.create();
    const storage = new MemoryBlockstore();
    const value = {
      ...schema(),
      defs: {
        ...schema().defs,
        extra: {
          type: "string",
          const: "a",
          default: "b",
          minLength: 2,
          maxLength: -1,
        },
      },
    };
    const repo = await Repo.create(storage, DID, key, [{
      action: WriteOpAction.Create,
      collection: COLLECTION,
      rkey: NSID,
      record: value,
    }]);
    const proof = await collect(
      getRecords(storage, repo.cid, [{ collection: COLLECTION, rkey: NSID }]),
    );
    const result = await verifyLexiconProofAtTrustedHead({
      nsid: NSID,
      publisherDid: DID,
      signingKey: key.did(),
      currentCommitCid: repo.cid.toString(),
      proof,
    });
    expect(result.tag).toBe("proven");
    if (result.tag === "proven") expect(result.definitions).toBe("additional");
  });

  it("accepts a valid node with more than 2048 entries", async () => {
    const key = await P256Keypair.create();
    const storage = new MemoryBlockstore();
    const writes: RecordCreateOp[] = [{
      action: WriteOpAction.Create,
      collection: COLLECTION,
      rkey: NSID,
      record: schema(),
    }];
    for (let i = 0; writes.length < 2049; i++) {
      const rkey = `r${i}`;
      if ((sha256Sync(encodedKey(`com.example.note/${rkey}`))[0] >> 6) !== 0) {
        writes.push({
          action: WriteOpAction.Create,
          collection: "com.example.note",
          rkey,
          record: { $type: "com.example.note" },
        });
      }
    }
    const repo = await Repo.create(storage, DID, key, writes);
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
      .toBe("proven");
  });

  it("binds the exact trusted head, publisher, signing key and record path", async () => {
    const key = await P256Keypair.create();
    const other = await P256Keypair.create();
    const input = await validFixture(key);
    for (
      const altered of [
        {
          ...input,
          currentCommitCid:
            "bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua",
        },
        { ...input, publisherDid: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa" },
        { ...input, signingKey: other.did() },
        { ...input, nsid: "com.example.other" },
        { ...input, signingKey: "did:key:invalid" },
      ]
    ) {
      expect((await verifyLexiconProofAtTrustedHead(altered)).tag).toBe(
        "invalid",
      );
    }
    expect(
      (await verifyLexiconProofAtTrustedHead({
        ...input,
        currentCommitCid: CID.parse(input.currentCommitCid).toString(base58btc),
      })).tag,
    ).toBe("proven");
  });

  it("returns the revision from the verified signed commit", async () => {
    const fixture = await signedTree(
      await P256Keypair.create(),
      async (blocks, recordCid) =>
        await blocks.add({
          l: null,
          e: [{ p: 0, k: encodedKey(target), v: recordCid, t: null }],
        }) as unknown as CID,
    );
    const result = await verifyLexiconProofAtTrustedHead(fixture.input);
    expect(result.tag).toBe("proven");
    if (result.tag === "proven") {
      expect(result.revision).toBe(fixture.commit.rev);
    }
  });

  it("snapshots inputs before verification and returns independent records", async () => {
    const input = await validFixture(await P256Keypair.create());
    const original = Uint8Array.from(input.proof);
    const pending = verifyLexiconProofAtTrustedHead(input);
    input.publisherDid = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    input.proof.fill(0);
    const result = await pending;
    expect(result.tag).toBe("proven");
    if (result.tag !== "proven") throw new Error("Expected proof");
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.main)).toBe(true);
    expect(Object.isFrozen(result.main.collections)).toBe(true);
    expect(() =>
      (result.main.collections as string[]).push("com.example.other")
    ).toThrow();
    const again = await verifyLexiconProofAtTrustedHead({
      ...input,
      publisherDid: DID,
      proof: original,
    });
    expect(again.tag).toBe("proven");
    if (again.tag === "proven") {
      expect(again.main.spaceType).toBe(NSID);
    }
  });

  it("rejects malformed, overlong and oversized CAR framing before decoding", async () => {
    const input = await validFixture(await P256Keypair.create());
    const overlong = Uint8Array.from([
      input.proof[0] | 128,
      0,
      ...input.proof.slice(1),
    ]);
    const bad = [
      new Uint8Array(),
      new Uint8Array(4 * 1024 * 1024 + 1),
      new Uint8Array(4096).fill(128),
      Uint8Array.from([0xff, 0xff, 0x7f]),
      overlong,
      input.proof.slice(0, -1),
    ];
    for (const proof of bad) {
      expect((await verifyLexiconProofAtTrustedHead({ ...input, proof })).tag)
        .toBe("invalid");
    }
  });

  it("rejects a noncanonical CAR header", async () => {
    const input = await validFixture(await P256Keypair.create());
    const length = input.proof[0];
    const header = input.proof.slice(1, length + 1);
    const marker = header.findIndex((byte, index) =>
      byte === 0x67 && header[index + 1] === 0x76
    );
    if (length >= 127 || header[0] !== 0xa2 || marker < 0) {
      throw new Error("Unexpected fixture header");
    }
    const proof = Uint8Array.from([
      length,
      0xa2,
      ...header.slice(marker),
      ...header.slice(1, marker),
      ...input.proof.slice(length + 1),
    ]);
    expect((await verifyLexiconProofAtTrustedHead({ ...input, proof })).tag)
      .toBe("invalid");
  });

  it("rejects mismatched or missing blocks but accepts identical duplicates", async () => {
    const key = await P256Keypair.create();
    const input = await validFixture(key);
    const tampered = input.proof.slice();
    tampered[tampered.length - 1] ^= 1;
    expect(
      (await verifyLexiconProofAtTrustedHead({ ...input, proof: tampered }))
        .tag,
    ).toBe("invalid");
    const { readCarWithRoot } = await import("@atproto/repo");
    const { root, blocks } = await readCarWithRoot(input.proof);
    const entries = [...blocks];
    const duplicate = await collect(
      writeCarStream(root, [...entries, entries[0]]),
    );
    expect(
      (await verifyLexiconProofAtTrustedHead({ ...input, proof: duplicate }))
        .tag,
    ).toBe("proven");
    const forgedBytes = Uint8Array.from(entries[0].bytes);
    forgedBytes[forgedBytes.length - 1] ^= 1;
    const forgedDuplicate = await collect(writeCarStream(root, [
      ...entries,
      { cid: entries[0].cid, bytes: forgedBytes },
    ]));
    expect(
      (await verifyLexiconProofAtTrustedHead({
        ...input,
        proof: forgedDuplicate,
      })).tag,
    ).toBe("invalid");
    const excessiveDuplicates = await collect(writeCarStream(root, [
      ...entries,
      ...Array.from({ length: 257 }, () => entries[0]),
    ]));
    expect(
      (await verifyLexiconProofAtTrustedHead({
        ...input,
        proof: excessiveDuplicates,
      })).tag,
    ).toBe("invalid");
    const missing = await collect(writeCarStream(root, entries.slice(0, -1)));
    expect(
      (await verifyLexiconProofAtTrustedHead({ ...input, proof: missing })).tag,
    ).toBe("invalid");
  });

  it("uses the first root and rejects excessive blocks or a CID-spoofed cycle", async () => {
    const input = await validFixture(await P256Keypair.create());
    const { readCarWithRoot } = await import("@atproto/repo");
    const { root, blocks } = await readCarWithRoot(input.proof);
    const entries = [...blocks];
    const multiRoot = await collect(writeCarStream([root, root], entries));
    expect(
      (await verifyLexiconProofAtTrustedHead({ ...input, proof: multiRoot }))
        .tag,
    ).toBe("proven");
    const otherRoot = CID.parse(
      "bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua",
    );
    const wrongFirstRoot = await collect(
      writeCarStream([otherRoot, root], entries),
    );
    expect(
      (await verifyLexiconProofAtTrustedHead({
        ...input,
        proof: wrongFirstRoot,
      })).tag,
    ).toBe("invalid");

    for (let i = 0; blocks.size <= 256; i++) await blocks.add({ extra: i });
    const excessive = await blocksToCarFile(root, blocks);
    expect(
      (await verifyLexiconProofAtTrustedHead({ ...input, proof: excessive }))
        .tag,
    ).toBe("invalid");

    const original = await readCarWithRoot(input.proof);
    const commit = def.commit.schema.parse(
      decode(original.blocks.get(original.root)!),
    );
    const nodeCid = original.blocks.cids().find((cid) =>
      cid.equals(commit.data)
    );
    if (!nodeCid) throw new Error("Missing node fixture");
    const node = nodeDataDef.schema.parse(
      decode(original.blocks.get(nodeCid)!),
    );
    // A real content-addressed cycle would require a SHA-256 fixed point. This
    // spoofs the node's old CID after changing its left link to itself.
    original.blocks.set(nodeCid, encode({ ...node, l: nodeCid }));
    const cyclic = await blocksToCarFile(original.root, original.blocks);
    expect(
      (await verifyLexiconProofAtTrustedHead({ ...input, proof: cyclic })).tag,
    ).toBe("invalid");
  });
});
