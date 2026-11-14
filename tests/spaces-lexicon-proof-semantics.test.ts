import { expect } from "@std/expect";
import { P256Keypair } from "@atproto/crypto-spaces";
import {
  getRecords,
  MemoryBlockstore,
  type RecordCreateOp,
  Repo,
  WriteOpAction,
} from "@atproto/repo";
import { describe, it } from "./helpers/bdd";
import { verifyLexiconProofAtTrustedHead } from "../src/lib/spaces/lexicon-proof";
import { resolveSpaceLexiconProof } from "../src/lib/spaces/lexicon-resolution";
import {
  collect,
  COLLECTION,
  DID,
  NSID,
  schema,
} from "./fixtures/spaces/lexicon-proof";

async function fixture(record: RecordCreateOp["record"]) {
  const key = await P256Keypair.create();
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
  return {
    key,
    input: {
      nsid: NSID,
      publisherDid: DID,
      signingKey: key.did(),
      currentCommitCid: repo.cid.toString(),
      proof,
    },
  };
}

function withExtra(extra: RecordCreateOp["record"]) {
  return { ...schema(), defs: { ...schema().defs, extra } };
}

describe("semantic validation of signed Lexicon proofs", () => {
  it("proves a semantically valid named definition", async () => {
    const sample = await fixture(withExtra({ type: "string", maxLength: 100 }));
    const result = await verifyLexiconProofAtTrustedHead(sample.input);
    expect(result.tag).toBe("proven");
    if (result.tag === "proven") expect(result.definitions).toBe("additional");
  });

  it("returns no declaration for unsupported signed records", async () => {
    const samples = [
      withExtra({ type: "future-schema" }),
      withExtra({ type: "string", format: "future-format" }),
      withExtra({
        type: "object",
        properties: { nested: { type: "ref", ref: "com.remote.schema#view" } },
      }),
      { ...schema(), extension: { $bytes: "Zm9v" } },
    ];
    for (const record of samples) {
      const sample = await fixture(record);
      const result = await verifyLexiconProofAtTrustedHead(sample.input);
      expect(result.tag).toBe("unsupported");
      expect(Object.hasOwn(result, "main")).toBe(false);
      expect(Object.isFrozen(result)).toBe(true);
    }
  });

  it("never reports unsupported evidence for an unauthenticated proof", async () => {
    const sample = await fixture(withExtra({ type: "future-schema" }));
    const otherKey = await P256Keypair.create();
    const other = await fixture(schema());
    for (
      const input of [
        { ...sample.input, signingKey: otherKey.did() },
        { ...sample.input, currentCommitCid: other.input.currentCommitCid },
        { ...sample.input, nsid: "com.example.other" },
        { ...sample.input, publisherDid: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa" },
      ]
    ) {
      expect((await verifyLexiconProofAtTrustedHead(input)).tag).toBe(
        "invalid",
      );
    }
  });

  it("requires record identity fields to be own properties", async () => {
    const { $type: _type, ...withoutType } = schema();
    const { id: _id, ...withoutId } = schema();
    for (
      const [name, value, record] of [
        ["$type", COLLECTION, withoutType],
        ["id", NSID, withoutId],
      ] as const
    ) {
      const sample = await fixture(record);
      const previous = Object.getOwnPropertyDescriptor(Object.prototype, name);
      Object.defineProperty(Object.prototype, name, {
        configurable: true,
        value,
      });
      try {
        expect((await verifyLexiconProofAtTrustedHead(sample.input)).tag).toBe(
          "invalid",
        );
      } finally {
        if (previous) Object.defineProperty(Object.prototype, name, previous);
        else Reflect.deleteProperty(Object.prototype, name);
      }
    }
  });

  it("propagates unsupported only after stable authority, identity and head checks", async () => {
    const sample = await fixture(withExtra({ type: "future-schema" }));
    const checked = await verifyLexiconProofAtTrustedHead(sample.input);
    if (checked.tag !== "unsupported") {
      throw new Error("Expected unsupported proof");
    }
    const document = {
      id: DID,
      verificationMethod: [{
        id: "#atproto",
        type: "Multikey",
        controller: DID,
        publicKeyMultibase: sample.key.did().slice(8),
      }],
      service: [{
        id: "#atproto_pds",
        type: "AtprotoPersonalDataServer",
        serviceEndpoint: "https://pds.example.com",
      }],
    };
    let authorityReads = 0;
    const options = {
      resolveTxt: () => {
        authorityReads++;
        return Promise.resolve([[`did=${DID}`]]);
      },
      fetch: (resource: string | URL | Request) => {
        const url = new URL(
          resource instanceof Request ? resource.url : resource.toString(),
        );
        if (url.origin === "https://plc.directory") {
          return Promise.resolve(Response.json(document));
        }
        if (url.pathname.endsWith("/com.atproto.sync.getLatestCommit")) {
          return Promise.resolve(
            Response.json({ cid: checked.headCid, rev: checked.revision }),
          );
        }
        if (url.pathname.endsWith("/com.atproto.sync.getRecord")) {
          return Promise.resolve(
            new Response(new Uint8Array(sample.input.proof).buffer),
          );
        }
        throw new Error("Unexpected test URL");
      },
    };
    const result = await resolveSpaceLexiconProof(NSID, options);
    expect(result.tag).toBe("unsupported");
    expect(Object.hasOwn(result, "main")).toBe(false);
    expect(Object.isFrozen(result)).toBe(true);
    expect(authorityReads).toBe(2);

    let changingReads = 0;
    const changed = await resolveSpaceLexiconProof(NSID, {
      ...options,
      resolveTxt: () =>
        Promise.resolve([[
          `did=${
            changingReads++ % 2 === 0 ? DID : "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
          }`,
        ]]),
    });
    expect(changed.tag === "unsupported" || changed.tag === "proven").toBe(
      false,
    );
  });
});
