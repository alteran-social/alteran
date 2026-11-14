import { P256Keypair } from "@atproto/crypto-spaces";
import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import { verifyLexiconProofAtTrustedHead } from "../src/lib/spaces/lexicon-proof";
import { resolveSpaceScopes } from "../src/lib/spaces/resolve-scopes";
import {
  createSpaceConsentSnapshot,
  restoreSpaceConsentSnapshot,
} from "../src/lib/spaces/consent-snapshot";
import { DID, NSID, validFixture } from "./fixtures/spaces/lexicon-proof";

describe("Space scope resolution and consent evidence", () => {
  it("seals the exact signed declaration used for equivalent requested scopes", async () => {
    const key = await P256Keypair.create();
    const input = await validFixture(key);
    const proof = await verifyLexiconProofAtTrustedHead(input);
    if (proof.tag !== "proven") throw new Error("Expected signed proof");
    const document = {
      id: DID,
      verificationMethod: [{
        id: "#atproto",
        type: "Multikey",
        controller: DID,
        publicKeyMultibase: key.did().slice(8),
      }],
      service: [{
        id: "#atproto_pds",
        type: "AtprotoPersonalDataServer",
        serviceEndpoint: "https://pds.example.com",
      }],
    };
    let dnsCalls = 0;
    let httpCalls = 0;
    const clientId = "https://client.example/metadata.json";
    const result = await resolveSpaceScopes({
      subject: DID,
      clientId,
      scopes: [`space:${NSID}`, `space?spaceType=${NSID}&action=read`],
    }, {
      resolveTxt: () => {
        dnsCalls++;
        return Promise.resolve([[`did=${DID}`]]);
      },
      fetch: (resource) => {
        httpCalls++;
        const url = new URL(
          resource instanceof Request ? resource.url : resource.toString(),
        );
        if (url.origin === "https://plc.directory") {
          return Promise.resolve(Response.json(document));
        }
        if (url.pathname.endsWith("/com.atproto.sync.getLatestCommit")) {
          return Promise.resolve(
            Response.json({ cid: proof.headCid, rev: proof.revision }),
          );
        }
        if (url.pathname.endsWith("/com.atproto.sync.getRecord")) {
          return Promise.resolve(
            new Response(new Uint8Array(input.proof).buffer),
          );
        }
        throw new Error("Unexpected test URL");
      },
    });
    if (result.tag !== "resolved") {
      throw new Error(`Scope resolution failed: ${result.tag}`);
    }
    expect(dnsCalls).toBe(2);
    expect(httpCalls).toBe(5);
    expect(result.grants).toHaveLength(2);
    expect(result.declarations).toHaveLength(1);
    expect(result.declarations[0].recordCid).toBe(proof.main.recordCid);
    const seal = await createSpaceConsentSnapshot({
      subject: result.subject,
      clientId: result.clientId,
      grants: result.grants,
      declarations: result.declarations,
    });
    if (!seal) throw new Error("Expected authenticated snapshot input");
    const restored = await restoreSpaceConsentSnapshot(seal.serialized, {
      subject: DID,
      clientId,
      digest: seal.digest,
    });
    expect(restored?.grants).toEqual(result.grants);
    expect(restored?.declarations).toEqual(result.declarations);
  });
});
