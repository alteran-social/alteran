import { P256Keypair, Secp256k1Keypair } from "@atproto/crypto-spaces";
import { createSpaceCredential, createSpaceSigHeaders } from "@atproto/space";
import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { parseSpaceRef } from "../src/db/space-ref";
import {
  authorityPdsOrigin,
  authoritySigningKey,
} from "../src/lib/spaces/authority-document";
import { verifySpaceCredential } from "../src/lib/spaces/credential-verifier";
import { checkSpaceKemIdentity } from "../src/lib/spaces/kem-identity";
import { resolveLexiconAuthority } from "../src/lib/spaces/lexicon-authority";
import { verifyLexiconProofAtTrustedHead } from "../src/lib/spaces/lexicon-proof";
import {
  readSpaceRepoArchive,
  writeSpaceRepoArchive,
} from "../src/lib/spaces/repo-archive";
import { validFixture } from "./fixtures/spaces/lexicon-proof";

const INVALID_DID = "did:example:%ZZ";
const VALID_DID = "did:plc:abcdefghijklmnopqrstuvwx";
const INVALID_SPACE =
  `at://${INVALID_DID}/space/com.example.forum/general` as const;
const VALID_SPACE =
  `at://${VALID_DID}/space/com.example.forum/general` as const;
const KEM_KEY = "did:key:zDnaepxWioy4TQi6a94tSHKU4aqQkz6rksDiBfnuiGbwf4i5N";

describe("Space DID boundaries", () => {
  it("rejects malformed authorities in Space references", () => {
    expect(() => parseSpaceRef(INVALID_SPACE)).toThrow();
    expect(parseSpaceRef(VALID_SPACE).authorityDid).toBe(VALID_DID);
  });

  it("rejects malformed identities in DID document helpers", () => {
    const document = {
      id: INVALID_DID,
      verificationMethod: [{
        id: "#atproto_kem",
        controller: INVALID_DID,
        type: "Multikey",
        publicKeyMultibase: KEM_KEY.slice(8),
      }],
      service: [{
        id: "#atproto_pds",
        type: "AtprotoPersonalDataServer",
        serviceEndpoint: "https://pds.example.com",
      }],
    };
    expect(checkSpaceKemIdentity(INVALID_DID, KEM_KEY, document)).toBe(
      "invalid",
    );
    expect(authorityPdsOrigin(INVALID_DID, document)).toBeNull();
    expect(authoritySigningKey(INVALID_DID, document)).toBeNull();
  });

  it("rejects malformed identities returned by Lexicon DNS or supplied to proofs", async () => {
    expect(
      await resolveLexiconAuthority("com.example.forum", {
        resolveTxt: () => Promise.resolve([[`did=${INVALID_DID}`]]),
      }),
    ).toEqual({ tag: "invalid", reason: "did" });
    const key = await P256Keypair.create();
    const fixture = await validFixture(key);
    expect(
      (await verifyLexiconProofAtTrustedHead({
        ...fixture,
        publisherDid: INVALID_DID,
      })).tag,
    ).toBe("invalid");
  });

  it("rejects malformed archive authority and repo before processing data", async () => {
    const archive = {
      space: VALID_SPACE,
      repo: VALID_DID,
      rev: "3n2a5tw2wd22l",
      data: new Uint8Array(32),
      records: [],
    };
    await expect(writeSpaceRepoArchive({ ...archive, space: INVALID_SPACE }))
      .rejects.toThrow();
    await expect(writeSpaceRepoArchive({ ...archive, repo: INVALID_DID }))
      .rejects.toThrow();
    await expect(
      readSpaceRepoArchive(new Uint8Array(), {
        space: INVALID_SPACE,
        repo: VALID_DID,
      }),
    ).rejects.toThrow();
    await expect(
      readSpaceRepoArchive(new Uint8Array(), {
        space: VALID_SPACE,
        repo: INVALID_DID,
      }),
    ).rejects.toThrow();
  });

  it("rejects genuine credentials with malformed authorities or audiences", async () => {
    const signer = await Secp256k1Keypair.create();
    const holder = await P256Keypair.create();
    for (
      const [authority, space, audience] of [
        [INVALID_DID, INVALID_SPACE, VALID_DID],
        [VALID_DID, VALID_SPACE, INVALID_DID],
      ] as const
    ) {
      const credential = await createSpaceCredential({
        iss: authority,
        sub: space,
        keyId: holder.did() as `did:${string}:${string}`,
        keypair: signer,
      });
      const proof = await createSpaceSigHeaders({
        authorization: `Atproto-Space-Credential ${credential}`,
        audience,
        keypair: holder,
      });
      let resolved = false;
      const result = await verifySpaceCredential({
        space,
        expectedAudience: audience,
        headers: new Headers(proof.headers),
        getAuthoritySigningKey: () => {
          resolved = true;
          return Promise.resolve(signer.did());
        },
        isRevoked: () => Promise.resolve(false),
      });
      expect(result.tag).toBe("invalid");
      expect(resolved).toBe(false);
    }
  });
});
