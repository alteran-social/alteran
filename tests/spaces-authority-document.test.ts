import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { P256Keypair, Secp256k1Keypair } from "@atproto/crypto-spaces";
import { formatDidDoc } from "@did-plc/lib";
import {
  authorityPdsOrigin,
  authoritySigningKey,
} from "../src/lib/spaces/authority-document";

const DID = "did:plc:alice";
const p256 = await P256Keypair.create();
const k256 = await Secp256k1Keypair.create();
const method = (key: string, id = "#atproto") => ({
  id,
  type: "Multikey",
  controller: DID,
  publicKeyMultibase: key.slice(8),
});
const service = {
  id: "#atproto_pds",
  type: "AtprotoPersonalDataServer",
  serviceEndpoint: "https://pds.example",
};

describe("Spaces authority DID documents", () => {
  it("extracts supported modern signing keys and the first valid key", () => {
    const doc = {
      id: DID,
      verificationMethod: [
        { ...method(p256.did()), controller: "did:plc:other" },
        method(k256.did(), `${DID}#atproto`),
        method(p256.did()),
      ],
    };
    expect(authoritySigningKey(DID, doc)).toBe(k256.did());
    expect(
      authoritySigningKey(DID, {
        id: DID,
        verificationMethod: [method(p256.did())],
      }),
    ).toBe(p256.did());
  });

  it("accepts the legacy signing key representation emitted by PLC", () => {
    const doc = formatDidDoc({
      did: DID,
      rotationKeys: [],
      verificationMethods: { atproto: k256.did() },
      alsoKnownAs: [],
      services: {},
    });
    expect(authoritySigningKey(DID, doc)).toBe(k256.did());
  });

  it("rejects different DID documents, controllers, fragments, and malformed keys", () => {
    expect(
      authoritySigningKey(DID, {
        id: "did:plc:bob",
        verificationMethod: [method(k256.did())],
      }),
    ).toBeNull();
    expect(
      authoritySigningKey(DID, {
        id: DID,
        verificationMethod: [{
          ...method(k256.did()),
          controller: "did:plc:bob",
        }],
      }),
    ).toBeNull();
    expect(
      authoritySigningKey(DID, {
        id: DID,
        verificationMethod: [method(k256.did(), "did:plc:bob#atproto")],
      }),
    ).toBeNull();
    expect(
      authoritySigningKey(DID, {
        id: DID,
        verificationMethod: [{
          ...method(k256.did()),
          publicKeyMultibase: "bad",
        }],
      }),
    ).toBeNull();
  });

  it("extracts an HTTPS origin without credentials, paths, queries, or fragments", () => {
    expect(authorityPdsOrigin(DID, { id: DID, service: [service] })).toBe(
      "https://pds.example",
    );
    expect(
      authorityPdsOrigin(DID, {
        id: DID,
        service: [{
          ...service,
          id: `${DID}#atproto_pds`,
          serviceEndpoint: "https://pds.example:443/",
        }],
      }),
    ).toBe("https://pds.example");
    for (
      const endpoint of [
        "http://pds.example",
        "https://user:pass@pds.example",
        "https://pds.example/path",
        "https://pds.example/?x=1",
        "https://pds.example/#x",
      ]
    ) {
      expect(
        authorityPdsOrigin(DID, {
          id: DID,
          service: [{ ...service, serviceEndpoint: endpoint }],
        }),
      ).toBeNull();
    }
  });

  it("does not fall through an invalid first matching PDS service", () => {
    const invalid = { ...service, serviceEndpoint: "http://pds.example" };
    expect(authorityPdsOrigin(DID, { id: DID, service: [invalid, service] }))
      .toBeNull();
    expect(authorityPdsOrigin(DID, { id: "did:plc:bob", service: [service] }))
      .toBeNull();
    expect(
      authorityPdsOrigin(DID, {
        id: DID,
        service: [{ ...service, id: "did:plc:bob#atproto_pds" }],
      }),
    ).toBeNull();
  });
});
