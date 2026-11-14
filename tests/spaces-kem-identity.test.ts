import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { Secp256k1Keypair } from "@atproto/crypto-spaces";
import { formatDidDoc } from "@did-plc/lib";
import { checkSpaceKemIdentity } from "../src/lib/spaces/kem-identity";

const DID = "did:plc:alice";
const KEY = "did:key:zDnaepxWioy4TQi6a94tSHKU4aqQkz6rksDiBfnuiGbwf4i5N";
const OTHER_KEY = "did:key:zDnaeXxvmFHMHjqgQTbadpWG7gPHwnga1i7SMwxrV2BSdUjAD";
const method = {
  id: `${DID}#atproto_kem`,
  controller: DID,
  type: "Multikey",
  publicKeyMultibase: KEY.slice(8),
};
const document = { id: DID, verificationMethod: [method] };

function plcDocument(key: string) {
  return formatDidDoc({
    did: DID,
    rotationKeys: [],
    verificationMethods: { atproto_kem: key },
    alsoKnownAs: [],
    services: {},
  });
}

describe("Spaces KEM identity binding", () => {
  it("accepts exactly the advertised locally configured P-256 key", () => {
    expect(checkSpaceKemIdentity(DID, KEY, document)).toBe("ready");
    expect(checkSpaceKemIdentity(DID, KEY, {
      id: DID,
      verificationMethod: [{ ...method, id: "#atproto_kem" }],
    })).toBe("ready");
  });

  it("recognizes the legacy P-256 representation emitted by a PLC directory", () => {
    const legacy = plcDocument(KEY);
    expect(legacy.verificationMethod[0].id).toBe("#atproto_kem");
    expect(legacy.verificationMethod[0].type).toBe(
      "EcdsaSecp256r1VerificationKey2019",
    );
    expect(checkSpaceKemIdentity(DID, KEY, legacy)).toBe("ready");
    expect(checkSpaceKemIdentity(DID, OTHER_KEY, legacy)).toBe("mismatch");
    const key = legacy.verificationMethod[0];
    expect(checkSpaceKemIdentity(DID, KEY, {
      id: DID,
      verificationMethod: [{ ...key, controller: "did:plc:bob" }],
    })).toBe("invalid");
    expect(checkSpaceKemIdentity(DID, KEY, {
      id: DID,
      verificationMethod: [{ ...key, id: `${DID}#atproto` }],
    })).toBe("missing");
  });

  it("rejects malformed and wrong-curve KEM verification methods", async () => {
    const legacy = plcDocument(KEY).verificationMethod[0];
    for (const invalid of ["", "bad", "z1111"]) {
      expect(checkSpaceKemIdentity(DID, KEY, {
        id: DID,
        verificationMethod: [{ ...legacy, publicKeyMultibase: invalid }],
      })).toBe("invalid");
    }
    const otherCurve = await Secp256k1Keypair.create();
    const otherDidKey = otherCurve.did();
    expect(checkSpaceKemIdentity(DID, KEY, plcDocument(otherDidKey))).toBe(
      "invalid",
    );
    expect(checkSpaceKemIdentity(DID, KEY, {
      id: DID,
      verificationMethod: [{
        ...method,
        publicKeyMultibase: otherDidKey.slice(8),
      }],
    })).toBe("invalid");
  });

  it("distinguishes absent keys from malformed identity documents", () => {
    expect(checkSpaceKemIdentity(DID, KEY, { id: DID })).toBe("missing");
    expect(checkSpaceKemIdentity(DID, KEY, { id: DID, verificationMethod: [] }))
      .toBe("missing");
    expect(
      checkSpaceKemIdentity(DID, KEY, {
        id: "did:plc:bob",
        verificationMethod: [method],
      }),
    ).toBe("invalid");
    expect(checkSpaceKemIdentity(DID, KEY, { id: DID, verificationMethod: {} }))
      .toBe("invalid");
    expect(
      checkSpaceKemIdentity(DID, KEY, {
        id: DID,
        verificationMethod: [null, method],
      }),
    )
      .toBe("invalid");
    expect(
      checkSpaceKemIdentity(DID, KEY, {
        ...document,
        verificationMethod: [method, method],
      }),
    ).toBe("invalid");
  });

  it("rejects incorrectly identified, controlled, typed or encoded methods", () => {
    for (
      const changes of [
        { controller: "did:plc:bob" },
        { type: "JsonWebKey2020" },
        { publicKeyMultibase: "bad" },
      ]
    ) {
      expect(
        checkSpaceKemIdentity(DID, KEY, {
          id: DID,
          verificationMethod: [{ ...method, ...changes }],
        }),
      )
        .toBe("invalid");
    }
  });

  it("does not treat a different valid key as locally usable", () => {
    expect(checkSpaceKemIdentity(DID, OTHER_KEY, document)).toBe("mismatch");
    expect(checkSpaceKemIdentity(DID, "did:key:bad", document)).toBe("invalid");
  });
});
