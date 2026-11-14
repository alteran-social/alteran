import { expect } from "@std/expect";
import { P256Keypair, Secp256k1Keypair } from "@atproto/crypto-spaces";
import {
  assureValidOp,
  assureValidSig,
  type CompatibleOp,
  createOp,
  createUpdateOp,
  deprecatedSignCreate,
  didForCreateOp,
} from "@did-plc/lib";
import { base58btc } from "multiformats/bases/base58";
import { describe, it } from "./helpers/bdd";
import {
  parsePlcHead,
  validSigningKey,
} from "../src/lib/spaces/kem-plc-operation";
import { planKemPlcFromLineage } from "../src/lib/spaces/kem-plc-lineage";
import { verifyPlcLineageSignature } from "../src/lib/spaces/kem-plc-lineage-signature";
import { planKemPlcUpdate } from "../src/lib/spaces/kem-plc-plan";

const ORIGIN = "https://pds.example";
const INCARNATION = "1234567890abcdef1234567890abcdef";

async function fixture() {
  const signing = await Secp256k1Keypair.create();
  const recovery = await P256Keypair.create();
  const kem = await P256Keypair.create();
  const genesis = await createOp({
    signingKey: signing.did(),
    rotationKeys: [recovery.did(), signing.did()],
    handle: "alice.test",
    pds: ORIGIN,
    signer: signing,
  });
  const update = await createUpdateOp(genesis.op, recovery, (current) => ({
    ...current,
    alsoKnownAs: ["at://updated.test", "https://例.example/1"],
  }));
  const plan = (operations: readonly unknown[], did: unknown = genesis.did) =>
    planKemPlcFromLineage(
      operations.map((operation) =>
        typeof operation === "string" ? operation : JSON.stringify(operation)
      ),
      did,
      INCARNATION,
      true,
      ORIGIN,
      signing.did(),
      signing.did(),
      kem.did(),
    );
  return { signing, recovery, kem, genesis, update, plan };
}

function malformedP256Key(): string {
  const prefixed = new Uint8Array(35);
  prefixed.set([0x80, 0x24, 0x02]);
  prefixed.fill(0xff, 3);
  return `did:key:${base58btc.encode(prefixed)}`;
}

describe("offline KEM PLC signature linkage", () => {
  it("checks mixed curves and returns the same unsigned plan and canonical head CID", async () => {
    const f = await fixture();
    const result = await f.plan([f.genesis.op, f.update]);
    expect(result.tag).toBe("signatureLinked");
    if (result.tag !== "signatureLinked") {
      throw new Error("Expected linked history");
    }
    expect(result.operationCount).toBe(2);
    expect(result.plan).toEqual(
      planKemPlcUpdate(
        JSON.stringify(f.update),
        f.genesis.did,
        INCARNATION,
        true,
        ORIGIN,
        f.signing.did(),
        f.signing.did(),
        f.kem.did(),
      ),
    );
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("verifies a legacy genesis using its original unsigned representation", async () => {
    const f = await fixture();
    const legacy = await deprecatedSignCreate({
      type: "create",
      signingKey: f.signing.did(),
      recoveryKey: f.recovery.did(),
      handle: "alice.test",
      service: "pds.example",
      prev: null,
    }, f.signing);
    const did = await didForCreateOp(legacy);
    const update = await createUpdateOp(
      legacy,
      f.recovery,
      (current) => current,
    );
    const result = await f.plan([legacy, update], did);
    expect(result.tag).toBe("signatureLinked");
    if (result.tag !== "signatureLinked") {
      throw new Error("Expected linked legacy history");
    }
    expect(result.plan.tag).toBe("proposed");
  });

  it("rejects broken ancestry, signatures, DID and ambiguous JSON", async () => {
    const f = await fixture();
    const outsider = await Secp256k1Keypair.create();
    const forged = await createUpdateOp(
      f.genesis.op,
      outsider,
      (current) => current,
    );
    const tampered = { ...f.update, alsoKnownAs: ["at://tampered.test"] };
    const badGenesis = { ...f.genesis.op, alsoKnownAs: ["at://tampered.test"] };
    const another = await createUpdateOp(
      f.update,
      f.signing,
      (current) => current,
    );
    for (
      const history of [
        [badGenesis],
        [f.genesis.op, tampered],
        [f.genesis.op, forged],
        [f.genesis.op, another],
        [f.update, f.genesis.op],
        [f.genesis.op, '{"type":"plc_operation","type":"plc_operation"}'],
      ]
    ) {
      expect((await f.plan(history)).tag).toBe("invalidLineage");
    }
    expect(
      (await f.plan(
        [f.genesis.op, f.update],
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
      )).tag,
    ).toBe("invalidLineage");
    expect(
      (await f.plan([f.genesis.op, {
        type: "plc_tombstone",
        prev: f.update.prev,
        sig: f.update.sig,
      }])).tag,
    )
      .toBe("invalidLineage");
  });

  it("rejects an invalid P-256 method even when a later operation removes it", async () => {
    const f = await fixture();
    const badKey = malformedP256Key();
    expect(validSigningKey(badKey)).toBe(false);
    const bad = await createUpdateOp(f.genesis.op, f.signing, (current) => ({
      ...current,
      verificationMethods: { ...current.verificationMethods, extra: badKey },
    }));
    expect(parsePlcHead(JSON.stringify(bad)) !== null).toBe(true);
    await assureValidOp(bad);
    const later = await createUpdateOp(bad, f.signing, (current) => ({
      ...current,
      verificationMethods: { atproto: f.signing.did() },
    }));
    expect((await f.plan([f.genesis.op, bad])).tag).toBe("invalidLineage");
    expect((await f.plan([f.genesis.op, bad, later])).tag).toBe(
      "invalidLineage",
    );
  });

  it("rejects P-256 high-S signatures that the older PLC verifier accepts", async () => {
    const key = "did:key:zDnaeVRtXZd7kn9EV6VCHtV1LnxJBJQimj2q4yZ7ZxX9CXfrd";
    const operation: CompatibleOp = {
      type: "plc_operation",
      rotationKeys: [],
      verificationMethods: {},
      alsoKnownAs: [],
      services: {},
      prev: null,
      sig:
        "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZ_____gAAAAH__________3nN9VtOLz0J53OVhfjGSqQ",
    };
    expect(await assureValidSig([key], operation)).toBe(key);
    expect(await verifyPlcLineageSignature(operation, [key])).toBe(false);
  });

  it("tries a later signer when an earlier curve rejects the signature range", async () => {
    const first = "did:key:zDnaeVRtXZd7kn9EV6VCHtV1LnxJBJQimj2q4yZ7ZxX9CXfrd";
    const second = "did:key:zQ3shW8H8ZKy7mUXAp9kAEAweXpHdMANuBX6KncjUMcBiNvLY";
    const operation: CompatibleOp = {
      type: "plc_operation",
      rotationKeys: [],
      verificationMethods: {},
      alsoKnownAs: [],
      services: {},
      prev: null,
      sig:
        "_____wAAAAD__________7zm-q2nF56E87nKwvxjJVIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ",
    };
    expect(await assureValidSig([first, second], operation)).toBe(second);
    expect(await verifyPlcLineageSignature(operation, [first, second])).toBe(
      true,
    );
  });

  it("captures its inputs before async verification and accepts a stale valid prefix", async () => {
    const f = await fixture();
    const texts = [JSON.stringify(f.genesis.op), JSON.stringify(f.update)];
    const pending = planKemPlcFromLineage(
      texts,
      f.genesis.did,
      INCARNATION,
      true,
      ORIGIN,
      f.signing.did(),
      f.signing.did(),
      f.kem.did(),
    );
    texts[1] = "{}";
    let lengthReads = 0;
    const unusual = new Proxy([JSON.stringify(f.genesis.op)], {
      get(target, key, receiver) {
        if (key === "length") return ++lengthReads === 1 ? 1 : 100_000;
        return Reflect.get(target, key, receiver);
      },
    });
    const bounded = await planKemPlcFromLineage(
      unusual,
      f.genesis.did,
      INCARNATION,
      true,
      ORIGIN,
      f.signing.did(),
      f.signing.did(),
      f.kem.did(),
    );
    expect(bounded.tag).toBe("signatureLinked");
    expect(lengthReads).toBe(1);
    const result = await pending;
    expect(result.tag).toBe("signatureLinked");
    const prefix = await f.plan([f.genesis.op]);
    expect(prefix.tag).toBe("signatureLinked");
    if (
      result.tag !== "signatureLinked" || prefix.tag !== "signatureLinked" ||
      result.plan.tag !== "proposed" || prefix.plan.tag !== "proposed"
    ) throw new Error("Expected proposals");
    expect(result.plan.context.headCid).not.toBe(prefix.plan.context.headCid);
  });

  it("bounds input bytes, operation count and key work", async () => {
    const f = await fixture();
    expect((await f.plan([])).tag).toBe("invalidInput");
    expect((await f.plan(Array(33).fill(f.genesis.op))).tag).toBe(
      "invalidInput",
    );
    expect((await f.plan(["x".repeat(65_537)])).tag).toBe("invalidInput");
    expect((await f.plan(Array(9).fill("x".repeat(60_000)))).tag).toBe(
      "invalidInput",
    );
    const methods = Object.fromEntries(
      Array.from(
        { length: 14 },
        (_, index) => [`extra${index}`, f.signing.did()],
      ),
    );
    const tooMany = await createUpdateOp(
      f.genesis.op,
      f.signing,
      (current) => ({
        ...current,
        verificationMethods: { ...current.verificationMethods, ...methods },
      }),
    );
    expect((await f.plan([f.genesis.op, tooMany])).tag).toBe("invalidLineage");
    let previous = f.genesis.op;
    const operations = [previous];
    const withinLimit = Object.fromEntries(
      Array.from(
        { length: 10 },
        (_, index) => [`extra${index}`, f.signing.did()],
      ),
    );
    for (let index = 0; index < 20; index++) {
      previous = await createUpdateOp(previous, f.signing, (current) => ({
        ...current,
        verificationMethods: { ...current.verificationMethods, ...withinLimit },
      }));
      operations.push(previous);
    }
    expect((await f.plan(operations)).tag).toBe("invalidLineage");
  });
});
