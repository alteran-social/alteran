import { expect } from "@std/expect";
import { P256Keypair } from "@atproto/crypto-spaces";
import { base58btc } from "multiformats/bases/base58";
import { CID } from "multiformats/cid";
import { describe, it } from "./helpers/bdd";
import { verifyLexiconProofAtTrustedHead } from "../src/lib/spaces/lexicon-proof";
import {
  resolveSpaceLexiconProof,
  type SpaceLexiconResolutionOptions,
} from "../src/lib/spaces/lexicon-resolution";
import { DID, NSID, validFixture } from "./fixtures/spaces/lexicon-proof";

type Scenario = {
  readonly dids?: readonly string[];
};

async function setup(scenario: Scenario = {}) {
  const key = await P256Keypair.create();
  const input = await validFixture(key);
  const checked = await verifyLexiconProofAtTrustedHead(input);
  if (checked.tag !== "proven") throw new Error("Invalid test proof");
  const baseHead = { cid: checked.headCid, rev: checked.revision };
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
  const queries: string[] = [];
  const requests: string[] = [];
  let authorityReads = 0;
  const options: SpaceLexiconResolutionOptions = {
    resolveTxt: (name) => {
      queries.push(name);
      const did = scenario.dids?.[authorityReads] ?? DID;
      authorityReads++;
      return Promise.resolve([[`did=${did}`]]);
    },
    fetch: (resource, init) => {
      const url = new URL(
        resource instanceof Request ? resource.url : resource.toString(),
      );
      requests.push(url.href);
      expect(init?.method).toBe("GET");
      expect(init?.redirect).toBe("manual");
      if (
        url.origin === "https://plc.directory" && url.pathname === `/${DID}`
      ) {
        return Promise.resolve(Response.json(document));
      }
      if (
        url.origin === "https://pds.example.com" &&
        url.pathname === "/xrpc/com.atproto.sync.getLatestCommit"
      ) {
        return Promise.resolve(Response.json(baseHead));
      }
      if (
        url.origin === "https://pds.example.com" &&
        url.pathname === "/xrpc/com.atproto.sync.getRecord"
      ) {
        return Promise.resolve(
          new Response(new Uint8Array(input.proof).buffer),
        );
      }
      throw new Error("Unexpected test URL");
    },
  };
  return {
    input,
    checked,
    baseHead,
    document,
    options,
    queries,
    requests,
  };
}

describe("Space Lexicon resolution", () => {
  it("proves a record against stable authority, identity, and signed repo head", async () => {
    const fixture = await setup();
    const alternate = CID.parse(fixture.baseHead.cid).toString(base58btc);
    const result = await resolveSpaceLexiconProof(NSID, {
      ...fixture.options,
      fetch: (resource, init) => {
        const url = new URL(
          resource instanceof Request ? resource.url : resource.toString(),
        );
        if (url.pathname.endsWith("/com.atproto.sync.getLatestCommit")) {
          return Promise.resolve(
            Response.json({ ...fixture.baseHead, cid: alternate }),
          );
        }
        return fixture.options.fetch!(resource, init);
      },
    });
    expect(result.tag).toBe("proven");
    if (result.tag === "proven") {
      expect(result.head).toEqual({
        cid: fixture.baseHead.cid,
        revision: fixture.baseHead.rev,
      });
      expect(result.main.collections).toEqual(["com.example.note"]);
      expect(result.definitions).toBe("main-only");
      expect(Object.isFrozen(result)).toBe(true);
    }
    expect(fixture.queries).toEqual([
      "_lexicon.example.com",
      "_lexicon.example.com",
    ]);
    const recordUrl = new URL(
      fixture.requests.find((url) =>
        url.includes("com.atproto.sync.getRecord")
      )!,
    );
    expect(recordUrl.searchParams.get("did")).toBe(DID);
    expect(recordUrl.searchParams.get("collection")).toBe(
      "com.atproto.lexicon.schema",
    );
    expect(recordUrl.searchParams.get("rkey")).toBe(NSID);
  });

  it("retries a head change before accepting a stable proof", async () => {
    const fixture = await setup();
    const other = "bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua";
    const changed = { ...fixture.baseHead, cid: other };
    const consistent = { ...fixture.options };
    let heads = 0;
    consistent.fetch = (resource, init) => {
      const url = new URL(
        resource instanceof Request ? resource.url : resource.toString(),
      );
      if (url.pathname.endsWith("/com.atproto.sync.getLatestCommit")) {
        return Promise.resolve(
          Response.json(heads++ === 0 ? changed : fixture.baseHead),
        );
      }
      return fixture.options.fetch!(resource, init);
    };
    expect((await resolveSpaceLexiconProof(NSID, consistent)).tag).toBe(
      "proven",
    );
    expect(heads).toBe(4);
  });

  it("rejects a head that never stabilizes", async () => {
    const fixture = await setup();
    const changed = {
      ...fixture.baseHead,
      cid: "bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua",
    };
    let heads = 0;
    const unstable = {
      ...fixture.options,
      fetch: (resource: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(
          resource instanceof Request ? resource.url : resource.toString(),
        );
        if (url.pathname.endsWith("/com.atproto.sync.getLatestCommit")) {
          return Promise.resolve(
            Response.json(heads++ % 2 === 0 ? changed : fixture.baseHead),
          );
        }
        return fixture.options.fetch!(resource, init);
      },
    };
    expect(await resolveSpaceLexiconProof(NSID, unstable)).toEqual({
      tag: "unavailable",
      reason: "unstable",
    });
    expect(heads).toBe(4);
  });

  it("rejects a signed proof when the reported revision does not match", async () => {
    const fixture = await setup();
    const options = {
      ...fixture.options,
      fetch: (resource: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(
          resource instanceof Request ? resource.url : resource.toString(),
        );
        if (url.pathname.endsWith("/com.atproto.sync.getLatestCommit")) {
          return Promise.resolve(
            Response.json({ cid: fixture.baseHead.cid, rev: "3kbcq3p7ad42b" }),
          );
        }
        return fixture.options.fetch!(resource, init);
      },
    };
    expect(await resolveSpaceLexiconProof(NSID, options)).toEqual({
      tag: "invalid",
      reason: "proof",
    });
  });

  it("retries a transient proof mismatch", async () => {
    const fixture = await setup();
    const corrupt = Uint8Array.from(fixture.input.proof);
    corrupt[corrupt.length - 1] ^= 1;
    let proofs = 0;
    const options = {
      ...fixture.options,
      fetch: (resource: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(
          resource instanceof Request ? resource.url : resource.toString(),
        );
        if (
          url.origin === "https://pds.example.com" &&
          url.pathname === "/xrpc/com.atproto.sync.getRecord"
        ) {
          return Promise.resolve(
            new Response(
              new Uint8Array(proofs++ === 0 ? corrupt : fixture.input.proof)
                .buffer,
            ),
          );
        }
        return fixture.options.fetch!(resource, init);
      },
    };
    expect((await resolveSpaceLexiconProof(NSID, options)).tag).toBe("proven");
    expect(proofs).toBe(2);
  });

  it("does not accept an authority that changes during resolution", async () => {
    const fixture = await setup({
      dids: [
        DID,
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        DID,
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
      ],
    });
    expect(await resolveSpaceLexiconProof(NSID, fixture.options)).toEqual({
      tag: "unavailable",
      reason: "unstable",
    });
  });

  it("does not accept a signing key or PDS that changes during resolution", async () => {
    const fixture = await setup();
    const rotated = await P256Keypair.create();
    const changedKey = {
      ...fixture.document,
      verificationMethod: [{
        ...fixture.document.verificationMethod[0],
        publicKeyMultibase: rotated.did().slice(8),
      }],
    };
    const changedPds = {
      ...fixture.document,
      service: [{
        ...fixture.document.service[0],
        serviceEndpoint: "https://other.example.com",
      }],
    };
    for (const change of [changedKey, changedPds]) {
      let reads = 0;
      const options = {
        ...fixture.options,
        fetch: (resource: RequestInfo | URL, init?: RequestInit) => {
          const url = new URL(
            resource instanceof Request ? resource.url : resource.toString(),
          );
          if (url.hostname === "plc.directory") {
            return Promise.resolve(
              Response.json(reads++ % 2 ? change : fixture.document),
            );
          }
          return fixture.options.fetch!(resource, init);
        },
      };
      expect(await resolveSpaceLexiconProof(NSID, options)).toEqual({
        tag: "unavailable",
        reason: "unstable",
      });
    }
  });

  it("retries after a signing key rotates before the proof is fetched", async () => {
    const fixture = await setup();
    const oldKey = await P256Keypair.create();
    const oldDocument = {
      ...fixture.document,
      verificationMethod: [{
        ...fixture.document.verificationMethod[0],
        publicKeyMultibase: oldKey.did().slice(8),
      }],
    };
    let documentReads = 0;
    const options = {
      ...fixture.options,
      fetch: (resource: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(
          resource instanceof Request ? resource.url : resource.toString(),
        );
        if (
          url.origin === "https://plc.directory" && url.pathname === `/${DID}`
        ) {
          return Promise.resolve(
            Response.json(
              documentReads++ === 0 ? oldDocument : fixture.document,
            ),
          );
        }
        return fixture.options.fetch!(resource, init);
      },
    };
    expect((await resolveSpaceLexiconProof(NSID, options)).tag).toBe("proven");
    expect(documentReads).toBe(4);
  });

  it("resolves a signed Space Lexicon using a did:web authority", async () => {
    const did = "did:web:publisher.example.com";
    const key = await P256Keypair.create();
    const input = await validFixture(key, 4, did);
    const checked = await verifyLexiconProofAtTrustedHead(input);
    if (checked.tag !== "proven") throw new Error("Invalid test proof");
    const document = {
      id: did,
      verificationMethod: [{
        id: "#atproto",
        type: "Multikey",
        controller: did,
        publicKeyMultibase: key.did().slice(8),
      }],
      service: [{
        id: "#atproto_pds",
        type: "AtprotoPersonalDataServer",
        serviceEndpoint: "https://pds.example.com",
      }],
    };
    const result = await resolveSpaceLexiconProof(NSID, {
      resolveTxt: () => Promise.resolve([[`did=${did}`]]),
      fetch: (resource) => {
        const url = new URL(
          resource instanceof Request ? resource.url : resource.toString(),
        );
        if (url.href === "https://publisher.example.com/.well-known/did.json") {
          return Promise.resolve(Response.json(document));
        }
        if (
          url.origin === "https://pds.example.com" &&
          url.pathname === "/xrpc/com.atproto.sync.getLatestCommit"
        ) {
          return Promise.resolve(
            Response.json({ cid: checked.headCid, rev: checked.revision }),
          );
        }
        if (
          url.origin === "https://pds.example.com" &&
          url.pathname === "/xrpc/com.atproto.sync.getRecord"
        ) {
          return Promise.resolve(
            new Response(new Uint8Array(input.proof).buffer),
          );
        }
        throw new Error("Unexpected test URL");
      },
    });
    expect(result.tag).toBe("proven");
    if (result.tag === "proven") expect(result.main.publisherDid).toBe(did);
  });

  it("rejects a tampered proof, invalid head and unsupported DID methods", async () => {
    const fixture = await setup();
    const corrupt = Uint8Array.from(fixture.input.proof);
    corrupt[corrupt.length - 1] ^= 1;
    const badProof = {
      ...fixture.options,
      fetch: (resource: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(
          resource instanceof Request ? resource.url : resource.toString(),
        );
        return url.pathname.endsWith("/com.atproto.sync.getRecord")
          ? Promise.resolve(new Response(corrupt.buffer))
          : fixture.options.fetch!(resource, init);
      },
    };
    expect(await resolveSpaceLexiconProof(NSID, badProof)).toEqual({
      tag: "invalid",
      reason: "proof",
    });
    const badHead = {
      ...fixture.options,
      fetch: (resource: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(
          resource instanceof Request ? resource.url : resource.toString(),
        );
        return url.pathname.endsWith("/com.atproto.sync.getLatestCommit")
          ? Promise.resolve(Response.json({ cid: "bad", rev: "bad" }))
          : fixture.options.fetch!(resource, init);
      },
    };
    expect(await resolveSpaceLexiconProof(NSID, badHead)).toEqual({
      tag: "invalid",
      reason: "head",
    });
    const unsupported = await setup({ dids: ["did:web:localhost"] });
    expect(await resolveSpaceLexiconProof(NSID, unsupported.options)).toEqual({
      tag: "invalid",
      reason: "identity",
    });
    expect(unsupported.requests).toHaveLength(0);
  });

  it("stops before network I/O when cancelled and does not accept a late DNS answer", async () => {
    const controller = new AbortController();
    let complete: (value: unknown) => void = () => {};
    let requests = 0;
    const pending = resolveSpaceLexiconProof(NSID, {
      signal: controller.signal,
      resolveTxt: () =>
        new Promise((resolve) => {
          complete = resolve;
        }),
      fetch: () => {
        requests++;
        throw new Error("Unexpected fetch");
      },
    });
    await Promise.resolve();
    controller.abort();
    expect(await pending).toEqual({ tag: "unavailable", reason: "aborted" });
    complete([[`did=${DID}`]]);
    await Promise.resolve();
    expect(requests).toBe(0);
  });

  it("applies one deadline while the authority lookup is pending", async () => {
    let complete: (value: unknown) => void = () => {};
    const result = await resolveSpaceLexiconProof(NSID, {
      timeoutMs: 5,
      resolveTxt: () =>
        new Promise((resolve) => {
          complete = resolve;
        }),
      fetch: () => {
        throw new Error("Unexpected fetch");
      },
    });
    expect(result).toEqual({ tag: "unavailable", reason: "timeout" });
    complete([[`did=${DID}`]]);
    await Promise.resolve();
  });
});
