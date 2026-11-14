import {
  COMMIT_MAC_PROFILE,
  createSpaceSigHeaders,
  encapsulate,
  formatMacRequest,
  isP256DidKey,
  type MacProfile,
  RECORD_MAC_PROFILE,
  type SpaceCommit,
  spaceHostAud,
  verifyCommit,
  verifyRecord,
  verifySpaceToken,
} from "@atproto/space";
import {
  formatDidVerificationMethod,
  P256Keypair,
} from "@atproto/crypto-spaces";
import {
  isSpaceAtUriString,
  isValidDid,
  SpaceRef,
} from "@atproto/syntax-spaces";
import { expect } from "@std/expect";
import {
  readSpaceRepoArchive,
  writeSpaceRepoArchive,
} from "../src/lib/spaces/repo-archive";
import {
  applySpaceSetHashChanges,
  spaceRecordHashElement,
  spaceSetHashDigest,
} from "../src/lib/spaces/lthash";
import { encodeRecordBlock } from "../src/services/repo/blockstore-ops";
import { verifySpaceCredential } from "../src/lib/spaces/credential-verifier";
import { checkSpaceKemIdentity } from "../src/lib/spaces/kem-identity";
import { authoritySigningKey } from "../src/lib/spaces/authority-document";

// Set ALTERAN_REFERENCE_INTEROP_CONFIG to a JSON file containing pds, plc,
// did, and accessJwt for a disposable local reference-PDS account.
const configPath = Deno.env.get("ALTERAN_REFERENCE_INTEROP_CONFIG");

Deno.test({
  name: "reference PDS: STAR import/export and response MAC interoperability",
  ignore: !configPath,
  async fn() {
    const config = JSON.parse(await Deno.readTextFile(configPath!));
    const pds = loopbackOrigin(config.pds);
    const plc = loopbackOrigin(config.plc);
    if (
      !isValidDid(config.did) || typeof config.accessJwt !== "string" ||
      !config.accessJwt
    ) {
      throw new Error("Invalid disposable reference account");
    }
    const repo = config.did as `did:${string}:${string}`;
    const authorization = `Bearer ${config.accessJwt}`;
    const skey = `interop-${crypto.randomUUID()}`;
    const space = `at://${repo}/space/com.example.note/${skey}`;
    const rpc = async (nsid: string, init: RequestInit = {}) => {
      const headers = new Headers(init.headers);
      headers.set("Authorization", authorization);
      const response = await localFetch(`${pds}/xrpc/${nsid}`, {
        ...init,
        headers,
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error(`${nsid} returned HTTP ${response.status}`);
      }
      return response;
    };
    const postJson = (nsid: string, value: unknown) =>
      rpc(nsid, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(value),
      });

    const didResponse = await localFetch(`${plc}/${encodeURIComponent(repo)}`, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!didResponse.ok) throw new Error("Local DID lookup failed");
    const doc = await didResponse.json() as {
      id?: string;
      verificationMethod?: {
        id?: string;
        controller?: string;
        type?: string;
        publicKeyMultibase?: string;
      }[];
    };
    const methods = doc.verificationMethod?.filter((entry: { id?: string }) =>
      entry.id === "#atproto_kem" || entry.id === `${repo}#atproto_kem`
    );
    const method = methods?.[0];
    if (
      doc.id !== repo || methods?.length !== 1 || method?.controller !== repo ||
      !method.type || !method.publicKeyMultibase
    ) {
      throw new Error("Local DID has no valid KEM method");
    }
    const kemKey = formatDidVerificationMethod({
      type: method.type,
      publicKeyMultibase: method.publicKeyMultibase,
    });
    if (
      !isP256DidKey(kemKey) ||
      checkSpaceKemIdentity(repo, kemKey, doc) !== "ready"
    ) {
      throw new Error("Invalid KEM key");
    }
    const signedGet = async (
      nsid: string,
      parameters: Record<string, string>,
      profile: MacProfile,
    ) => {
      const shared = await encapsulate(kemKey);
      const response = await rpc(`${nsid}?${new URLSearchParams(parameters)}`, {
        headers: {
          "Accept-Signature": formatMacRequest(profile, shared.keyShare),
        },
      });
      return { response, ...shared };
    };

    let createdSpace = false;
    try {
      const creation = await postJson("com.atproto.space.createSpace", {
        spaceType: "com.example.note",
        skey,
        policy: { $type: "com.atproto.personalspace.policy" },
      });
      createdSpace = true;
      const created = await creation.json() as { space?: string };
      if (created.space !== space) {
        throw new Error("Reference PDS created an unexpected space");
      }
      await postJson("com.atproto.space.createRecord", {
        space,
        repo,
        collection: "com.example.note",
        rkey: "fixture-1",
        validate: false,
        record: { $type: "com.example.note", text: "Reference fixture" },
      });

      const exported = await signedGet("com.atproto.space.getRepo", {
        space,
        repo,
      }, COMMIT_MAC_PROFILE);
      const archive = await readSpaceRepoArchive(
        new Uint8Array(await exported.response.arrayBuffer()),
        { space, repo },
      );
      const commit: SpaceCommit = {
        ver: 1,
        space: SpaceRef.parse(space).toString(),
        repo,
        rev: archive.rev,
        data: archive.data,
      };
      verifyCommit(commit, {
        ...exported,
        headers: exported.response.headers,
        space: commit.space,
        repo: commit.repo,
      });
      expect(archive.records).toHaveLength(1);

      const [cid, value] = await encodeRecordBlock({
        $type: "com.example.note",
        text: "Alteran archive fixture",
      });
      const added = {
        collection: "com.example.note",
        rkey: "fixture-2",
        cid: cid.toString(),
        value,
      };
      const records = [...archive.records, added];
      const state = applySpaceSetHashChanges(
        null,
        records.map((record) => ({
          action: "add",
          element: spaceRecordHashElement(
            record.collection,
            record.rkey,
            record.cid,
          ),
        })),
      );
      const data = spaceSetHashDigest(state);
      const bytes = await writeSpaceRepoArchive({ ...archive, records, data });
      await rpc("com.atproto.space.importRepo", {
        method: "POST",
        headers: { "Content-Type": "application/vnd.dasl.star" },
        body: new Uint8Array(bytes).buffer,
      });

      const received = await signedGet("com.atproto.space.getRecord", {
        space,
        repo,
        collection: added.collection,
        rkey: added.rkey,
      }, RECORD_MAC_PROFILE);
      const record = await received.response.json() as Parameters<
        typeof verifyRecord
      >[0];
      const uri = `${space}/${repo}/${added.collection}/${added.rkey}`;
      if (!isSpaceAtUriString(uri)) {
        throw new Error("Invalid expected record URI");
      }
      await verifyRecord(record, {
        ...received,
        headers: received.response.headers,
        uri,
      });
      expect(record.cid).toBe(added.cid);
      expect(record.value.text).toBe("Alteran archive fixture");

      const delegation = await (await rpc(
        `com.atproto.space.getDelegationToken?${new URLSearchParams({
          space,
        })}`,
      )).json() as { token: string };
      const holder = await P256Keypair.create();
      const authorityKey = authoritySigningKey(repo, doc);
      if (!authorityKey) {
        throw new Error("Local DID has no valid signing method");
      }
      await verifySpaceToken("delegation", delegation.token, {
        getSigningKey: () => authorityKey,
        sub: space,
        aud: spaceHostAud(repo),
      });
      const issued =
        await (await postJson("com.atproto.space.authorizeSpaceSync", {
          space,
          credentialKey: holder.did(),
          delegationToken: delegation.token,
        })).json() as { credential: string };
      const replay = await localFetch(
        `${pds}/xrpc/com.atproto.space.authorizeSpaceSync`,
        {
          method: "POST",
          headers: {
            Authorization: authorization,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            space,
            credentialKey: holder.did(),
            delegationToken: delegation.token,
          }),
          signal: AbortSignal.timeout(10_000),
        },
      );
      expect(replay.status).toBe(400);
      await replay.body?.cancel();
      const proof = await createSpaceSigHeaders({
        authorization: `Atproto-Space-Credential ${issued.credential}`,
        audience: repo,
        keypair: holder,
      });
      const verifyOptions = {
        space,
        expectedAudience: repo,
        headers: new Headers(proof.headers),
        getAuthoritySigningKey: () => Promise.resolve(authorityKey),
        isRevoked: () => Promise.resolve(false),
      };
      expect((await verifySpaceCredential(verifyOptions)).tag).toBe(
        "authorized",
      );
      expect(
        (await verifySpaceCredential({
          ...verifyOptions,
          isRevoked: () => Promise.resolve(true),
        })).tag,
      )
        .toBe("invalid");

      const credentialMac = await encapsulate(kemKey);
      const credentialHeaders = new Headers(proof.headers);
      credentialHeaders.set(
        "Accept-Signature",
        formatMacRequest(RECORD_MAC_PROFILE, credentialMac.keyShare),
      );
      const credentialQuery = new URLSearchParams({
        space,
        repo,
        collection: added.collection,
        rkey: added.rkey,
      });
      const credentialUrl =
        `${pds}/xrpc/com.atproto.space.getRecord?${credentialQuery}`;
      const credentialResponse = await localFetch(
        credentialUrl,
        {
          headers: credentialHeaders,
          signal: AbortSignal.timeout(10_000),
        },
      );
      if (!credentialResponse.ok) {
        throw new Error(
          `Credential read returned HTTP ${credentialResponse.status}`,
        );
      }
      const credentialRecord = await credentialResponse.json() as Parameters<
        typeof verifyRecord
      >[0];
      await verifyRecord(credentialRecord, {
        ...credentialMac,
        headers: credentialResponse.headers,
        uri,
      });
      expect(credentialRecord.cid).toBe(added.cid);

      const missingProofHeaders = new Headers(credentialHeaders);
      missingProofHeaders.delete("signature");
      const missingProof = await localFetch(credentialUrl, {
        headers: missingProofHeaders,
        signal: AbortSignal.timeout(10_000),
      });
      expect(missingProof.status).toBe(401);
      await missingProof.body?.cancel();

      const wrongAudience = await createSpaceSigHeaders({
        authorization: `Atproto-Space-Credential ${issued.credential}`,
        audience: "did:plc:wrong",
        keypair: holder,
      });
      const wrongAudienceHeaders = new Headers(wrongAudience.headers);
      wrongAudienceHeaders.set(
        "Accept-Signature",
        formatMacRequest(RECORD_MAC_PROFILE, credentialMac.keyShare),
      );
      const rejectedAudience = await localFetch(credentialUrl, {
        headers: wrongAudienceHeaders,
        signal: AbortSignal.timeout(10_000),
      });
      expect(rejectedAudience.status).toBe(401);
      await rejectedAudience.body?.cancel();

      const latest = await signedGet("com.atproto.space.getLatestCommit", {
        space,
        repo,
      }, COMMIT_MAC_PROFILE);
      const raw = (await latest.response.json() as {
        commit: Omit<SpaceCommit, "data"> & { data: { $bytes: string } };
      }).commit;
      const encoded = raw.data.$bytes.replaceAll("-", "+").replaceAll("_", "/");
      const finalCommit = {
        ...raw,
        data: Uint8Array.from(
          atob(encoded),
          (character) => character.charCodeAt(0),
        ),
      };
      verifyCommit(finalCommit, {
        ...latest,
        headers: latest.response.headers,
        space: commit.space,
        repo: commit.repo,
      });
      expect(finalCommit.data).toEqual(data);
      expect(() =>
        verifyCommit({ ...finalCommit, data: new Uint8Array(32) }, {
          ...latest,
          headers: latest.response.headers,
          space: commit.space,
          repo: commit.repo,
        })
      ).toThrow();
    } finally {
      if (createdSpace) {
        await postJson("com.atproto.space.deleteSpace", { space });
      }
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
    throw new Error(
      "Reference interoperability tests only support loopback HTTP origins",
    );
  }
  return url.origin;
}

function localFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const url = new URL(input);
  loopbackOrigin(url.origin);
  if (url.username || url.password) {
    throw new Error("Credentials in test URLs are not allowed");
  }
  return fetch(url, { ...init, redirect: "manual" });
}

Deno.test("reference interop requests do not follow redirects", async () => {
  let received = false;
  const target = Deno.serve(
    { hostname: "127.0.0.1", port: 0, onListen() {} },
    () => {
      received = true;
      return new Response("unexpected");
    },
  );
  const targetAddr = target.addr as Deno.NetAddr;
  const source = Deno.serve(
    { hostname: "127.0.0.1", port: 0, onListen() {} },
    () =>
      new Response(null, {
        status: 307,
        headers: { Location: `http://127.0.0.1:${targetAddr.port}/` },
      }),
  );
  try {
    const sourceAddr = source.addr as Deno.NetAddr;
    const response = await localFetch(`http://127.0.0.1:${sourceAddr.port}/`, {
      method: "POST",
      body: "test",
    });
    expect(response.status).toBe(307);
    expect(received).toBe(false);
  } finally {
    await source.shutdown();
    await target.shutdown();
  }
});
