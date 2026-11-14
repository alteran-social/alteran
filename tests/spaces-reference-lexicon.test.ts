import { expect } from "@std/expect";
import { resolveSpaceLexiconProof } from "../src/lib/spaces/lexicon-resolution";

const configPath = Deno.env.get("ALTERAN_REFERENCE_INTEROP_CONFIG");

Deno.test({
  name: "reference PDS: prove a published Space Lexicon",
  ignore: !configPath,
  async fn() {
    const config = JSON.parse(await Deno.readTextFile(configPath!));
    const pds = loopbackOrigin(config.pds);
    const plc = loopbackOrigin(config.plc);
    if (
      typeof config.did !== "string" || typeof config.accessJwt !== "string" ||
      !config.accessJwt
    ) {
      throw new Error("Invalid disposable reference account");
    }
    const did: string = config.did;
    const nsid = `com.example.reference${
      crypto.randomUUID().replaceAll("-", "")
    }`;
    const collection = "com.atproto.lexicon.schema";
    const headers = {
      Authorization: `Bearer ${config.accessJwt}`,
      "Content-Type": "application/json",
    };
    const post = async (method: string, body: unknown) => {
      const response = await fetch(`${pds}/xrpc/${method}`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        redirect: "manual",
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error(`${method} returned HTTP ${response.status}`);
      }
      return response;
    };

    let created = false;
    try {
      await post("com.atproto.repo.createRecord", {
        repo: did,
        collection,
        rkey: nsid,
        validate: false,
        record: {
          $type: collection,
          lexicon: 1,
          id: nsid,
          defs: {
            main: {
              type: "space",
              key: "any",
              collections: ["com.example.note"],
            },
          },
        },
      });
      created = true;
      let txtQueries = 0;
      // The disposable services use loopback HTTP; the adapter maps their
      // identity and PDS to test HTTPS origins while retaining real signed CARs.
      const result = await resolveSpaceLexiconProof(nsid, {
        resolveTxt: (name) => {
          expect(name).toBe("_lexicon.example.com");
          txtQueries++;
          return Promise.resolve([[`did=${did}`]]);
        },
        fetch: async (input, init) => {
          const url = new URL(
            input instanceof Request ? input.url : input.toString(),
          );
          if (
            url.origin === "https://plc.directory" && url.pathname === `/${did}`
          ) {
            const response = await fetch(`${plc}/${encodeURIComponent(did)}`, {
              ...init,
              redirect: "manual",
            });
            if (!response.ok) return response;
            const document = await response.json() as {
              service?: { id?: string; serviceEndpoint?: string }[];
            };
            const service = document.service?.find((entry) =>
              entry.id === "#atproto_pds" || entry.id === `${did}#atproto_pds`
            );
            if (!service) throw new Error("Reference DID has no PDS service");
            service.serviceEndpoint = "https://pds.example.com";
            return Response.json(document);
          }
          if (
            url.origin === "https://pds.example.com" &&
            [
              "/xrpc/com.atproto.sync.getLatestCommit",
              "/xrpc/com.atproto.sync.getRecord",
            ].includes(url.pathname)
          ) {
            return await fetch(`${pds}${url.pathname}${url.search}`, {
              ...init,
              redirect: "manual",
            });
          }
          throw new Error("Unexpected reference URL");
        },
      });
      expect(result.tag).toBe("proven");
      if (result.tag === "proven") {
        expect(result.main.spaceType).toBe(nsid);
        expect(result.main.publisherDid).toBe(did);
        expect(result.main.collections).toEqual(["com.example.note"]);
        expect(result.definitions).toBe("main-only");
      }
      expect(txtQueries).toBe(2);
    } finally {
      if (created) {
        await post("com.atproto.repo.deleteRecord", {
          repo: did,
          collection,
          rkey: nsid,
        });
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
