import { expect } from "@std/expect";
import { resolveSpaceLexiconProof } from "../src/lib/spaces/lexicon-resolution";

const configPath = Deno.env.get("ALTERAN_REFERENCE_INTEROP_CONFIG");

Deno.test({
  name: "reference PDS: prove a published Space Lexicon",
  ignore: !configPath,
  fn: withReferenceErrors(async () => {
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

    let attempted = false;
    try {
      attempted = true;
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
        expect(result.main.spaceType === nsid).toBe(true);
        expect(result.main.publisherDid === did).toBe(true);
        expect(result.main.collections.length === 1 && result.main.collections[0] === "com.example.note").toBe(true);
        expect(result.definitions).toBe("main-only");
      }
      expect(txtQueries).toBe(2);
    } finally {
      if (attempted) {
        await post("com.atproto.repo.deleteRecord", {
          repo: did,
          collection,
          rkey: nsid,
        });
      }
    }
  }),
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


function withReferenceErrors<T>(action: () => T | Promise<T>): () => Promise<T> {
  return async () => {
    try {
      return await action();
    } catch {
      throw new Error('Reference interoperability failed');
    }
  };
}

Deno.test('reference failure output excludes private input', async () => {
  const sentinel = 'harmless-private-sentinel';
  const malformed = `{"accessJwt":${sentinel}}`;
  const path = await Deno.makeTempFile();
  try {
    await Deno.writeTextFile(path, malformed);
    const failures = [
      async () => JSON.parse(await Deno.readTextFile(path)),
      () => new URL(`http://[${sentinel}`),
      () => new Headers({ authorization: `Bearer ${sentinel}\0` }),
      () => JSON.parse(malformed),
      () => { throw new Error(`server response: ${sentinel}`); },
    ];
    for (const failure of failures) {
      let caught: unknown;
      try {
        await withReferenceErrors(failure)();
      } catch (error) {
        caught = error;
      }
      expect(caught instanceof Error && caught.message === 'Reference interoperability failed').toBe(true);
      expect(caught instanceof Error && typeof caught.stack === 'string' && !caught.stack.includes(sentinel)).toBe(true);
    }
  } finally {
    await Deno.remove(path);
  }
});
