import { expect } from "@std/expect";
import { Secp256k1Keypair } from "@atproto/crypto";
import type { Env } from "../src/env";
import { authenticateRequest } from "../src/lib/auth";
import { getRuntimeString, resolveEnvSecrets } from "../src/lib/secrets";
import { createServiceJwt } from "../src/lib/appview/service-jwt";
import { issueSessionTokens } from "../src/lib/session-tokens";
import { describe, it } from "./helpers/bdd";
import { makeEnv } from "./helpers/env";

const did = "did:example:test";
const tokenRequest = (token: string) =>
  new Request("https://pds.example/xrpc/com.atproto.server.getSession", {
    headers: { authorization: `Bearer ${token}` },
  });

describe("request environment isolation", () => {
  it("keeps string, Secret Store and explicit defaults scoped to the supplied Env", async () => {
    const secret = crypto.randomUUID() + crypto.randomUUID();
    const foreign = await makeEnv({ USER_PASSWORD: secret, PDS_DID: did });
    const local = await makeEnv({
      USER_PASSWORD: undefined,
      PDS_DID: undefined,
    });
    await resolveEnvSecrets(foreign);
    expect((await getRuntimeString(local, "USER_PASSWORD", "")) === "").toBe(
      true,
    );
    expect(
      (await getRuntimeString(local, "PDS_DID", "fallback")) === "fallback",
    ).toBe(true);
    expect((await getRuntimeString(foreign, "USER_PASSWORD", "")) === secret)
      .toBe(true);
    const store = { ...local, USER_PASSWORD: { get: async () => secret } };
    expect((await getRuntimeString(store, "USER_PASSWORD", "")) === secret)
      .toBe(true);
    let blankRejected = false;
    try {
      await getRuntimeString(
        { ...local, USER_PASSWORD: "" },
        "USER_PASSWORD",
        "fallback",
      );
    } catch {
      blankRejected = true;
    }
    expect(blankRejected).toBe(true);
    const broken = {
      ...local,
      USER_PASSWORD: {
        get: async () => {
          throw new Error("unavailable");
        },
      },
    };
    let failed = false;
    try {
      await getRuntimeString(broken, "USER_PASSWORD", "fallback");
    } catch {
      failed = true;
    }
    expect(failed).toBe(true);
    let boundaryFailed = false;
    try {
      await resolveEnvSecrets(broken);
    } catch {
      boundaryFailed = true;
    }
    expect(boundaryFailed).toBe(true);
  });

  it("isolates modern signing keys even for equal audiences and validates distinct audiences", async () => {
    const secret = crypto.randomUUID() + crypto.randomUUID();
    const foreign = await makeEnv({ PDS_DID: did, SESSION_JWT_SECRET: secret });
    const local = await makeEnv({
      PDS_DID: did,
      SESSION_JWT_SECRET: undefined,
    });
    await resolveEnvSecrets(foreign);
    const issued = await issueSessionTokens(foreign, did);
    expect(
      (await authenticateRequest(tokenRequest(issued.accessJwt), local)) ===
        null,
    ).toBe(true);
    const own = await issueSessionTokens(local, did);
    expect(
      (await authenticateRequest(tokenRequest(own.accessJwt), local)) !== null,
    ).toBe(true);
    const differentAudience = {
      ...local,
      PDS_DID: "did:example:other",
      SESSION_JWT_SECRET: secret,
    };
    expect(
      (await authenticateRequest(
        tokenRequest(issued.accessJwt),
        differentAudience,
      )) === null,
    ).toBe(true);
    const noIdentity = {
      ...local,
      PDS_DID: undefined,
      SESSION_JWT_SECRET: secret,
    };
    expect(
      (await authenticateRequest(
        tokenRequest(issued.accessJwt),
        noIdentity,
      )) === null,
    ).toBe(true);
    const store = {
      ...foreign,
      SESSION_JWT_SECRET: { get: async () => secret },
      PDS_DID: { get: async () => did },
    };
    const storeTokens = await issueSessionTokens(store, did);
    expect(
      (await authenticateRequest(
        tokenRequest(storeTokens.accessJwt),
        store,
      )) !== null,
    ).toBe(true);
    const padded = { ...foreign, SESSION_JWT_SECRET: ` ${secret} ` };
    const paddedTokens = await issueSessionTokens(padded, did);
    expect(
      (await authenticateRequest(
        tokenRequest(paddedTokens.accessJwt),
        padded,
      )) !== null,
    ).toBe(true);
    expect(
      (await authenticateRequest(
        tokenRequest(paddedTokens.accessJwt),
        foreign,
      )) === null,
    ).toBe(true);
  });

  it("does not inherit another Env's service signing key", async () => {
    const foreign = await makeEnv();
    const local = await makeEnv({ REPO_SIGNING_KEY: undefined });
    const pair = await Secp256k1Keypair.create({ exportable: true });
    const key = Array.from(await pair.export()).map((byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("");
    const signedEnv = {
      ...foreign,
      REPO_SIGNING_KEY: { get: async () => key },
    };
    await resolveEnvSecrets(signedEnv);
    let missing = false;
    try {
      await createServiceJwt(local, did, "did:example:service", null);
    } catch {
      missing = true;
    }
    expect(missing).toBe(true);
    expect(
      (await createServiceJwt(signedEnv, did, "did:example:service", null))
        .split(".").length,
    ).toBe(3);
  });

  it("never logs malformed bearer header or payload content", async () => {
    const env = await makeEnv();
    const marker = "JWT_LOG_REDACTION_MARKER";
    const malformed = btoa(marker).replaceAll("=", "");
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replaceAll("=", "");
    const tokens = [`${malformed}.e30.eA`, `${header}.${malformed}.eA`];
    const messages: string[] = [];
    const previous = console.error;
    try {
      console.error = (...values: unknown[]) => {
        messages.push(values.map(String).join(" "));
      };
      for (const token of tokens) {
        expect((await authenticateRequest(tokenRequest(token), env)) === null)
          .toBe(true);
      }
    } finally {
      console.error = previous;
    }
    expect(
      messages.some((message) => message.includes("JWT verification failed")),
    ).toBe(true);
    expect(
      messages.every((message) =>
        !message.includes(marker) &&
        tokens.every((token) => !message.includes(token))
      ),
    ).toBe(true);
  });
});
