import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from "./helpers/env";
import { makeDpopKey, signResourceDpop } from "./helpers/oauth";
import { createOAuthSession, storeRefreshToken } from "../src/db/account";
import { AuthScope } from "../src/lib/auth-scope";
import { issueSessionTokens } from "../src/lib/session-tokens";
import { GET as getServiceAuth } from "../src/pages/xrpc/com.atproto.server.getServiceAuth";

const did = "did:example:test";
const clientId = "https://client.example/metadata";
const signingKey = "8b5e3d226b44c4c88fbd3d4529f6283fb2b20f6deee8a0b34e7f0a9b12d3e4f1";
const audience = "did:web:api.bsky.chat#bsky_chat";

const CHAT_METHODS = [
  "chat.bsky.convo.acceptConvo",
  "chat.bsky.convo.addReaction",
  "chat.bsky.convo.removeReaction",
  "chat.bsky.convo.listConvoRequests",
  "chat.bsky.convo.updateAllRead",
  "chat.bsky.convo.getConvoAvailability",
  "chat.bsky.group.createGroup",
  "chat.bsky.convo.sendMessage",
  "chat.bsky.futureMethod",
] as const;

const PRIVILEGED_CASE_VARIANTS = [
  "CHAT.BSKY.CONVO.FUTUREMETHOD",
  "com.atproto.server.createAccount",
  "com.atproto.server.createaccount",
] as const;

function apiContext(env: Awaited<ReturnType<typeof makeEnv>>, request: Request) {
  return { locals: { env }, request } as never;
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const payload = token.split(".")[1];
  if (!payload) throw new Error("missing payload");
  const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return JSON.parse(atob(padded));
}

function serviceAuthEnv() {
  return makeEnv({ REPO_SIGNING_KEY: signingKey });
}

async function bearerToken(env: Awaited<ReturnType<typeof makeEnv>>, scope: string): Promise<string> {
  return (await issueSessionTokens(env, did, { accessScope: scope })).accessJwt;
}

async function oauthToken(
  env: Awaited<ReturnType<typeof makeEnv>>,
  key: Awaited<ReturnType<typeof makeDpopKey>>,
  scope: string,
): Promise<string> {
  const sessionId = crypto.randomUUID().replace(/-/g, "");
  const accessJti = crypto.randomUUID().replace(/-/g, "");
  const { accessJwt, accessPayload, refreshPayload, refreshExpiry } = await issueSessionTokens(
    env,
    did,
    {
      accessScope: scope,
      clientId,
      dpopJkt: key.jkt,
      oauthSessionId: sessionId,
      accessJti,
    },
  );
  await createOAuthSession(env, {
    id: sessionId,
    did,
    clientId,
    clientAuthMethod: "none",
    clientAuthKeyId: null,
    dpopJkt: key.jkt,
    scope,
    currentRefreshTokenId: refreshPayload.jti,
    accessJti: String(accessPayload.jti),
    expiresAt: refreshExpiry,
  });
  await storeRefreshToken(env, {
    id: refreshPayload.jti,
    did,
    expiresAt: refreshExpiry,
    tokenKind: "oauth",
    oauthSessionId: sessionId,
    clientId,
    clientAuthMethod: "none",
    dpopJkt: key.jkt,
    oauthScope: scope,
    accessJti: String(accessPayload.jti),
  });
  return accessJwt;
}

function serviceAuthUrl(lexiconMethod: string): string {
  const params = new URLSearchParams({ aud: audience, lxm: lexiconMethod });
  return `https://pds.example/xrpc/com.atproto.server.getServiceAuth?${params.toString()}`;
}

function callBearer(
  env: Awaited<ReturnType<typeof makeEnv>>,
  token: string,
  lexiconMethod: string,
): Promise<Response> {
  return getServiceAuth(apiContext(env, new Request(serviceAuthUrl(lexiconMethod), {
    headers: { authorization: `Bearer ${token}` },
  })));
}

async function callDpop(
  env: Awaited<ReturnType<typeof makeEnv>>,
  token: string,
  key: Awaited<ReturnType<typeof makeDpopKey>>,
  lexiconMethod: string,
): Promise<Response> {
  const url = serviceAuthUrl(lexiconMethod);
  const proof = await signResourceDpop(env, key, "GET", url, token);
  return getServiceAuth(apiContext(env, new Request(url, {
    headers: { authorization: `DPoP ${token}`, dpop: proof },
  })));
}

function privilegedDenial(lexiconMethod: string) {
  return {
    error: "InvalidRequest",
    message: `insufficient access to request a service auth token for the following method: ${lexiconMethod}`,
  };
}

async function expectMinted(response: Response, lexiconMethod: string) {
  expect(response.status).toBe(200);
  const { token } = await response.json() as { token: string };
  expect(decodeJwtPayload(token).lxm).toBe(lexiconMethod);
}

describe("getServiceAuth chat.bsky privileged access", () => {
  it("refuses an ordinary app password for every chat.bsky method", async () => {
    const env = await serviceAuthEnv();
    const token = await bearerToken(env, AuthScope.AppPass);
    for (const lexiconMethod of CHAT_METHODS) {
      const response = await callBearer(env, token, lexiconMethod);
      expect({ lexiconMethod, status: response.status, body: await response.json() }).toEqual({
        lexiconMethod,
        status: 400,
        body: privilegedDenial(lexiconMethod),
      });
    }
  });

  it("mints chat service auth for a privileged app password", async () => {
    const env = await serviceAuthEnv();
    const token = await bearerToken(env, AuthScope.AppPassPrivileged);
    for (const lexiconMethod of CHAT_METHODS) {
      await expectMinted(await callBearer(env, token, lexiconMethod), lexiconMethod);
    }
  });

  it("mints chat service auth for a full session", async () => {
    const env = await serviceAuthEnv();
    const token = await bearerToken(env, AuthScope.Access);
    for (const lexiconMethod of CHAT_METHODS) {
      await expectMinted(await callBearer(env, token, lexiconMethod), lexiconMethod);
    }
  });

  it("refuses case-variant privileged methods for an ordinary app password and keeps the caller casing", async () => {
    const env = await serviceAuthEnv();
    const token = await bearerToken(env, AuthScope.AppPass);
    for (const lexiconMethod of PRIVILEGED_CASE_VARIANTS) {
      const response = await callBearer(env, token, lexiconMethod);
      expect({ lexiconMethod, status: response.status, body: await response.json() }).toEqual({
        lexiconMethod,
        status: 400,
        body: privilegedDenial(lexiconMethod),
      });
    }
  });

  it("mints case-variant privileged methods for a privileged app password", async () => {
    const env = await serviceAuthEnv();
    const token = await bearerToken(env, AuthScope.AppPassPrivileged);
    for (const lexiconMethod of PRIVILEGED_CASE_VARIANTS) {
      await expectMinted(await callBearer(env, token, lexiconMethod), lexiconMethod);
    }
  });

  it("mints case-variant privileged methods for a full session", async () => {
    const env = await serviceAuthEnv();
    const token = await bearerToken(env, AuthScope.Access);
    for (const lexiconMethod of PRIVILEGED_CASE_VARIANTS) {
      await expectMinted(await callBearer(env, token, lexiconMethod), lexiconMethod);
    }
  });

  it("allows an ordinary app password to mint service auth outside the privileged prefix", async () => {
    const env = await serviceAuthEnv();
    const token = await bearerToken(env, AuthScope.AppPass);
    for (const lexiconMethod of ["chat.bskyish.futureMethod", "com.atproto.server.createAccountExtra", "app.bsky.feed.getTimeline"]) {
      await expectMinted(await callBearer(env, token, lexiconMethod), lexiconMethod);
    }
  });

  it("refuses a case-variant protected method for every access-token kind", async () => {
    const env = await serviceAuthEnv();
    const lexiconMethod = "com.atproto.server.UpdateEmail";
    for (const scope of [AuthScope.AppPass, AuthScope.AppPassPrivileged, AuthScope.Access]) {
      const response = await callBearer(env, await bearerToken(env, scope), lexiconMethod);
      expect({ scope, status: response.status, body: await response.json() }).toEqual({
        scope,
        status: 401,
        body: { error: "InvalidToken", message: "token does not grant access to this resource" },
      });
    }
  });

  it("refuses chat methods for transition:generic and allows transition:chat.bsky", async () => {
    const env = await serviceAuthEnv();
    const genericKey = await makeDpopKey();
    const generic = await oauthToken(env, genericKey, "atproto transition:generic");
    for (const lexiconMethod of ["chat.bsky.convo.acceptConvo", "CHAT.BSKY.convo.sendMessage"]) {
      const response = await callDpop(env, generic, genericKey, lexiconMethod);
      expect({ lexiconMethod, status: response.status, body: await response.json() }).toEqual({
        lexiconMethod,
        status: 401,
        body: { error: "InvalidToken", message: "token does not grant access to this resource" },
      });
    }

    const chatKey = await makeDpopKey();
    const chat = await oauthToken(env, chatKey, "atproto transition:generic transition:chat.bsky");
    await expectMinted(await callDpop(env, chat, chatKey, "chat.bsky.convo.acceptConvo"), "chat.bsky.convo.acceptConvo");
    await expectMinted(await callDpop(env, chat, chatKey, "CHAT.BSKY.convo.sendMessage"), "CHAT.BSKY.convo.sendMessage");
  });
});
