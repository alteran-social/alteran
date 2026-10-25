import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from "./helpers/env";
import { AuthScope, bearerAccessContext, oauthAccessContext } from "../src/lib/auth-scope";
import { proxyAppView } from "../src/lib/appview/proxy";
import { issueSessionTokens } from "../src/lib/session-tokens";
import { GET as catchallGet } from "../src/pages/xrpc/[...nsid]";

const did = "did:example:test";
const signingKey = "8b5e3d226b44c4c88fbd3d4529f6283fb2b20f6deee8a0b34e7f0a9b12d3e4f1";

const CHAT_METHODS = [
  "chat.bsky.convo.acceptConvo",
  "chat.bsky.convo.addReaction",
  "chat.bsky.convo.removeReaction",
  "chat.bsky.convo.listConvoRequests",
  "chat.bsky.convo.updateAllRead",
  "chat.bsky.convo.getConvoAvailability",
  "chat.bsky.group.createGroup",
  "chat.bsky.convo.sendMessage",
  "chat.bsky.convo.AcceptConvo",
  "chat.bsky.futureMethod",
  "CHAT.BSKY.convo.acceptConvo",
] as const;

const PROXY_DENIAL = { error: "InvalidToken", message: "Bad token method" };

function apiContext(env: Awaited<ReturnType<typeof makeEnv>>, request: Request, nsid: string) {
  return { locals: { env }, params: { nsid }, request } as never;
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const payload = token.split(".")[1];
  if (!payload) throw new Error("missing payload");
  const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return JSON.parse(atob(padded));
}

type TestFetch = (
  input: Parameters<typeof fetch>[0],
  init?: Parameters<typeof fetch>[1],
) => Promise<Response>;

async function withFetch<T>(handler: TestFetch, run: () => Promise<T>): Promise<T> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = handler as unknown as typeof fetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function proxyBearer(
  env: Awaited<ReturnType<typeof makeEnv>>,
  token: string,
  lexiconMethod: string,
): Promise<{ status: number; body: unknown; fetchCalls: number; authorization: string | null; upstreamUrl: string | null }> {
  let fetchCalls = 0;
  let authorization: string | null = null;
  let upstreamUrl: string | null = null;
  const response = await withFetch((input, init) => {
    fetchCalls++;
    const request = input instanceof Request ? input : new Request(input, init);
    authorization = request.headers.get("authorization");
    upstreamUrl = request.url;
    return Promise.resolve(new Response(JSON.stringify({ ok: true }), {
      headers: { "Content-Type": "application/json" },
    }));
  }, () => catchallGet(apiContext(
    env,
    new Request(`https://pds.example/xrpc/${lexiconMethod}`, {
      headers: { authorization: `Bearer ${token}` },
    }),
    lexiconMethod,
  )));
  return {
    status: response.status,
    body: await response.json(),
    fetchCalls,
    authorization,
    upstreamUrl,
  };
}

function suppliedAuth(scope: string, kind: "bearer" | "oauth") {
  if (kind === "oauth") {
    return {
      token: "oauth-token",
      claims: { sub: did, scope, t: "access" as const },
      access: oauthAccessContext(scope, "active"),
    };
  }
  const bearerScope = scope as typeof AuthScope.Access;
  return {
    token: "bearer-token",
    claims: { sub: did, scope, t: "access" as const },
    access: bearerAccessContext(bearerScope, "active"),
  };
}

describe("proxied chat.bsky privileged access", () => {
  it("refuses an ordinary app password for every chat.bsky method", async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: signingKey });
    const { accessJwt } = await issueSessionTokens(env, did, { accessScope: AuthScope.AppPass });

    for (const lexiconMethod of CHAT_METHODS) {
      const result = await proxyBearer(env, accessJwt, lexiconMethod);
      expect({ lexiconMethod, ...result, authorization: null, upstreamUrl: null }).toEqual({
        lexiconMethod,
        status: 400,
        body: PROXY_DENIAL,
        fetchCalls: 0,
        authorization: null,
        upstreamUrl: null,
      });
    }
  });

  it("proxies every chat.bsky method for a privileged app password", async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: signingKey });
    const { accessJwt } = await issueSessionTokens(env, did, { accessScope: AuthScope.AppPassPrivileged });

    for (const lexiconMethod of CHAT_METHODS) {
      const result = await proxyBearer(env, accessJwt, lexiconMethod);
      expect(result.status).toBe(200);
      expect(result.fetchCalls).toBe(1);
      expect(result.upstreamUrl).toBe(`https://api.bsky.chat/xrpc/${lexiconMethod}`);
      const serviceToken = (result.authorization ?? "").slice("Bearer ".length);
      expect(decodeJwtPayload(serviceToken)).toMatchObject({
        iss: did,
        aud: "did:web:api.bsky.chat",
        lxm: lexiconMethod,
      });
    }
  });

  it("proxies every chat.bsky method for a full session", async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: signingKey });
    const { accessJwt } = await issueSessionTokens(env, did, { accessScope: AuthScope.Access });

    for (const lexiconMethod of CHAT_METHODS) {
      const result = await proxyBearer(env, accessJwt, lexiconMethod);
      expect(result.status).toBe(200);
      expect(result.fetchCalls).toBe(1);
      expect(result.upstreamUrl).toBe(`https://api.bsky.chat/xrpc/${lexiconMethod}`);
      const serviceToken = (result.authorization ?? "").slice("Bearer ".length);
      expect(decodeJwtPayload(serviceToken)).toMatchObject({ lxm: lexiconMethod });
    }
  });

  it("still proxies a non-chat method for an ordinary app password", async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: signingKey });
    const { accessJwt } = await issueSessionTokens(env, did, { accessScope: AuthScope.AppPass });
    const result = await proxyBearer(env, accessJwt, "app.bsky.feed.getTimeline");
    expect(result.status).toBe(200);
    expect(result.fetchCalls).toBe(1);
    expect(result.upstreamUrl).toBe("https://api.bsky.app/xrpc/app.bsky.feed.getTimeline");
  });

  it("refuses createAccount on the proxy for an ordinary app password and allows privileged and full sessions", async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: signingKey });
    const lexiconMethod = "com.atproto.server.createAccount";

    const cases = [
      { scope: AuthScope.AppPass, status: 400, body: PROXY_DENIAL, fetchCalls: 0 },
      { scope: AuthScope.AppPassPrivileged, status: 200, body: { ok: true }, fetchCalls: 1 },
      { scope: AuthScope.Access, status: 200, body: { ok: true }, fetchCalls: 1 },
    ] as const;

    for (const expected of cases) {
      let fetchCalls = 0;
      const response = await withFetch(() => {
        fetchCalls++;
        return Promise.resolve(new Response(JSON.stringify({ ok: true }), {
          headers: { "Content-Type": "application/json" },
        }));
      }, () => proxyAppView({
        env,
        lxm: lexiconMethod,
        request: new Request(`https://pds.example/xrpc/${lexiconMethod}`),
        auth: suppliedAuth(expected.scope, "bearer"),
      }));
      expect({ scope: expected.scope, status: response.status, body: await response.json(), fetchCalls }).toEqual({
        scope: expected.scope,
        status: expected.status,
        body: expected.body,
        fetchCalls: expected.fetchCalls,
      });
    }
  });

  it("does not treat chat.bskyish as a privileged chat method", async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: signingKey });
    const lexiconMethod = "chat.bskyish.futureMethod";
    let fetchCalls = 0;
    const response = await withFetch(() => {
      fetchCalls++;
      return Promise.resolve(new Response(JSON.stringify({ ok: true }), {
        headers: { "Content-Type": "application/json" },
      }));
    }, () => proxyAppView({
      env,
      lxm: lexiconMethod,
      request: new Request(`https://pds.example/xrpc/${lexiconMethod}`),
      auth: suppliedAuth(AuthScope.AppPass, "bearer"),
    }));
    expect(response.status).toBe(200);
    expect(fetchCalls).toBe(1);
  });

  it("refuses chat methods for transition:generic and allows transition:chat.bsky", async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: signingKey });
    const deniedMethods = ["chat.bsky.convo.acceptConvo", "CHAT.BSKY.convo.sendMessage"];
    for (const lexiconMethod of deniedMethods) {
      let fetchCalls = 0;
      const response = await withFetch(() => {
        fetchCalls++;
        return Promise.resolve(new Response(JSON.stringify({ ok: true })));
      }, () => proxyAppView({
        env,
        lxm: lexiconMethod,
        request: new Request(`https://pds.example/xrpc/${lexiconMethod}`),
        auth: suppliedAuth("atproto transition:generic", "oauth"),
      }));
      expect({ lexiconMethod, status: response.status, body: await response.json(), fetchCalls }).toEqual({
        lexiconMethod,
        status: 401,
        body: { error: "InvalidToken" },
        fetchCalls: 0,
      });
    }

    let fetchCalls = 0;
    let upstreamUrl: string | null = null;
    const allowed = await withFetch((input, init) => {
      fetchCalls++;
      const request = input instanceof Request ? input : new Request(input, init);
      upstreamUrl = request.url;
      return Promise.resolve(new Response(JSON.stringify({ ok: true }), {
        headers: { "Content-Type": "application/json" },
      }));
    }, () => proxyAppView({
      env,
      lxm: "chat.bsky.convo.acceptConvo",
      request: new Request("https://pds.example/xrpc/chat.bsky.convo.acceptConvo"),
      auth: suppliedAuth("atproto transition:generic transition:chat.bsky", "oauth"),
    }));
    expect(allowed.status).toBe(200);
    expect(fetchCalls).toBe(1);
    expect(upstreamUrl).toBe("https://api.bsky.chat/xrpc/chat.bsky.convo.acceptConvo");
  });

  it("still rejects a case-variant protected method", async () => {
    const env = await makeEnv({ REPO_SIGNING_KEY: signingKey });
    let fetchCalls = 0;
    const response = await withFetch(() => {
      fetchCalls++;
      return Promise.resolve(new Response(JSON.stringify({ ok: true })));
    }, () => proxyAppView({
      env,
      lxm: "com.atproto.server.UpdateEmail",
      request: new Request("https://pds.example/xrpc/com.atproto.server.UpdateEmail"),
      auth: suppliedAuth(AuthScope.Access, "bearer"),
    }));
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "InvalidToken", message: "method cannot be proxied" });
    expect(fetchCalls).toBe(0);
  });
});
