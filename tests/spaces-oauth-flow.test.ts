import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import { makeEnv } from "./helpers/env";
import { makeDpopKey, signAuthzDpop, signResourceDpop } from "./helpers/oauth";
import { setAccountState } from "../src/db/dal";
import { createAccount, getAccountByIdentifier } from "../src/db/account";
import { hashPassword } from "../src/lib/password";
import { sha256b64url } from "../src/lib/oauth/dpop";
import { verifyAccessToken, verifyRefreshToken } from "../src/lib/session-tokens";
import { consumeVerifiedSpacePrincipal, isVerifiedSpacePrincipal } from "../src/lib/oauth/space-principal";
import { verifyResourceRequestHybrid } from "../src/lib/oauth/resource";
import { authenticateSingleUserPassword } from "../src/lib/oauth/consent";
import { POST as parPost } from "../src/pages/oauth/par";
import { GET as consentGet, POST as consentPost } from "../src/pages/oauth/consent";
import { POST as tokenPost } from "../src/pages/oauth/token";
import { POST as revokePost } from "../src/pages/oauth/revoke";
import { POST as createSession } from "../src/pages/xrpc/com.atproto.server.createSession";
import { createPersonalSpace } from "../src/db/space-lifecycle-create";
import { applySpaceWrites } from "../src/db/space-store";
import { readAuthorizedSpaceRecord } from "../src/db/space-authorized-record";
import * as dagCbor from "@ipld/dag-cbor";

const ORIGIN = "https://pds.example";
const SPACE_SCOPE = "space:com.example.forum?collection=com.example.post&action=read_self";
const SCOPE = `atproto ${SPACE_SCOPE}`;
const CLIENT = `http://localhost?${new URLSearchParams({
  redirect_uri: "http://127.0.0.1/callback", scope: SCOPE,
})}`;
const REDIRECT = "http://127.0.0.1:51789/callback";
const VERIFIER = "space-read-flow-code-verifier-0123456789";

type TestEnv = Awaited<ReturnType<typeof makeEnv>>;
type Key = Awaited<ReturnType<typeof makeDpopKey>>;
function context(env: TestEnv, request: Request) {
  return { locals: { env }, request, url: new URL(request.url) } as never;
}

async function token(env: TestEnv, key: Key, form: Record<string, string>, proof?: string): Promise<Response> {
  const url = `${ORIGIN}/oauth/token`;
  return tokenPost(context(env, new Request(url, {
    method: "POST",
    headers: { dpop: proof ?? await signAuthzDpop(env, key, "POST", url), "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: CLIENT, ...form }),
  })));
}

async function startConsent(env: TestEnv, key: Key) {
  const parUrl = `${ORIGIN}/oauth/par`;
  const pushed = await parPost(context(env, new Request(parUrl, {
    method: "POST",
    headers: { dpop: await signAuthzDpop(env, key, "POST", parUrl), "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT, response_type: "code", redirect_uri: REDIRECT, scope: SCOPE, state: "state",
      code_challenge: await sha256b64url(VERIFIER), code_challenge_method: "S256",
    }),
  })));
  expect(pushed.status).toBe(201);
  const requestUri = (await pushed.json() as { request_uri: string }).request_uri;
  const page = await consentGet(context(env, new Request(`${ORIGIN}/oauth/consent?request_uri=${encodeURIComponent(requestUri)}`)));
  expect(page.status).toBe(200);
  const html = await page.text();
  const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1];
  if (!csrf) throw new Error("Missing consent CSRF");
  return { requestUri, csrf, html };
}

function approve(env: TestEnv, consent: { requestUri: string; csrf: string }) {
  return consentPost(context(env, new Request(`${ORIGIN}/oauth/consent`, {
    method: "POST",
    headers: { origin: ORIGIN, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ request_uri: consent.requestUri, client_id: CLIENT, csrf: consent.csrf, password: "pwd", decision: "allow" }),
  })));
}

async function authorizationCode(env: TestEnv, key: Key): Promise<{ code: string; html: string }> {
  const request = await startConsent(env, key);
  const consent = await approve(env, request);
  expect(consent.status).toBe(302);
  const code = new URL(consent.headers.get("location") ?? "").searchParams.get("code");
  if (!code) throw new Error("Missing authorization code");
  return { code, html: request.html };
}

async function createActiveAccount(env: TestEnv) {
  await createAccount(env, { did: "did:example:test", handle: "test.example", passwordScrypt: await hashPassword("pwd") });
  await setAccountState(env, "did:example:test", { tag: "active" });
}

async function replaceActiveAccount(env: TestEnv) {
  await env.ALTERAN_DB.prepare("DELETE FROM account WHERE did = ?").bind("did:example:test").run();
  await env.ALTERAN_DB.prepare("DELETE FROM account_state WHERE did = ?").bind("did:example:test").run();
  await createActiveAccount(env);
}

async function mint(env: TestEnv, key: Key) {
  const { code } = await authorizationCode(env, key);
  const response = await token(env, key, { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: VERIFIER });
  expect(response.status).toBe(200);
  return await response.json() as { access_token: string; refresh_token: string; scope: string };
}

function replaceBeforeNextBatch(env: TestEnv): TestEnv {
  const database = env.ALTERAN_DB;
  let replaced = false;
  return { ...env, ALTERAN_DB: new Proxy(database, { get(target, property) {
    if (property === "batch") return async (statements: Parameters<typeof database.batch>[0]) => {
      if (!replaced) { replaced = true; await replaceActiveAccount(env); }
      return database.batch(statements);
    };
    const value = Reflect.get(target, property, target);
    return typeof value === "function" ? value.bind(target) : value;
  } }) };
}

describe("Space read-self OAuth flow", () => {
  it("binds displayed consent through code, signed tokens, resource admission, refresh and revoke", async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    await createAccount(env, { did: "did:example:test", handle: "test.example", passwordScrypt: await hashPassword("pwd") });
    await setAccountState(env, "did:example:test", { tag: "active" });
    const space = "at://did:example:test/space/com.example.forum/general";
    await createPersonalSpace(env, space, { $type: "com.atproto.personalspace.policy" }, crypto.randomUUID());
    await applySpaceWrites(env, space, "did:example:test", [{
      action: "create", collection: "com.example.other", rkey: "one",
      record: { $type: "com.example.other", text: "private record" },
    }]);
    const { code, html } = await authorizationCode(env, key);
    expect(html).toContain("Read your own repository, including all collections, in matching spaces");
    expect(html).toContain("Read settings, policies, member lists, writer identities and sync state");
    expect(html).toContain("com.example.forum");
    const issued = await token(env, key, {
      grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: VERIFIER,
    });
    expect(issued.status).toBe(200);
    const body = await issued.json() as { access_token: string; refresh_token: string; scope: string };
    const accessPayload = await verifyAccessToken(env, body.access_token);
    const refreshPayload = (await verifyRefreshToken(env, body.refresh_token)).payload;
    expect(typeof accessPayload.space_grant).toBe("string");
    expect(refreshPayload.space_grant).toBe(accessPayload.space_grant);
    expect(body.scope).toContain("action=read_self");

    const path = `${ORIGIN}/xrpc/com.atproto.space.getRecord`;
    const params = new URLSearchParams({ space, repo: "did:example:test", collection: "com.example.other", rkey: "one" });
    const resourceRequest = new Request(`${path}?${params}`, {
      headers: { authorization: `DPoP ${body.access_token}`, dpop: await signResourceDpop(env, key, "GET", path, body.access_token) },
    });
    const resource = await verifyResourceRequestHybrid(env, resourceRequest);
    const principal = resource?.spacePrincipal;
    expect(isVerifiedSpacePrincipal(principal)).toBe(true);
    expect(Object.isFrozen(principal)).toBe(true);
    expect(principal?.grant.digest).toBe(accessPayload.space_grant);
    if (!principal) throw new Error("Missing verified Space principal");
    const read = await readAuthorizedSpaceRecord(env, principal, resourceRequest, space, "did:example:test", "com.example.other", "one");
    expect(read.tag).toBe("found");
    if (read.tag !== "found") throw new Error("Private record unavailable");
    expect(dagCbor.decode(read.record.value)).toEqual({ $type: "com.example.other", text: "private record" });
    expect(consumeVerifiedSpacePrincipal(principal, resourceRequest, env.ALTERAN_DB)).toBe(false);

    const refreshed = await token(env, key, { grant_type: "refresh_token", refresh_token: body.refresh_token });
    expect(refreshed.status).toBe(200);
    const rotated = await refreshed.json() as { access_token: string; refresh_token: string; scope: string };
    expect(rotated.scope).toBe(body.scope);
    expect((await verifyAccessToken(env, rotated.access_token)).space_grant).toBe(accessPayload.space_grant);
    await expect(verifyResourceRequestHybrid(env, new Request(`${path}?rkey=two`, {
      headers: { authorization: `DPoP ${body.access_token}`, dpop: await signResourceDpop(env, key, "GET", path, body.access_token) },
    }))).rejects.toMatchObject({ code: "invalid_token" });

    const revokeUrl = `${ORIGIN}/oauth/revoke`;
    const revoked = await revokePost(context(env, new Request(revokeUrl, {
      method: "POST", headers: { dpop: await signAuthzDpop(env, key, "POST", revokeUrl), "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: rotated.access_token, client_id: CLIENT }),
    })));
    expect(revoked.status).toBe(200);
    await expect(verifyResourceRequestHybrid(env, new Request(`${path}?rkey=three`, {
      headers: { authorization: `DPoP ${rotated.access_token}`, dpop: await signResourceDpop(env, key, "GET", path, rotated.access_token) },
    }))).rejects.toMatchObject({ code: "invalid_token" });
  });

  it("does not recreate an account over an orphan active state after failed login", async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    await createAccount(env, { did: "did:example:test", handle: "test.example", passwordScrypt: await hashPassword("pwd") });
    await setAccountState(env, "did:example:test", { tag: "active" });
    const { code } = await authorizationCode(env, key);
    const issued = await token(env, key, { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: VERIFIER });
    expect(issued.status).toBe(200);
    const body = await issued.json() as { access_token: string };
    await env.ALTERAN_DB.prepare("DELETE FROM account WHERE did = ?").bind("did:example:test").run();

    const login = await createSession(context(env, new Request(`${ORIGIN}/xrpc/com.atproto.server.createSession`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: "unknown.example", password: "wrong" }),
    })));
    expect(login.status).toBe(401);
    expect(await getAccountByIdentifier(env, "did:example:test")).toBeNull();
    const path = `${ORIGIN}/xrpc/com.atproto.space.getRecord`;
    await expect(verifyResourceRequestHybrid(env, new Request(path, {
      headers: { authorization: `DPoP ${body.access_token}`, dpop: await signResourceDpop(env, key, "GET", path, body.access_token) },
    }))).rejects.toMatchObject({ code: "invalid_token" });

    expect(await authenticateSingleUserPassword(env, "pwd")).toBeNull();
    expect(await getAccountByIdentifier(env, "did:example:test")).toBeNull();
  });

  it("does not reset an existing account on an unknown-identifier login", async () => {
    const env = await makeEnv();
    await createAccount(env, { did: "did:example:test", handle: "test.example", passwordScrypt: await hashPassword("distinct-password") });
    const login = (identifier: string, password: string) => createSession(context(env, new Request(
      `${ORIGIN}/xrpc/com.atproto.server.createSession`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ identifier, password }),
      },
    )));
    expect((await login("unknown.example", "wrong")).status).toBe(401);
    expect((await login("test.example", "distinct-password")).status).toBe(200);
    expect((await login("test.example", "pwd")).status).toBe(401);
  });

  it("atomically refuses orphaned state and concurrent account replacement", async () => {
    const blocked = await makeEnv();
    await setAccountState(blocked, "did:example:test", { tag: "deactivated" });
    expect(await createAccount(blocked, { did: "did:example:test", handle: "test.example", passwordScrypt: "one" })).toBe(false);
    expect(await getAccountByIdentifier(blocked, "did:example:test")).toBeNull();

    const env = await makeEnv();
    const results = await Promise.all([
      createAccount(env, { did: "did:example:test", handle: "test.example", passwordScrypt: "one" }),
      createAccount(env, { did: "did:example:test", handle: "test.example", passwordScrypt: "two" }),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
    const account = await getAccountByIdentifier(env, "did:example:test");
    expect(["one", "two"]).toContain(account?.passwordScrypt);
  });

  it("rejects replacement between the displayed consent and approval", async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    await createActiveAccount(env);
    const pending = await startConsent(env, key);
    await replaceActiveAccount(env);
    expect((await approve(env, pending)).status).toBe(400);
    const codes = await env.ALTERAN_DB.prepare("SELECT COUNT(*) AS n FROM secret WHERE key GLOB 'oauth:code:*'")
      .first<{ n: number }>();
    expect(codes?.n).toBe(0);
  });

  it("does not spend a code or proof when the account changes before exchange", async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    await createActiveAccount(env);
    const { code } = await authorizationCode(env, key);
    await replaceActiveAccount(env);
    const response = await token(env, key, { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: VERIFIER });
    expect(response.status).toBe(400);
    const record = await env.ALTERAN_DB.prepare("SELECT value FROM secret WHERE key = ?").bind(`oauth:code:${code}`)
      .first<{ value: string }>();
    expect(JSON.parse(record?.value ?? "{}").code).toBe(code);
    const sessions = await env.ALTERAN_DB.prepare("SELECT COUNT(*) AS n FROM oauth_session").first<{ n: number }>();
    expect(sessions?.n).toBe(0);
  });

  it("does not rotate or revoke a grant if account replacement wins the commit race", async () => {
    for (const operation of ["refresh", "revoke"] as const) {
      const env = await makeEnv();
      const key = await makeDpopKey();
      await createActiveAccount(env);
      const tokens = await mint(env, key);
      const sessionId = (await verifyAccessToken(env, tokens.access_token)).oauth_session;
      const racing = replaceBeforeNextBatch(env);
      let response: Response;
      if (operation === "refresh") {
        response = await token(racing, key, { grant_type: "refresh_token", refresh_token: tokens.refresh_token });
      } else {
        const url = `${ORIGIN}/oauth/revoke`;
        response = await revokePost(context(racing, new Request(url, {
          method: "POST", headers: { dpop: await signAuthzDpop(env, key, "POST", url), "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token: tokens.access_token, client_id: CLIENT }),
        })));
      }
      expect(response.status).toBe(400);
      if (operation === "refresh") expect((await response.json() as { error: string }).error).toBe("invalid_grant");
      const session = await env.ALTERAN_DB.prepare("SELECT revoked_at, access_jti FROM oauth_session WHERE id = ?")
        .bind(sessionId).first<{ revoked_at: number | null; access_jti: string }>();
      expect(session?.revoked_at).toBeNull();
      expect(session?.access_jti).toBe((await verifyAccessToken(env, tokens.access_token)).jti);
    }
  });

  it("keeps old grants invalid after account replacement and trusted activation", async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    await createActiveAccount(env);
    const tokens = await mint(env, key);
    const before = (await getAccountByIdentifier(env, "did:example:test"))?.spaceIncarnation;
    await env.ALTERAN_DB.prepare("DELETE FROM account WHERE did = ?").bind("did:example:test").run();
    await env.ALTERAN_DB.prepare("DELETE FROM account_state WHERE did = ?").bind("did:example:test").run();
    const login = await createSession(context(env, new Request(`${ORIGIN}/xrpc/com.atproto.server.createSession`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: "unknown.example", password: "wrong" }),
    })));
    expect(login.status).toBe(401);
    await setAccountState(env, "did:example:test", { tag: "active" });
    expect((await getAccountByIdentifier(env, "did:example:test"))?.spaceIncarnation).not.toBe(before);
    const path = `${ORIGIN}/xrpc/com.atproto.space.getRecord`;
    await expect(verifyResourceRequestHybrid(env, new Request(path, { headers: {
      authorization: `DPoP ${tokens.access_token}`, dpop: await signResourceDpop(env, key, "GET", path, tokens.access_token),
    } }))).rejects.toMatchObject({ code: "invalid_token" });
  });
});
