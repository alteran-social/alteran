import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import { makeEnv } from "./helpers/env";
import { createOAuthSession } from "./helpers/oauth-store";
import { makeDpopKey, signResourceDpop } from "./helpers/oauth";
import { createAccount, getAccountByIdentifier } from "../src/db/account";
import { setAccountState } from "../src/db/dal";
import { hashPassword } from "../src/lib/password";
import { authenticateSingleUserPassword } from "../src/lib/oauth/consent";
import { createExplicitSpaceConsent } from "../src/lib/spaces/explicit-read-consent";
import { issueSessionTokens } from "../src/lib/session-tokens";
import { verifyResourceRequestHybrid } from "../src/lib/oauth/resource";
import { POST as createSession } from "../src/pages/xrpc/com.atproto.server.createSession";

const DID = "did:example:test";
const CLIENT = "https://client.example/metadata.json";
const URL = "https://pds.example/xrpc/com.atproto.space.getRecord";
type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

function login(env: TestEnv, identifier: string, password: string) {
  const request = new Request("https://pds.example/xrpc/com.atproto.server.createSession", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ identifier, password }),
  });
  return createSession({ locals: { env }, request, url: new globalThis.URL(request.url) } as never);
}

describe("account bootstrap state", () => {
  it("does not restore a signed Space grant through failed-login fallback", async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    expect(await createAccount(env, { did: DID, handle: "test.example", passwordScrypt: await hashPassword("pwd") })).toBe(true);
    await setAccountState(env, DID, { tag: "active" });
    const incarnation = (await getAccountByIdentifier(env, DID))?.spaceIncarnation;
    if (!incarnation) throw new Error("Missing account incarnation");
    const consent = await createExplicitSpaceConsent({
      subject: DID, accountIncarnation: incarnation, clientId: CLIENT, dpopJkt: key.jkt, clientAuthMethod: "none",
      clientAuthKeyId: null, clientAuthKeyBinding: null,
    }, "atproto space:com.example.forum?collection=com.example.post&action=read_self");
    if (!consent) throw new Error("Missing consent fixture");
    const tokens = await issueSessionTokens(env, DID, {
      accessScope: consent.tokenScope, clientId: CLIENT, dpopJkt: key.jkt,
      oauthSessionId: "space-session", accessJti: "space-access", spaceGrantDigest: consent.digest,
    });
    await createOAuthSession(env, {
      id: "space-session", did: DID, clientId: CLIENT, clientAuthMethod: "none", dpopJkt: key.jkt,
      scope: consent.tokenScope, currentRefreshTokenId: tokens.refreshPayload.jti,
      accessJti: "space-access", expiresAt: tokens.refreshExpiry,
    });
    await env.ALTERAN_DB.prepare("INSERT INTO oauth_space_grant VALUES (?, ?, ?, ?)")
      .bind("space-session", consent.serialized, consent.digest, Math.floor(Date.now() / 1000)).run();
    const request = async () => new Request(URL, { headers: {
      authorization: `DPoP ${tokens.accessJwt}`, dpop: await signResourceDpop(env, key, "GET", URL, tokens.accessJwt),
    } });
    expect((await verifyResourceRequestHybrid(env, await request()))?.spacePrincipal).toBeDefined();
    await env.ALTERAN_DB.prepare("DELETE FROM account WHERE did = ?").bind(DID).run();
    expect((await login(env, "unknown.example", "wrong")).status).toBe(401);
    expect(await getAccountByIdentifier(env, DID)).toBeNull();
    await expect(verifyResourceRequestHybrid(env, await request())).rejects.toMatchObject({ code: "invalid_token" });
    expect(await authenticateSingleUserPassword(env, "pwd")).toBeNull();
    expect(await getAccountByIdentifier(env, DID)).toBeNull();
  });

  it("does not overwrite an existing account after an unknown-identifier login", async () => {
    const env = await makeEnv();
    await createAccount(env, { did: DID, handle: "test.example", passwordScrypt: await hashPassword("distinct-password") });
    expect((await login(env, "unknown.example", "wrong")).status).toBe(401);
    expect((await login(env, "test.example", "distinct-password")).status).toBe(200);
    expect((await login(env, "test.example", "pwd")).status).toBe(401);
  });

  it("atomically rejects orphan state and competing account replacement", async () => {
    const blocked = await makeEnv();
    await setAccountState(blocked, DID, { tag: "deactivated" });
    expect(await createAccount(blocked, { did: DID, handle: "test.example", passwordScrypt: "one" })).toBe(false);
    expect(await getAccountByIdentifier(blocked, DID)).toBeNull();
    const env = await makeEnv();
    const results = await Promise.all([
      createAccount(env, { did: DID, handle: "test.example", passwordScrypt: "one" }),
      createAccount(env, { did: DID, handle: "test.example", passwordScrypt: "two" }),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(["one", "two"]).toContain((await getAccountByIdentifier(env, DID))?.passwordScrypt);
  });
});
