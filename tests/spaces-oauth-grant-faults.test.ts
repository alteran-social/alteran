import { expect } from "@std/expect";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, it } from "./helpers/bdd";
import { makeEnv } from "./helpers/env";
import { makeDpopKey, signDpopProof } from "./helpers/oauth";
import { saveCode } from "./helpers/oauth-store";
import { createAccount, getAccountByIdentifier, getSecret } from "../src/db/account";
import { setAccountState } from "../src/db/dal";
import { hashPassword } from "../src/lib/password";
import { jwkThumbprint, sha256b64url } from "../src/lib/oauth/dpop";
import { createExplicitSpaceConsent } from "../src/lib/spaces/explicit-read-consent";
import { loadCodeSnapshot } from "../src/lib/oauth/store";
import { verifyAccessToken } from "../src/lib/session-tokens";
import { POST as tokenPost } from "../src/pages/oauth/token";

const DID = "did:example:test";
const CLIENT = "https://client.example/metadata";
const URL = "https://pds.example/oauth/token";
const REDIRECT = "https://client.example/callback";
const VERIFIER = "space-fault-test-verifier-0123456789";
const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const REQUESTED = "atproto space:com.example.forum?collection=com.example.post&action=read_self";
type Env = Awaited<ReturnType<typeof makeEnv>>;
type Key = Awaited<ReturnType<typeof makeDpopKey>>;

async function fixture(confidential = false) {
  const env = await makeEnv();
  await createAccount(env, { did: DID, handle: "test.example", passwordScrypt: await hashPassword("pwd") });
  await setAccountState(env, DID, { tag: "active" });
  const incarnation = (await getAccountByIdentifier(env, DID))?.spaceIncarnation;
  if (!incarnation) throw new Error("Missing account incarnation");
  const key = await makeDpopKey();
  const clientKey = confidential ? await generateKeyPair("ES256") : null;
  const jwk = clientKey ? { ...await exportJWK(clientKey.publicKey), kid: "client-key" } : null;
  const keyId = jwk ? await jwkThumbprint(jwk as JsonWebKey) : null;
  const consent = await createExplicitSpaceConsent({
    subject: DID, accountIncarnation: incarnation, clientId: CLIENT, dpopJkt: key.jkt,
    clientAuthMethod: confidential ? "private_key_jwt" : "none", clientAuthKeyId: keyId,
    clientAuthKeyBinding: confidential ? "jwk-thumbprint-v1" : null,
  }, REQUESTED);
  if (!consent) throw new Error("Missing Space consent fixture");
  const code = crypto.randomUUID().replaceAll("-", "");
  const now = Math.floor(Date.now() / 1000);
  await saveCode(env, code, {
    code, client_id: CLIENT, redirect_uri: REDIRECT, code_challenge: await sha256b64url(VERIFIER),
    scope: consent.tokenScope, dpopJkt: key.jkt, clientAuthMethod: confidential ? "private_key_jwt" : "none",
    clientAuthKeyId: keyId, clientAuthKeyBinding: confidential ? "jwk-thumbprint-v1" : null,
    did: DID, createdAt: now, expiresAt: now + 300,
    spaceConsent: { serialized: consent.serialized, digest: consent.digest, tokenScope: consent.tokenScope,
      accountIncarnation: incarnation },
  });
  const originalFetch = globalThis.fetch;
  if (jwk) {
    const metadata = { client_id: CLIENT, redirect_uris: [REDIRECT], token_endpoint_auth_method: "private_key_jwt",
      grant_types: ["authorization_code", "refresh_token"], response_types: ["code"],
      scope: REQUESTED, dpop_bound_access_tokens: true, jwks: { keys: [jwk] } };
    globalThis.fetch = (async (input: RequestInfo | globalThis.URL) => {
      const url = input instanceof Request ? input.url : String(input);
      return url.startsWith("https://cloudflare-dns.com/dns-query")
        ? Response.json({ Answer: [{ type: 1, data: "93.184.216.34" }] })
        : url === CLIENT ? Response.json(metadata) : new Response(null, { status: 404 });
    }) as typeof fetch;
  }
  async function assertion() {
    if (!clientKey) throw new Error("Missing confidential client key");
    const jti = crypto.randomUUID();
    const iat = Math.floor(Date.now() / 1000);
    const jwt = await new SignJWT({ iss: CLIENT, sub: CLIENT, aud: "https://pds.example", iat, exp: iat + 120, jti })
      .setProtectedHeader({ alg: "ES256", kid: "client-key" }).sign(clientKey.privateKey);
    return { jwt, jti };
  }
  function codeForm(assertionJwt?: string) {
    return new URLSearchParams({ grant_type: "authorization_code", code, client_id: CLIENT,
      redirect_uri: REDIRECT, code_verifier: VERIFIER,
      ...(assertionJwt && { client_assertion_type: ASSERTION_TYPE, client_assertion: assertionJwt }) });
  }
  return { env, key, code, consent, assertion, codeForm, restore: () => { globalThis.fetch = originalFetch; } };
}

async function proof(key: Key) {
  const jti = crypto.randomUUID();
  return { jti, jwt: await signDpopProof({ key, method: "POST", url: URL, jti }) };
}

function post(env: Env, form: URLSearchParams, jwt: string) {
  const request = new Request(URL, { method: "POST", headers: { dpop: jwt }, body: form });
  return tokenPost({ locals: { env }, request, url: new globalThis.URL(URL) } as never);
}

async function exchange(f: Awaited<ReturnType<typeof fixture>>) {
  const signed = await proof(f.key);
  const response = await post(f.env, f.codeForm(), signed.jwt);
  expect(response.status).toBe(200);
  return await response.json() as { access_token: string; refresh_token: string; scope: string };
}

describe("Space grant transaction faults", () => {
  it("rejects changed refresh scope without consuming proof and accepts same-proof retry", async () => {
    const f = await fixture();
    try {
      const issued = await exchange(f);
      const sessionId = (await verifyAccessToken(f.env, issued.access_token)).oauth_session;
      const readSession = () => f.env.ALTERAN_DB.prepare(
        "SELECT current_refresh_token_id, access_jti, revoked_at FROM oauth_session WHERE id = ?",
      ).bind(sessionId).first<{ current_refresh_token_id: string; access_jti: string; revoked_at: number | null }>();
      const before = await readSession();
      const signed = await proof(f.key);
      for (const scopes of [["atproto"], [`${issued.scope} repo:com.example.other`], [issued.scope, issued.scope]]) {
        const form = new URLSearchParams({ grant_type: "refresh_token", client_id: CLIENT, refresh_token: issued.refresh_token });
        for (const scope of scopes) form.append("scope", scope);
        const response = await post(f.env, form, signed.jwt);
        expect(response.status).toBe(400);
        expect((await response.json() as { error: string }).error).toBe("invalid_scope");
        expect(await getSecret(f.env, `oauth:dpop:jti:authz:${signed.jti}`)).toBeNull();
        expect(await readSession()).toEqual(before);
      }
      const accepted = await post(f.env, new URLSearchParams({ grant_type: "refresh_token", client_id: CLIENT,
        refresh_token: issued.refresh_token, scope: issued.scope }), signed.jwt);
      expect(accepted.status).toBe(200);
      expect(await getSecret(f.env, `oauth:dpop:jti:authz:${signed.jti}`)).not.toBeNull();
      const rotated = await accepted.json() as { refresh_token: string };
      const omitted = await proof(f.key);
      expect((await post(f.env, new URLSearchParams({ grant_type: "refresh_token", client_id: CLIENT,
        refresh_token: rotated.refresh_token }), omitted.jwt)).status).toBe(200);
    } finally { f.restore(); }
  });

  it("rolls back a skipped grant insertion and both confidential proof markers", async () => {
    const f = await fixture(true);
    try {
      const signed = await proof(f.key);
      const assertion = await f.assertion();
      await f.env.ALTERAN_DB.exec("CREATE TRIGGER skip_space_grant BEFORE INSERT ON oauth_space_grant BEGIN SELECT RAISE(IGNORE); END");
      expect((await post(f.env, f.codeForm(assertion.jwt), signed.jwt)).status).toBe(400);
      expect(await loadCodeSnapshot(f.env, f.code)).not.toBeNull();
      expect(await getSecret(f.env, `oauth:dpop:jti:authz:${signed.jti}`)).toBeNull();
      expect(await getSecret(f.env, `oauth:client-assertion:jti:${CLIENT}:${assertion.jti}`)).toBeNull();
      expect((await f.env.ALTERAN_DB.prepare("SELECT COUNT(*) AS n FROM oauth_session").first<{ n: number }>())?.n).toBe(0);
      await f.env.ALTERAN_DB.exec("DROP TRIGGER skip_space_grant");
      expect((await post(f.env, f.codeForm(assertion.jwt), signed.jwt)).status).toBe(200);
    } finally { f.restore(); }
  });

  it("does not spend confidential proof markers when account incarnation changes before exchange", async () => {
    const f = await fixture(true);
    try {
      const signed = await proof(f.key);
      const assertion = await f.assertion();
      await f.env.ALTERAN_DB.prepare("DELETE FROM account WHERE did = ?").bind(DID).run();
      await f.env.ALTERAN_DB.prepare("DELETE FROM account_state WHERE did = ?").bind(DID).run();
      await createAccount(f.env, { did: DID, handle: "test.example", passwordScrypt: await hashPassword("pwd") });
      await setAccountState(f.env, DID, { tag: "active" });
      expect((await post(f.env, f.codeForm(assertion.jwt), signed.jwt)).status).toBe(400);
      expect(await loadCodeSnapshot(f.env, f.code)).not.toBeNull();
      expect(await getSecret(f.env, `oauth:dpop:jti:authz:${signed.jti}`)).toBeNull();
      expect(await getSecret(f.env, `oauth:client-assertion:jti:${CLIENT}:${assertion.jti}`)).toBeNull();
      expect((await f.env.ALTERAN_DB.prepare("SELECT COUNT(*) AS n FROM oauth_session").first<{ n: number }>())?.n).toBe(0);
    } finally { f.restore(); }
  });

  it("does not classify an unrelated D1 batch fault as a stale grant", async () => {
    const f = await fixture();
    try {
      const issued = await exchange(f);
      const signed = await proof(f.key);
      const db = f.env.ALTERAN_DB;
      const failed = { ...f.env, ALTERAN_DB: new Proxy(db, { get(target, property) {
        if (property === "batch") return () => Promise.reject(new Error("Injected D1 failure"));
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      } }) };
      const response = await post(failed, new URLSearchParams({ grant_type: "refresh_token", client_id: CLIENT,
        refresh_token: issued.refresh_token }), signed.jwt);
      expect(response.status).toBe(400);
      expect((await response.json() as { error: string }).error).toBe("invalid_request");
      expect(await getSecret(f.env, `oauth:dpop:jti:authz:${signed.jti}`)).toBeNull();
      expect((await post(f.env, new URLSearchParams({ grant_type: "refresh_token", client_id: CLIENT,
        refresh_token: issued.refresh_token }), signed.jwt)).status).toBe(200);
    } finally { f.restore(); }
  });
});
