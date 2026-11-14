import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import { makeEnv } from "./helpers/env";
import { createAccount } from "../src/db/account";
import { hashPassword } from "../src/lib/password";
import { clearLoginAttempt, reserveLoginAttempt } from "../src/lib/login-attempts";
import { savePar } from "../src/lib/oauth/store";
import { POST as createSession } from "../src/pages/xrpc/com.atproto.server.createSession";
import { GET as consentGet, POST as consentPost } from "../src/pages/oauth/consent";

const IP = "198.51.100.25";
const ORIGIN = "https://pds.example";
type Env = Awaited<ReturnType<typeof makeEnv>>;

function attemptRequest(ip = IP): Request {
  return new Request(`${ORIGIN}/xrpc/com.atproto.server.createSession`, { headers: { "cf-connecting-ip": ip } });
}

function login(env: Env, password: string, ip = IP) {
  const request = new Request(`${ORIGIN}/xrpc/com.atproto.server.createSession`, {
    method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": ip },
    body: JSON.stringify({ identifier: "test.example", password }),
  });
  return createSession({ locals: { env }, request, url: new URL(request.url) } as never);
}

async function seededAccount(env: Env) {
  await createAccount(env, { did: "did:example:test", handle: "test.example", passwordScrypt: await hashPassword("pwd") });
}

async function consentRequest(env: Env, id: string): Promise<Request> {
  const now = Math.floor(Date.now() / 1000);
  await savePar(env, id, { client_id: "http://localhost", redirect_uri: "http://127.0.0.1/callback",
    code_challenge: "challenge", code_challenge_method: "S256", scope: "atproto", state: "state",
    dpopJkt: "key", clientAuthMethod: "none", createdAt: now, expiresAt: now + 300 });
  const uri = `urn:ietf:params:oauth:request_uri:${id}`;
  const pageRequest = new Request(`${ORIGIN}/oauth/consent?request_uri=${encodeURIComponent(uri)}`);
  const page = await consentGet({ locals: { env }, request: pageRequest, url: new URL(pageRequest.url) } as never);
  const csrf = (await page.text()).match(/name="csrf" value="([^"]+)"/)?.[1];
  if (!csrf) throw new Error("Missing consent CSRF");
  return new Request(`${ORIGIN}/oauth/consent`, {
    method: "POST", headers: { origin: ORIGIN, "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": IP },
    body: new URLSearchParams({ request_uri: uri, client_id: "http://localhost", csrf, decision: "allow", password: "wrong" }),
  });
}

describe("atomic login attempt reservations", () => {
  it("does not clear a newer same-second attempt after an ABA sequence", async () => {
    const env = await makeEnv();
    const request = attemptRequest();
    const a = await reserveLoginAttempt(env, request);
    const b = await reserveLoginAttempt(env, request);
    if (a.tag !== "reserved" || b.tag !== "reserved") throw new Error("Missing reservation");
    const first = await env.ALTERAN_DB.prepare("SELECT last_attempt FROM login_attempts WHERE ip = ?")
      .bind(IP).first<{ last_attempt: number }>();
    if (!first) throw new Error("Missing first reservation");
    await clearLoginAttempt(env, b.reservation);
    expect(await env.ALTERAN_DB.prepare("SELECT ip FROM login_attempts WHERE ip = ?").bind(IP).first()).toBeNull();
    const c = await reserveLoginAttempt(env, request);
    if (c.tag !== "reserved") throw new Error("Missing newer reservation");
    await env.ALTERAN_DB.prepare("UPDATE login_attempts SET last_attempt = ? WHERE ip = ?")
      .bind(first.last_attempt, IP).run();
    await clearLoginAttempt(env, a.reservation);
    const row = await env.ALTERAN_DB.prepare("SELECT attempts, reservation_nonce FROM login_attempts WHERE ip = ?")
      .bind(IP).first<{ attempts: number; reservation_nonce: string }>();
    expect(row).toEqual({ attempts: 1, reservation_nonce: c.reservation.nonce });
    expect(a.reservation.nonce).not.toBe(c.reservation.nonce);
  });

  it("limits simultaneous invalid createSession requests to five reservations", async () => {
    const env = await makeEnv();
    await seededAccount(env);
    const results = await Promise.all(Array.from({ length: 6 }, () => login(env, "wrong")));
    expect(results.filter((response) => response.status === 401)).toHaveLength(4);
    expect(results.filter((response) => response.status === 429)).toHaveLength(2);
    const row = await env.ALTERAN_DB.prepare("SELECT attempts, locked_until FROM login_attempts WHERE ip = ?")
      .bind(IP).first<{ attempts: number; locked_until: number }>();
    expect(row?.attempts).toBe(5);
    expect(row?.locked_until).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("allows a correct fifth login and clears only its own reservation", async () => {
    const env = await makeEnv();
    await seededAccount(env);
    for (let i = 0; i < 4; i++) expect((await login(env, "wrong")).status).toBe(401);
    expect((await login(env, "pwd")).status).toBe(200);
    expect(await env.ALTERAN_DB.prepare("SELECT ip FROM login_attempts WHERE ip = ?").bind(IP).first()).toBeNull();
  });

  it("preserves the fifth-failure response and blocks later attempts", async () => {
    const env = await makeEnv();
    await seededAccount(env);
    for (let i = 0; i < 4; i++) expect((await login(env, "wrong")).status).toBe(401);
    const locked = await login(env, "wrong");
    expect(locked.status).toBe(429);
    expect(await locked.json()).toEqual({
      error: "RateLimitExceeded", message: "Too many failed login attempts. Account locked for 15 minutes.",
    });
    expect((await login(env, "pwd")).status).toBe(429);
  });

  it("resets an expired lock using D1 time even when Worker time differs", async () => {
    const env = await makeEnv();
    await env.ALTERAN_DB.prepare(`INSERT INTO login_attempts (ip, attempts, locked_until, last_attempt, reservation_nonce)
      VALUES (?, 5, unixepoch(), unixepoch() - 900, 'old')`).bind(IP).run();
    const originalNow = Date.now;
    try {
      Date.now = () => 0;
      const result = await reserveLoginAttempt(env, attemptRequest());
      expect(result.tag).toBe("reserved");
      if (result.tag !== "reserved") throw new Error("Expected unlocked reservation");
      expect(result.reservation.attempts).toBe(1);
      expect(result.reservation.lockedUntil).toBeNull();
    } finally { Date.now = originalNow; }
  });

  it("fails closed when reservation insertion is skipped and bounds untrusted IP keys", async () => {
    const env = await makeEnv();
    await env.ALTERAN_DB.exec("CREATE TRIGGER skip_login_reservation BEFORE INSERT ON login_attempts BEGIN SELECT RAISE(IGNORE); END");
    await expect(reserveLoginAttempt(env, attemptRequest())).rejects.toThrow();
    await env.ALTERAN_DB.exec("DROP TRIGGER skip_login_reservation");
    const oversized = await reserveLoginAttempt(env, attemptRequest("1".repeat(500)));
    const forwarded = await reserveLoginAttempt(env, new Request(ORIGIN, { headers: { "x-forwarded-for": "203.0.113.1" } }));
    expect(oversized.tag).toBe("reserved");
    expect(forwarded.tag).toBe("reserved");
    const row = await env.ALTERAN_DB.prepare("SELECT attempts FROM login_attempts WHERE ip = 'unknown'")
      .first<{ attempts: number }>();
    expect(row?.attempts).toBe(2);
    expect((await reserveLoginAttempt(env, attemptRequest())).tag).toBe("reserved");
    await env.ALTERAN_DB.exec("CREATE TRIGGER skip_login_update BEFORE UPDATE ON login_attempts BEGIN SELECT RAISE(IGNORE); END");
    expect((await reserveLoginAttempt(env, attemptRequest())).tag).toBe("locked");
    await env.ALTERAN_DB.exec("DROP TRIGGER skip_login_update");
    await env.ALTERAN_DB.prepare("UPDATE login_attempts SET attempts = 5, locked_until = NULL WHERE ip = ?").bind(IP).run();
    expect((await reserveLoginAttempt(env, attemptRequest())).tag).toBe("locked");
  });

  it("shares one atomic limit between consent and createSession", async () => {
    const env = await makeEnv();
    await seededAccount(env);
    const requests = await Promise.all([consentRequest(env, "login1"), consentRequest(env, "login2"), consentRequest(env, "login3")]);
    const responses = await Promise.all([
      ...requests.map((request) => consentPost({ locals: { env }, request, url: new URL(request.url) } as never)),
      ...Array.from({ length: 4 }, () => login(env, "wrong")),
    ]);
    expect(responses.filter((response) => response.status === 429).length).toBeGreaterThanOrEqual(2);
    const row = await env.ALTERAN_DB.prepare("SELECT attempts, locked_until FROM login_attempts WHERE ip = ?")
      .bind(IP).first<{ attempts: number; locked_until: number }>();
    expect(row?.attempts).toBe(5);
    expect(row?.locked_until).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });
});
