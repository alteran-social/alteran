import { expect } from "@std/expect";
import { SignJWT } from "jose";
import type { APIContext } from "astro";
import type { Env } from "../src/env";
import { verifyJwt } from "../src/lib/jwt";
import { issueSessionTokens } from "../src/lib/session-tokens";
import { getSecret, storeRefreshToken } from "../src/db/account";
import { SecretResolutionError } from "../src/lib/secrets";
import { GET as getSession } from "../src/pages/xrpc/com.atproto.server.getSession";
import { POST as refreshSession } from "../src/pages/xrpc/com.atproto.server.refreshSession";
import { describe, it } from "./helpers/bdd";
import { makeEnv } from "./helpers/env";

const did = "did:example:test";

function context(env: Env, token: string, method = "GET"): APIContext {
  const route = method === "POST" ? "refreshSession" : "getSession";
  return {
    locals: { env },
    request: new Request(
      `https://pds.example/xrpc/com.atproto.server.${route}`,
      {
        method,
        headers: { authorization: `Bearer ${token}` },
      },
    ),
  } as unknown as APIContext;
}

describe("session JWT verification", () => {
  it("rejects the obsolete token format even when old configuration is present", async () => {
    const secret = crypto.randomUUID() + crypto.randomUUID();
    const env = {
      ...await makeEnv(),
      REFRESH_TOKEN: secret,
      REFRESH_TOKEN_SECRET: secret,
    } as Env;
    for (const kind of ["access", "refresh"] as const) {
      const token = await new SignJWT({ t: kind, scope: "com.atproto.access" })
        .setProtectedHeader({ alg: "HS256", typ: "JWT" }).setSubject(did)
        .setExpirationTime("1h").sign(new TextEncoder().encode(secret));
      expect((await verifyJwt(env, token)) === null).toBe(true);
      if (kind === "access") {
        expect((await getSession(context(env, token))).status).toBe(401);
      } else {expect((await refreshSession(context(env, token, "POST"))).status)
          .toBe(401);}
    }
  });

  it("retains current access and refresh session behavior", async () => {
    const env = await makeEnv();
    const tokens = await issueSessionTokens(env, did);
    await storeRefreshToken(env, {
      id: tokens.refreshPayload.jti,
      did,
      expiresAt: tokens.refreshExpiry,
    });
    expect((await getSession(context(env, tokens.accessJwt))).status).toBe(200);
    expect(
      (await refreshSession(context(env, tokens.refreshJwt, "POST"))).status,
    ).toBe(200);
  });

  it("rejects invalid session keys without creating a D1 fallback", async () => {
    const base = await makeEnv();
    const tokenSecret = crypto.randomUUID() + crypto.randomUUID();
    const access = await new SignJWT({ scope: "com.atproto.access" })
      .setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
      .setSubject(did).setAudience(did).setExpirationTime("1h")
      .sign(new TextEncoder().encode(tokenSecret));
    const refresh = await new SignJWT({ scope: "com.atproto.refresh" })
      .setProtectedHeader({ alg: "HS256", typ: "refresh+jwt" })
      .setSubject(did).setAudience(did).setExpirationTime("1h")
      .sign(new TextEncoder().encode(tokenSecret));
    for (
      const value of [false, 0, true, "", " \t\n", { get: async () => " \t\n" }]
    ) {
      const env = { ...base, SESSION_JWT_SECRET: value } as unknown as Env;
      expect((await getSession(context(env, access))).status).toBe(401);
      for (
        const run of [
          () => issueSessionTokens(env, did),
          () => refreshSession(context(env, refresh, "POST")),
        ]
      ) {
        let caught: unknown;
        try {
          await run();
        } catch (error) {
          caught = error;
        }
        expect(caught instanceof SecretResolutionError).toBe(true);
      }
      expect((await getSecret(base, "session_jwt_secret")) === null).toBe(true);
    }
  });

  it("returns controlled refresh failures without masking database failures", async () => {
    const secret = crypto.randomUUID() + crypto.randomUUID();
    const env = await makeEnv({ SESSION_JWT_SECRET: secret });
    const expired = await new SignJWT({ scope: "com.atproto.refresh" })
      .setProtectedHeader({ alg: "HS256", typ: "refresh+jwt" }).setSubject(did)
      .setAudience(did).setExpirationTime(1).sign(
        new TextEncoder().encode(secret),
      );
    const response = await refreshSession(context(env, expired, "POST"));
    expect(response.status).toBe(401);
    expect((await response.json() as { error: string }).error).toBe(
      "ExpiredToken",
    );
    expect((await refreshSession(context(env, "invalid", "POST"))).status).toBe(
      401,
    );
    const broken = {
      ...env,
      ALTERAN_DB: {
        prepare() {
          throw new Error("database unavailable");
        },
      },
    } as unknown as Env;
    let databaseFailed = false;
    try {
      await refreshSession(context(broken, expired, "POST"));
    } catch {
      databaseFailed = true;
    }
    expect(databaseFailed).toBe(true);
  });
});
