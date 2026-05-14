/**
 * Authentication Tests — JWT signing/verification round-trips.
 *
 * Tests use a Miniflare-backed Env so signJwt / verifyJwt can read the real
 * `secret` table. CLAUDE.md §6: do not mock the database.
 */

import { describe, it as test } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from "./helpers/env";
import { signJwt, verifyJwt } from "../src/lib/jwt";
import { cleanupExpiredTokens, lazyCleanupExpiredTokens } from "../src/lib/token-cleanup";

describe("Authentication", () => {
  describe("JWT Token Generation", () => {
    test("should generate a structurally-valid access token", async () => {
      const env = await makeEnv();
      const token = await signJwt(
        env,
        { sub: "did:plc:test123", handle: "test.bsky.social", t: "access" },
        "access",
      );
      expect(typeof token).toBe("string");
      expect(token.split(".")).toHaveLength(3);
    });

    test("should generate refresh tokens that carry the requested jti", async () => {
      const env = await makeEnv();
      const jti = crypto.randomUUID();
      const token = await signJwt(
        env,
        { sub: "did:plc:test123", t: "refresh", jti },
        "refresh",
      );
      const result = await verifyJwt(env, token);
      expect(result?.payload.jti).toBe(jti);
    });

    test("should include all required JWT claims", async () => {
      const env = await makeEnv();
      const token = await signJwt(
        env,
        {
          sub: "did:plc:test123",
          handle: "test.bsky.social",
          scope: "com.atproto.access",
          t: "access",
        },
        "access",
      );
      const result = await verifyJwt(env, token);
      expect(result?.valid).toBe(true);
      expect(result?.payload.sub).toBe("did:plc:test123");
      expect(result?.payload.aud).toBe(env.PDS_DID as string);
      expect(result?.payload.iat).toBeDefined();
      expect(result?.payload.exp).toBeDefined();
    });
  });

  describe("Token Verification", () => {
    test("should reject malformed tokens", async () => {
      const env = await makeEnv();
      expect(await verifyJwt(env, "not-a-token")).toBeNull();
      expect(await verifyJwt(env, "only.two")).toBeNull();
    });

    test("should reject tokens minted by a different secret store", async () => {
      const env1 = await makeEnv();
      const env2 = await makeEnv();
      const token = await signJwt(env1, { sub: "did:plc:test123", t: "access" }, "access");
      // Each makeEnv spins up an isolated D1 with an independent session
      // secret, so a token signed against env1 must not verify against env2.
      const result = await verifyJwt(env2, token);
      expect(result).toBeNull();
    });
  });

  describe("Token Rotation", () => {
    test("should produce distinct refresh tokens when minted with different jtis", async () => {
      const env = await makeEnv();
      const jti1 = crypto.randomUUID();
      const jti2 = crypto.randomUUID();
      const token1 = await signJwt(env, { sub: "did:plc:test123", t: "refresh", jti: jti1 }, "refresh");
      const token2 = await signJwt(env, { sub: "did:plc:test123", t: "refresh", jti: jti2 }, "refresh");
      expect(token1).not.toBe(token2);
      expect(jti1).not.toBe(jti2);
    });
  });

  describe("Token Cleanup helpers", () => {
    test("cleanupExpiredTokens runs against a real D1 and reports a count", async () => {
      const env = await makeEnv();
      const removed = await cleanupExpiredTokens(env);
      expect(typeof removed).toBe("number");
      expect(removed).toBeGreaterThanOrEqual(0);
    });

    test("lazyCleanupExpiredTokens is callable without throwing", async () => {
      const env = await makeEnv();
      await lazyCleanupExpiredTokens(env);
    });
  });
});
