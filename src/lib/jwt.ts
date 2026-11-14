import type { Env } from "../env";
import { AuthTokenExpiredError } from "./auth-errors";
import { errorCode } from "./errors";
import {
  issueSessionTokens,
  verifyAccessToken,
  verifyRefreshToken,
} from "./session-tokens";

export interface JwtClaims {
  sub: string; // DID
  handle?: string;
  scope?: string;
  aud?: string;
  jti?: string;
  iss?: string;
  iat?: number;
  exp?: number;
  t: "access" | "refresh";
}

// JWT
export async function signJwt(
  env: Env,
  claims: JwtClaims,
  kind: "access" | "refresh",
): Promise<string> {
  if (!claims.sub) {
    throw new Error("Cannot sign JWT without subject");
  }
  const { accessJwt, refreshJwt } = await issueSessionTokens(env, claims.sub, {
    jti: kind === "refresh" ? claims.jti : undefined,
    accessJti: kind === "access" ? claims.jti : undefined,
    accessScope: kind === "access" ? claims.scope : undefined,
  });
  return kind === "access" ? accessJwt : refreshJwt;
}

export async function verifyJwt(
  env: Env,
  token: string,
): Promise<{ valid: boolean; payload: JwtClaims } | null> {
  console.error("[verifyJwt] Starting verification");

  const parts = token.split(".");
  if (parts.length !== 3) {
    console.error("[verifyJwt] Invalid token parts:", parts.length);
    return null;
  }

  const header = JSON.parse(
    atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")),
  );

  if (header.typ === "at+jwt") {
    console.error("[verifyJwt] Detected at+jwt type");
    let payload;
    try {
      payload = await verifyAccessToken(env, token);
    } catch (error) {
      if (isJwtExpiredError(error)) {
        console.error("[verifyJwt] Access token expired");
        throw new AuthTokenExpiredError();
      }
      console.error("[verifyJwt] Access token verification failed");
      return null;
    }
    if (!payload) {
      console.error("[verifyJwt] No payload from verifyAccessToken");
      return null;
    }
    if (!payload.sub) {
      console.error("[verifyJwt] No sub in payload");
      return null;
    }
    if (payload.cnf) {
      console.error(
        "[verifyJwt] Rejecting DPoP-bound OAuth token on Bearer path",
      );
      return null;
    }
    const claims: JwtClaims = {
      sub: String(payload.sub),
      aud: payload.aud as string | undefined,
      scope: payload.scope as string | undefined,
      jti: payload.jti as string | undefined,
      iss: payload.iss as string | undefined,
      iat: payload.iat as number | undefined,
      exp: payload.exp as number | undefined,
      t: "access",
    };
    if (payload.handle) {
      claims.handle = String(payload.handle);
    }
    console.error("[verifyJwt] at+jwt verified successfully");
    return { valid: true, payload: claims };
  }

  if (header.typ === "refresh+jwt") {
    console.error("[verifyJwt] Detected refresh+jwt type");
    const verified = await verifyRefreshToken(env, token).catch((error) => {
      if (isJwtExpiredError(error)) {
        console.error("[verifyJwt] Refresh token expired");
        throw new AuthTokenExpiredError();
      }
      return null;
    });
    if (!verified) return null;
    if (!verified.payload.sub) return null;
    const payload: JwtClaims = {
      sub: String(verified.payload.sub),
      aud: verified.payload.aud as string | undefined,
      scope: verified.payload.scope as string | undefined,
      jti: verified.payload.jti as string | undefined,
      iss: verified.payload.iss as string | undefined,
      iat: verified.payload.iat as number | undefined,
      exp: verified.payload.exp as number | undefined,
      t: "refresh",
    };
    console.error("[verifyJwt] refresh+jwt verified successfully");
    return { valid: true, payload };
  }

  return null;
}

function isJwtExpiredError(error: unknown): boolean {
  return error instanceof AuthTokenExpiredError ||
    errorCode(error) === "ERR_JWT_EXPIRED";
}
