import type { Env } from "../env";
import { AuthTokenExpiredError } from "./auth-errors";
import { getRuntimeString } from "./secrets";
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
    jti: claims.jti,
  });
  return kind === "access" ? accessJwt : refreshJwt;
}

export async function verifyJwt(
  env: Env,
  token: string,
): Promise<{ valid: boolean; payload: JwtClaims } | null> {
  console.error('[verifyJwt] Starting verification');

  const parts = token.split(".");
  if (parts.length !== 3) {
    console.error('[verifyJwt] Invalid token parts:', parts.length);
    return null;
  }

  const header = JSON.parse(
    atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")),
  );
  console.error('[verifyJwt] Header:', JSON.stringify(header));

  if (header.typ === "at+jwt") {
    console.error('[verifyJwt] Detected at+jwt type');
    let payload;
    try {
      payload = await verifyAccessToken(env, token);
    } catch (err) {
      if (isJwtExpiredError(err)) {
        console.error('[verifyJwt] Access token expired');
        throw new AuthTokenExpiredError();
      }
      console.error('[verifyJwt] verifyAccessToken failed:', err);
      return null;
    }
    if (!payload) {
      console.error('[verifyJwt] No payload from verifyAccessToken');
      return null;
    }
    if (!payload.sub) {
      console.error('[verifyJwt] No sub in payload');
      return null;
    }
    const claims: JwtClaims = {
      sub: String(payload.sub),
      aud: payload.aud as string | undefined,
      scope: payload.scope as string | undefined,
      jti: payload.jti as string | undefined,
      iss: (payload as any).iss as string | undefined,
      iat: (payload as any).iat as number | undefined,
      exp: (payload as any).exp as number | undefined,
      t: "access",
    };
    if (payload.handle) {
      claims.handle = String(payload.handle);
    }
    console.error('[verifyJwt] at+jwt verified successfully');
    return { valid: true, payload: claims };
  }

  if (header.typ === "refresh+jwt") {
    console.error('[verifyJwt] Detected refresh+jwt type');
    const verified = await verifyRefreshToken(env, token).catch((err) => {
      if (isJwtExpiredError(err)) {
        console.error('[verifyJwt] Refresh token expired');
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
      iss: (verified.payload as any).iss as string | undefined,
      iat: (verified.payload as any).iat as number | undefined,
      exp: (verified.payload as any).exp as number | undefined,
      t: "refresh",
    };
    console.error('[verifyJwt] refresh+jwt verified successfully');
    return { valid: true, payload };
  }

  console.error('[verifyJwt] Fallback to legacy JWT verification');
  const payload = JSON.parse(
    atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
  );
  console.error('[verifyJwt] Payload type:', payload.t);

  let ok = false;
  if (header.alg === "HS256" && header.typ === "JWT") {
    console.error('[verifyJwt] Using HS256 verification');
    const secret = await getRuntimeString(
      env,
      payload.t === "refresh" ? "REFRESH_TOKEN_SECRET" : "REFRESH_TOKEN",
      payload.t === "refresh" ? "dev-refresh" : "dev-access",
    );
    if (!secret) {
      console.error('[verifyJwt] No secret found');
      return null;
    }
    console.error('[verifyJwt] Secret found, verifying signature');
    ok = await hmacJwtVerify(parts[0] + "." + parts[1], parts[2], secret);
    console.error('[verifyJwt] Signature verification:', ok);
  } else {
    console.error('[verifyJwt] Unsupported alg/typ:', header.alg, header.typ);
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (!ok) {
    console.error('[verifyJwt] Signature verification failed');
    return null;
  }
  if (payload.exp && now > payload.exp) {
    console.error('[verifyJwt] Token expired. Now:', now, 'Exp:', payload.exp);
    throw new AuthTokenExpiredError();
  }

  console.error('[verifyJwt] Legacy JWT verified successfully');
  return { valid: true, payload: payload as JwtClaims };
}

async function hmacJwtSign(payload: any, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const header = { alg: "HS256", typ: "JWT" };
  const h = b64url(enc.encode(JSON.stringify(header)));
  const p = b64url(enc.encode(JSON.stringify(payload)));
  const data = `${h}.${p}`;
  const keyBytes = enc.encode(secret);
  const keyBuf = (() => { const b = new ArrayBuffer(keyBytes.byteLength); new Uint8Array(b).set(keyBytes); return b; })();
  const key = await crypto.subtle.importKey(
    "raw",
    keyBuf,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  const s = b64url(new Uint8Array(sig));
  return `${h}.${p}.${s}`;
}

async function hmacJwtVerify(
  data: string,
  sigB64: string,
  secret: string,
): Promise<boolean> {
  const enc = new TextEncoder();
  const keyBytes = enc.encode(secret);
  const keyBuf = (() => { const b = new ArrayBuffer(keyBytes.byteLength); new Uint8Array(b).set(keyBytes); return b; })();
  const key = await crypto.subtle.importKey(
    "raw",
    keyBuf,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const sigBytes = b64urlDecode(sigB64);
  const sigBuf = (() => { const b = new ArrayBuffer(sigBytes.byteLength); new Uint8Array(b).set(sigBytes); return b; })();
  const dataBytes = enc.encode(data);
  const dataBuf = (() => { const b = new ArrayBuffer(dataBytes.byteLength); new Uint8Array(b).set(dataBytes); return b; })();
  const ok = await crypto.subtle.verify(
    "HMAC",
    key,
    sigBuf,
    dataBuf,
  );
  return !!ok;
}


function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += String.fromCharCode(b[i]);
  }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 2 ? "==" : s.length % 4 === 3 ? "=" : "";
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// EdDSA (Ed25519) path removed; only HS256 session tokens are supported

function isJwtExpiredError(err: unknown): boolean {
  return err instanceof AuthTokenExpiredError ||
    (typeof err === "object" && err !== null && (err as any).code === "ERR_JWT_EXPIRED");
}
