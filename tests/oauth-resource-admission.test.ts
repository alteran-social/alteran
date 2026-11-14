import { createOAuthSession } from './helpers/oauth-store';
import { expect } from "@std/expect";
import { SignJWT } from "jose";
import { describe, it } from "./helpers/bdd";
import { makeEnv } from "./helpers/env";
import { makeDpopKey, signDpopProof } from "./helpers/oauth";
import { getSecret, setSecret } from "../src/db/account";
import {
  dpopResourceUnauthorized,
  verifyResourceRequestHybrid,
} from "../src/lib/oauth/resource";
import { issueSessionTokens } from "../src/lib/session-tokens";

const URL = "https://pds.example/xrpc/com.atproto.repo.getRecord";
const DID = "did:example:test";
const CLIENT = "https://client.example/metadata";
const SECRET = "oauth-resource-admission-test-secret";
type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

async function fixture(scope = "atproto") {
  const env = await makeEnv({ SESSION_JWT_SECRET: SECRET });
  const key = await makeDpopKey();
  const sessionId = crypto.randomUUID();
  const accessJti = crypto.randomUUID();
  const tokens = await issueSessionTokens(env, DID, {
    accessScope: scope,
    clientId: CLIENT,
    dpopJkt: key.jkt,
    oauthSessionId: sessionId,
    accessJti,
  });
  await createOAuthSession(env, {
    id: sessionId,
    did: DID,
    clientId: CLIENT,
    clientAuthMethod: "none",
    dpopJkt: key.jkt,
    scope,
    currentRefreshTokenId: tokens.refreshPayload.jti,
    accessJti,
    expiresAt: tokens.refreshExpiry,
  });
  const nonce = (await dpopResourceUnauthorized(env)).headers.get("DPoP-Nonce");
  if (!nonce) throw new Error("Missing resource nonce");
  return { env, key, sessionId, accessJti, tokens, nonce };
}

async function signedRequest(
  input: Awaited<ReturnType<typeof fixture>>,
  jti: string,
  token = input.tokens.accessJwt,
) {
  const proof = await signDpopProof({
    key: input.key,
    method: "GET",
    url: URL,
    nonce: input.nonce,
    accessToken: token,
    jti,
  });
  return new Request(URL, {
    headers: { authorization: `DPoP ${token}`, dpop: proof },
  });
}

function beforeBatch(env: TestEnv, mutate: () => Promise<void>): TestEnv {
  const database = env.ALTERAN_DB;
  const wrapped = new Proxy(database, {
    get(target, property) {
      if (property === "batch") {
        return async (statements: Parameters<typeof database.batch>[0]) => {
          await mutate();
          return database.batch(statements);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { ...env, ALTERAN_DB: wrapped };
}

describe("OAuth resource admission", () => {
  it("rejects revocation before the replay transaction", async () => {
    const input = await fixture();
    const jti = crypto.randomUUID();
    const env = beforeBatch(input.env, async () => {
      await input.env.ALTERAN_DB.prepare(
        "UPDATE oauth_session SET revoked_at = ? WHERE id = ?",
      )
        .bind(Math.floor(Date.now() / 1000), input.sessionId).run();
    });
    await expect(
      verifyResourceRequestHybrid(env, await signedRequest(input, jti)),
    ).rejects.toThrow("invalid_token");
    expect(await getSecret(input.env, `oauth:dpop:jti:resource:${jti}`))
      .toBeNull();
  });

  it("requires a versioned verified-key binding for confidential access tokens", async () => {
    const input = await fixture();
    await input.env.ALTERAN_DB.prepare(`UPDATE oauth_session SET client_auth_method = 'private_key_jwt',
      client_auth_key_id = ?, client_auth_key_binding = NULL WHERE id = ?`).bind('A'.repeat(43), input.sessionId).run();
    await expect(verifyResourceRequestHybrid(input.env, await signedRequest(input, crypto.randomUUID())))
      .rejects.toThrow('invalid_token');
    await input.env.ALTERAN_DB.prepare(`UPDATE oauth_session SET client_auth_key_binding = 'jwk-thumbprint-v1' WHERE id = ?`)
      .bind(input.sessionId).run();
    expect(await verifyResourceRequestHybrid(input.env, await signedRequest(input, crypto.randomUUID()))).not.toBeNull();
  });

  it("rechecks a confidential key binding after proof insertion", async () => {
    const input = await fixture();
    await input.env.ALTERAN_DB.prepare(`UPDATE oauth_session SET client_auth_method = 'private_key_jwt',
      client_auth_key_id = ?, client_auth_key_binding = 'jwk-thumbprint-v1' WHERE id = ?`)
      .bind('A'.repeat(43), input.sessionId).run();
    await input.env.ALTERAN_DB.prepare(`CREATE TRIGGER invalidate_confidential_binding AFTER INSERT ON secret
      WHEN NEW.key GLOB 'oauth:dpop:jti:resource:*' BEGIN
        UPDATE oauth_session SET client_auth_key_binding = NULL;
      END`).run();
    await expect(verifyResourceRequestHybrid(input.env, await signedRequest(input, crypto.randomUUID())))
      .rejects.toThrow('invalid_token');
  });

  it("rejects oversized stored session fields without returning them from D1", async () => {
    const input = await fixture();
    await input.env.ALTERAN_DB.prepare('UPDATE oauth_session SET scope = ? WHERE id = ?')
      .bind('x'.repeat(400_000), input.sessionId).run();
    const db = input.env.ALTERAN_DB;
    const originals = new WeakMap<object, D1PreparedStatement>();
    let largest = 0;
    function measure(value: unknown) {
      largest = Math.max(largest, JSON.stringify(value)?.length ?? 0);
      return value;
    }
    function wrapStatement(statement: D1PreparedStatement): D1PreparedStatement {
      const wrapped = new Proxy(statement, {
        get(target, property) {
          if (property === 'bind') return (...args: unknown[]) => wrapStatement(target.bind(...args));
          const value = Reflect.get(target, property, target);
          if (typeof value !== 'function') return value;
          if (property === 'first' || property === 'all' || property === 'raw' || property === 'run') {
            return async (...args: unknown[]) => measure(await value.apply(target, args));
          }
          return value.bind(target);
        },
      });
      originals.set(wrapped, statement);
      return wrapped;
    }
    const measured = { ...input.env, ALTERAN_DB: new Proxy(db, {
      get(target, property) {
        if (property === 'prepare') return (sql: string) => wrapStatement(target.prepare(sql));
        if (property === 'batch') return async (statements: D1PreparedStatement[]) =>
          measure(await target.batch(statements.map((statement) => originals.get(statement) ?? statement)));
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }) };
    await expect(verifyResourceRequestHybrid(measured, await signedRequest(input, crypto.randomUUID())))
      .rejects.toThrow('invalid_token');
    expect(largest).toBeLessThan(10_000);
  });

  it("also enforces the worker-time session expiry at admission", async () => {
    const input = await fixture();
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    await input.env.ALTERAN_DB.prepare('UPDATE oauth_session SET expires_at = ? WHERE id = ?')
      .bind(now + 10, input.sessionId).run();
    const request = await signedRequest(input, crypto.randomUUID());
    try {
      Date.now = () => (now + 11) * 1000;
      await expect(verifyResourceRequestHybrid(input.env, request)).rejects.toThrow('invalid_token');
    } finally {
      Date.now = originalNow;
    }
  });

  it("rejects a signed token that expires on the Worker before D1 admission", async () => {
    const input = await fixture();
    const originalNow = Date.now;
    const now = Math.floor(originalNow() / 1000);
    const token = await new SignJWT({ scope: 'atproto', client_id: CLIENT, oauth_session: input.sessionId,
      cnf: { jkt: input.key.jkt }, jti: input.accessJti })
      .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' }).setAudience(DID).setSubject(DID)
      .setIssuedAt(now).setExpirationTime(now + 50).sign(new TextEncoder().encode(SECRET));
    const jti = crypto.randomUUID();
    const request = await signedRequest(input, jti, token);
    const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
    let digests = 0;
    Object.defineProperty(crypto.subtle, 'digest', { configurable: true, value: async (...args: Parameters<SubtleCrypto['digest']>) => {
      const result = await originalDigest(...args);
      if (++digests === 2) Date.now = () => (now + 100) * 1000;
      return result;
    } });
    try {
      Date.now = () => now * 1000;
      await expect(verifyResourceRequestHybrid(input.env, request)).rejects.toThrow('invalid_token');
      expect(digests).toBe(2);
      expect(await getSecret(input.env, `oauth:dpop:jti:resource:${jti}`)).toBeNull();
    } finally {
      Date.now = originalNow;
      delete (crypto.subtle as { digest?: unknown }).digest;
    }
  });

  it("rechecks token and session expiry when Worker time advances during the D1 batch", async () => {
    for (const expired of ['token', 'session'] as const) {
      const input = await fixture();
      const originalNow = Date.now;
      const now = Math.floor(originalNow() / 1000);
      if (expired === 'session') {
        await input.env.ALTERAN_DB.prepare('UPDATE oauth_session SET expires_at = ? WHERE id = ?')
          .bind(now + 50, input.sessionId).run();
      }
      const token = expired === 'token' ? await new SignJWT({ scope: 'atproto', client_id: CLIENT,
        oauth_session: input.sessionId, cnf: { jkt: input.key.jkt }, jti: input.accessJti })
        .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' }).setAudience(DID).setSubject(DID)
        .setIssuedAt(now).setExpirationTime(now + 50).sign(new TextEncoder().encode(SECRET)) : input.tokens.accessJwt;
      const jti = crypto.randomUUID();
      const request = await signedRequest(input, jti, token);
      const database = input.env.ALTERAN_DB;
      const delayed = { ...input.env, ALTERAN_DB: new Proxy(database, {
        get(target, property) {
          if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
            const result = await target.batch(statements);
            Date.now = () => (now + 100) * 1000;
            return result;
          };
          const value = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      }) };
      try {
        Date.now = () => now * 1000;
        await expect(verifyResourceRequestHybrid(delayed, request)).rejects.toThrow('invalid_token');
        expect(await getSecret(input.env, `oauth:dpop:jti:resource:${jti}`)).not.toBeNull();
      } finally {
        Date.now = originalNow;
      }
    }
  });

  it("rejects a changed access JTI, identity, client, key, scope, or expired session", async () => {
    const input = await fixture();
    const updates = [
      ["UPDATE oauth_session SET access_jti = ? WHERE id = ?", "rotated"],
      ["UPDATE oauth_session SET did = ? WHERE id = ?", "did:example:other"],
      [
        "UPDATE oauth_session SET client_id = ? WHERE id = ?",
        "https://other.example/client",
      ],
      ["UPDATE oauth_session SET dpop_jkt = ? WHERE id = ?", "different"],
      [
        "UPDATE oauth_session SET scope = ? WHERE id = ?",
        "atproto transition:generic",
      ],
      ["UPDATE oauth_session SET expires_at = ? WHERE id = ?", 1],
    ] as const;
    for (const [statement, value] of updates) {
      const jti = crypto.randomUUID();
      const env = beforeBatch(input.env, async () => {
        await input.env.ALTERAN_DB.prepare(statement).bind(
          value,
          input.sessionId,
        ).run();
      });
      await expect(
        verifyResourceRequestHybrid(env, await signedRequest(input, jti)),
      ).rejects.toThrow("invalid_token");
      expect(await getSecret(input.env, `oauth:dpop:jti:resource:${jti}`))
        .toBeNull();
      await input.env.ALTERAN_DB.prepare(
        `UPDATE oauth_session SET did = ?, client_id = ?, dpop_jkt = ?,
        scope = ?, access_jti = ?, expires_at = ?, revoked_at = NULL WHERE id = ?`,
      )
        .bind(
          DID,
          CLIENT,
          input.key.jkt,
          "atproto",
          input.accessJti,
          input.tokens.refreshExpiry,
          input.sessionId,
        ).run();
    }
  });

  it("rechecks revocation after a proof marker is inserted", async () => {
    const input = await fixture();
    const staleKey = "oauth:dpop:jti:authz:must-remain";
    const stale = JSON.stringify({ iat: 1, exp: 1 });
    await setSecret(input.env, staleKey, stale);
    await input.env.ALTERAN_DB.prepare(
      `CREATE TRIGGER revoke_after_resource_marker AFTER INSERT ON secret
      WHEN NEW.key GLOB 'oauth:dpop:jti:resource:*' BEGIN
        UPDATE oauth_session SET revoked_at = unixepoch();
      END`,
    ).run();
    const jti = crypto.randomUUID();
    await expect(
      verifyResourceRequestHybrid(input.env, await signedRequest(input, jti)),
    ).rejects.toThrow("invalid_token");
    expect(await getSecret(input.env, `oauth:dpop:jti:resource:${jti}`)).not
      .toBeNull();
    expect(await getSecret(input.env, staleKey)).toBe(stale);
  });

  it("rechecks signed token expiration against the final database clock", async () => {
    const input = await fixture();
    const staleKey = "oauth:dpop:jti:authz:must-remain";
    const stale = JSON.stringify({ iat: 1, exp: 1 });
    await setSecret(input.env, staleKey, stale);
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({
      scope: "atproto",
      client_id: CLIENT,
      oauth_session: input.sessionId,
      cnf: { jkt: input.key.jkt },
      jti: input.accessJti,
    }).setProtectedHeader({ alg: "HS256", typ: "at+jwt" }).setAudience(DID)
      .setSubject(DID)
      .setIssuedAt(now).setExpirationTime(now + 30).sign(
        new TextEncoder().encode(SECRET),
      );
    await input.env.ALTERAN_DB.prepare(
      `CREATE TRIGGER expire_resource_token AFTER INSERT ON secret
      WHEN NEW.key GLOB 'oauth:dpop:jti:resource:*' BEGIN
        UPDATE oauth_replay_clock SET seconds = seconds + 60 WHERE id = 1;
      END`,
    ).run();
    await expect(
      verifyResourceRequestHybrid(
        input.env,
        await signedRequest(input, crypto.randomUUID(), token),
      ),
    )
      .rejects.toThrow("invalid_token");
    expect(await getSecret(input.env, staleKey)).toBe(stale);
  });

  it("admits only one concurrent use of the same signed proof", async () => {
    const input = await fixture();
    const request = await signedRequest(input, crypto.randomUUID());
    const results = await Promise.allSettled(
      Array.from(
        { length: 8 },
        () => verifyResourceRequestHybrid(input.env, request.clone()),
      ),
    );
    expect(
      results.filter((result) =>
        result.status === "fulfilled" && result.value?.did === DID
      ),
    ).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected"))
      .toHaveLength(7);
  });

  it("rejects oversized ASCII and multibyte proof identifiers as invalid tokens", async () => {
    const input = await fixture();
    for (const jti of ["x".repeat(8192), "é".repeat(4090)]) {
      await expect(
        verifyResourceRequestHybrid(input.env, await signedRequest(input, jti)),
      ).rejects.toThrow("invalid_token");
    }
  });

  it("accepts an existing valid OAuth scope longer than 4096 bytes", async () => {
    const scope = [
      "atproto",
      ...Array.from(
        { length: 180 },
        (_, index) => `repo:com.example.item${index}?action=create`,
      ),
    ].join(" ");
    expect(scope.length).toBeGreaterThan(4096);
    const input = await fixture(scope);
    const result = await verifyResourceRequestHybrid(
      input.env,
      await signedRequest(input, crypto.randomUUID()),
    );
    expect(result?.scope).toBe(scope);
  });

  it("does not authorize when the replay database transaction fails", async () => {
    const input = await fixture();
    await input.env.ALTERAN_DB.prepare(
      `CREATE TRIGGER fail_resource_clock BEFORE UPDATE ON oauth_replay_clock
      BEGIN SELECT RAISE(ABORT, 'test failure'); END`,
    ).run();
    await expect(
      verifyResourceRequestHybrid(
        input.env,
        await signedRequest(input, crypto.randomUUID()),
      ),
    ).rejects.toThrow();
  });
});
