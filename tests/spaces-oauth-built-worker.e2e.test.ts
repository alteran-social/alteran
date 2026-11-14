import { expect } from "@std/expect";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { Miniflare } from "miniflare";
import { join } from "node:path";
import type { Env } from "../src/env";
import { createAccount, getAccountByIdentifier } from "../src/db/account";
import { setAccountState } from "../src/db/dal";
import { createPersonalSpace } from "../src/db/space-lifecycle-create";
import { applySpaceWrites } from "../src/db/space-store";
import { hashPassword } from "../src/lib/password";
import { sha256b64url } from "../src/lib/oauth/dpop";
import { readWranglerCompatibility } from "./helpers/wrangler-compatibility";

const ORIGIN = "https://pds.example";
const DID = "did:example:test";
const HANDLE = "test.example";
const PASSWORD = "test-password";
const SPACE = `at://${DID}/space/com.example.notes/owner-flow`;
const COLLECTION = "com.example.note";
const SCOPE = "atproto space:com.example.notes?action=read_self";
const REDIRECT = "http://127.0.0.1:51789/callback";
const CLIENT = `http://localhost?${new URLSearchParams({
  redirect_uri: "http://127.0.0.1/callback",
  scope: SCOPE,
})}`;
const VERIFIER = "built-worker-oauth-space-code-verifier-0123456789";

Deno.test({
  name:
    "built Worker completes OAuth consent, owner Space read, refresh and revocation",
  ignore: Deno.env.get("RUN_APP_TESTS") !== "true",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    const root = join(import.meta.dirname!, "..");
    const build = await new Deno.Command(Deno.execPath(), {
      cwd: root,
      args: ["task", "build"],
      stdout: "null",
      stderr: "null",
    }).output();
    if (!build.success) throw new Error("Astro build failed");
    const compatibility = await readWranglerCompatibility(root);
    const modules: { type: "ESModule"; path: string }[] = [
      { type: "ESModule", path: join(root, "dist/server/entry.mjs") },
    ];
    for (const directory of ["", "chunks"]) {
      for await (
        const file of Deno.readDir(join(root, "dist/server", directory))
      ) {
        if (
          file.isFile && file.name.endsWith(".mjs") && file.name !== "entry.mjs"
        ) {
          modules.push({
            type: "ESModule",
            path: join(root, "dist/server", directory, file.name),
          });
        }
      }
    }
    const bindings = {
      PDS_DID: DID,
      PDS_HANDLE: HANDLE,
      USER_PASSWORD: PASSWORD,
      SESSION_JWT_SECRET: "test-session-signing-key",
      PDS_RELAY_NOTIFY: "false",
    };
    const worker = new Miniflare({
      modules,
      modulesRoot: join(root, "dist/server"),
      ...compatibility,
      d1Databases: { ALTERAN_DB: ":memory:" },
      r2Buckets: ["ALTERAN_BLOBS"],
      bindings,
      outboundService: { network: { allow: [] } },
    });
    try {
      const database = await worker.getD1Database("ALTERAN_DB");
      const migrationDirectory = join(root, "migrations");
      const names: string[] = [];
      for await (const file of Deno.readDir(migrationDirectory)) {
        if (file.name.endsWith(".sql")) names.push(file.name);
      }
      for (const name of names.sort()) {
        const statements =
          (await Deno.readTextFile(join(migrationDirectory, name))).split(
            "--> statement-breakpoint",
          );
        for (const statement of statements) {
          if (statement.trim()) {
            await database.prepare(statement.replaceAll("\n", " ")).run();
          }
        }
      }
      const env = {
        ...bindings,
        ALTERAN_DB: database,
        ALTERAN_BLOBS: await worker.getR2Bucket("ALTERAN_BLOBS"),
      } as unknown as Env;
      expect(
        await createAccount(env, {
          did: DID,
          handle: HANDLE,
          passwordScrypt: await hashPassword(PASSWORD),
        }),
      ).toBe(true);
      await setAccountState(env, DID, { tag: "active" });
      const account = await getAccountByIdentifier(env, DID);
      if (!account?.spaceIncarnation) {
        throw new Error("Missing test account incarnation");
      }
      // Creation and writes are internal setup; this test does not exercise those XRPCs.
      await createPersonalSpace(
        env,
        SPACE,
        { $type: "com.atproto.personalspace.policy" },
        crypto.randomUUID(),
        account.spaceIncarnation,
      );
      await applySpaceWrites(env, SPACE, DID, [{
        action: "create",
        collection: COLLECTION,
        rkey: "one",
        record: { $type: COLLECTION, text: "private fixture" },
      }], account.spaceIncarnation);

      const key = await generateKeyPair("ES256");
      const publicJwk = await exportJWK(key.publicKey);
      async function proof(
        method: string,
        path: string,
        nonce: string,
        accessToken?: string,
      ): Promise<string> {
        const payload: Record<string, unknown> = {
          htm: method,
          htu: `${ORIGIN}${path}`,
          iat: Math.floor(Date.now() / 1000),
          jti: crypto.randomUUID(),
          nonce,
        };
        if (accessToken) payload.ath = await sha256b64url(accessToken);
        return new SignJWT(payload).setProtectedHeader({
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: publicJwk,
        }).sign(key.privateKey);
      }
      async function postForm(
        path: string,
        values: Record<string, string>,
        dpop?: string,
      ): Promise<Response> {
        return await worker.dispatchFetch(`${ORIGIN}${path}`, {
          method: "POST",
          redirect: "manual",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            ...(dpop ? { dpop } : {}),
          },
          body: new URLSearchParams(values),
        }) as unknown as Response;
      }
      const parForm = {
        client_id: CLIENT,
        response_type: "code",
        redirect_uri: REDIRECT,
        scope: SCOPE,
        state: "test-state",
        code_challenge: await sha256b64url(VERIFIER),
        code_challenge_method: "S256",
      };
      const challenged = await postForm("/oauth/par", parForm);
      expect(challenged.status).toBe(401);
      const authNonce = challenged.headers.get("dpop-nonce");
      if (!authNonce) throw new Error("Missing authorization nonce");
      const pushed = await postForm(
        "/oauth/par",
        parForm,
        await proof("POST", "/oauth/par", authNonce),
      );
      expect(pushed.status).toBe(201);
      const par = await pushed.json() as { request_uri?: unknown };
      if (typeof par.request_uri !== "string") {
        throw new Error("Missing request URI");
      }

      const authorizeQuery = new URLSearchParams({
        client_id: CLIENT,
        request_uri: par.request_uri,
      });
      const authorize = await worker.dispatchFetch(
        `${ORIGIN}/oauth/authorize?${authorizeQuery}`,
        { redirect: "manual" },
      );
      expect(authorize.status).toBe(302);
      const consentUrl = new URL(authorize.headers.get("location") ?? "");
      expect(consentUrl.origin).toBe(ORIGIN);
      expect(consentUrl.pathname).toBe("/oauth/consent");
      const consent = await worker.dispatchFetch(consentUrl.toString(), {
        redirect: "manual",
      });
      expect(consent.status).toBe(200);
      const html = await consent.text();
      expect(html.includes(
        "Read your own repository, including all collections, in matching spaces",
      )).toBe(true);
      const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1];
      if (!csrf) throw new Error("Missing consent CSRF");
      const approval = await worker.dispatchFetch(`${ORIGIN}/oauth/consent`, {
        method: "POST",
        redirect: "manual",
        headers: {
          origin: ORIGIN,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          request_uri: par.request_uri,
          client_id: CLIENT,
          csrf,
          password: PASSWORD,
          decision: "allow",
        }),
      });
      expect(approval.status).toBe(302);
      const callback = new URL(approval.headers.get("location") ?? "");
      expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT);
      expect(callback.searchParams.get("state")).toBe("test-state");
      const code = callback.searchParams.get("code");
      if (!code) throw new Error("Missing authorization code");
      const token = await postForm("/oauth/token", {
        client_id: CLIENT,
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        code_verifier: VERIFIER,
      }, await proof("POST", "/oauth/token", authNonce));
      expect(token.status).toBe(200);
      const issued = await token.json() as {
        access_token?: unknown;
        refresh_token?: unknown;
        scope?: unknown;
      };
      if (
        typeof issued.access_token !== "string" ||
        typeof issued.refresh_token !== "string" ||
        typeof issued.scope !== "string"
      ) {
        throw new Error("Missing OAuth tokens or scope");
      }
      expect(issued.scope).toContain("action=read_self");
      const query = new URLSearchParams({
        space: SPACE,
        repo: DID,
        collection: COLLECTION,
        rkey: "one",
      });
      const readUrl = `${ORIGIN}/xrpc/com.atproto.space.getRecord?${query}`;
      const resourceChallenge = await worker.dispatchFetch(readUrl, {
        redirect: "manual",
        headers: { authorization: `DPoP ${issued.access_token}` },
      });
      expect(resourceChallenge.status).toBe(401);
      const resourceNonce = resourceChallenge.headers.get("dpop-nonce");
      if (!resourceNonce) throw new Error("Missing resource nonce");
      async function read(accessToken: string) {
        return await worker.dispatchFetch(readUrl, {
          redirect: "manual",
          headers: {
            authorization: `DPoP ${accessToken}`,
            dpop: await proof(
              "GET",
              "/xrpc/com.atproto.space.getRecord",
              resourceNonce,
              accessToken,
            ),
          },
        });
      }
      const first = await read(issued.access_token);
      expect(first.status).toBe(200);
      expect(first.headers.get("cache-control")).toBe("private, no-store");
      expect((await first.json() as { value: unknown }).value).toEqual({
        $type: COLLECTION,
        text: "private fixture",
      });

      const refresh = await postForm("/oauth/token", {
        client_id: CLIENT,
        grant_type: "refresh_token",
        refresh_token: issued.refresh_token,
      }, await proof("POST", "/oauth/token", authNonce));
      expect(refresh.status).toBe(200);
      const rotated = await refresh.json() as {
        access_token?: unknown;
        refresh_token?: unknown;
        scope?: unknown;
      };
      if (
        typeof rotated.access_token !== "string" ||
        typeof rotated.refresh_token !== "string"
      ) {
        throw new Error("Missing rotated OAuth tokens");
      }
      expect(rotated.scope).toBe(issued.scope);
      expect((await read(issued.access_token)).status).toBe(400);
      const afterRefresh = await read(rotated.access_token);
      expect(afterRefresh.status).toBe(200);
      expect((await afterRefresh.json() as { value: unknown }).value).toEqual({
        $type: COLLECTION,
        text: "private fixture",
      });
      const revoked = await postForm("/oauth/revoke", {
        client_id: CLIENT,
        token: rotated.access_token,
      }, await proof("POST", "/oauth/revoke", authNonce));
      expect(revoked.status).toBe(200);
      expect((await read(rotated.access_token)).status).toBe(400);
      const revokedRefresh = await postForm("/oauth/token", {
        client_id: CLIENT,
        grant_type: "refresh_token",
        refresh_token: rotated.refresh_token,
      }, await proof("POST", "/oauth/token", authNonce));
      expect(revokedRefresh.status).toBe(400);
      expect((await revokedRefresh.json() as { error: unknown }).error).toBe(
        "invalid_grant",
      );
    } finally {
      await worker.dispose();
    }
  },
});
