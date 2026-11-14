import { env as workerEnv } from "cloudflare:workers";
import { getSecret } from "astro:env/server";
import { onRequest } from "__ALTERAN_ROOT__/src/middleware.ts";
import { withRequestEnv } from "__ALTERAN_ROOT__/src/lib/request-env.ts";
import {
  getRuntimeString,
  resolveEnvSecrets,
} from "__ALTERAN_ROOT__/src/lib/secrets.ts";
import { issueSessionTokens } from "__ALTERAN_ROOT__/src/lib/session-tokens.ts";
import { authenticateRequest } from "__ALTERAN_ROOT__/src/lib/auth.ts";
import { authenticateSingleUserPassword } from "__ALTERAN_ROOT__/src/lib/oauth/consent.ts";
import {
  createAccount,
  getAccountByIdentifier,
} from "__ALTERAN_ROOT__/src/db/account.ts";
import { hashPassword } from "__ALTERAN_ROOT__/src/lib/password.ts";
import { POST as createSession } from "__ALTERAN_ROOT__/src/pages/xrpc/com.atproto.server.createSession.ts";

export const prerender = false;

function request(token) {
  return new Request("https://pds.example/xrpc/com.atproto.server.getSession", {
    headers: { authorization: `Bearer ${token}` },
  });
}

function login(env, password) {
  return createSession({
    locals: { env },
    request: new Request(
      "https://pds.example/xrpc/com.atproto.server.createSession",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identifier: "test.example", password }),
      },
    ),
  });
}

export async function GET() {
  const did = "did:example:test";
  const password = crypto.randomUUID();
  const secret = crypto.randomUUID() + crypto.randomUUID();
  const common = {
    ALTERAN_BLOBS: workerEnv.ALTERAN_BLOBS,
    PDS_DID: did,
    PDS_HANDLE: "test.example",
  };
  const foreign = {
    ...common,
    ALTERAN_DB: workerEnv.DB_A,
    USER_PASSWORD: password,
    SESSION_JWT_SECRET: secret,
    HOST_APP_SECRET: "foreign-host-value",
  };
  const local = { ...common, ALTERAN_DB: workerEnv.DB_B };
  const existing = { ...common, ALTERAN_DB: workerEnv.DB_C };
  const hostSecretBefore =
    getSecret("HOST_APP_SECRET") === workerEnv.HOST_APP_SECRET;
  await resolveEnvSecrets(foreign);
  const hostSecretAfter =
    getSecret("HOST_APP_SECRET") === workerEnv.HOST_APP_SECRET;
  const passwordIsolated =
    (await getRuntimeString(local, "USER_PASSWORD", "")) === "";
  const issued = await issueSessionTokens(foreign, did);
  const modernIsolated =
    (await authenticateRequest(request(issued.accessJwt), local)) === null;
  const differentAudience = {
    ...existing,
    PDS_DID: "did:example:other",
    SESSION_JWT_SECRET: secret,
  };
  const audienceIsolated = (await authenticateRequest(
    request(issued.accessJwt),
    differentAudience,
  )) === null;
  const missingIdentity = {
    ...existing,
    PDS_DID: undefined,
    SESSION_JWT_SECRET: secret,
  };
  const identityIsolated =
    (await authenticateRequest(request(issued.accessJwt), missingIdentity)) ===
      null;
  const loginRejected = (await login(local, password)).status === 401;
  const consentRejected =
    (await authenticateSingleUserPassword(local, password)) === null;
  const emptyAccount = (await getAccountByIdentifier(local, did)) === null;
  const ownPassword = crypto.randomUUID();
  await createAccount(existing, {
    did,
    handle: "test.example",
    passwordScrypt: await hashPassword(ownPassword),
  });
  const existingRejects = (await login(existing, password)).status === 401 &&
    (await authenticateSingleUserPassword(existing, password)) === null;
  const existingAccepts = (await login(existing, ownPassword)).status === 200 &&
    (await authenticateSingleUserPassword(existing, ownPassword))?.did === did;
  const ownStore = {
    ...local,
    USER_PASSWORD: { get: async () => ownPassword },
  };
  const secretStoreWorks =
    (await getRuntimeString(ownStore, "USER_PASSWORD", "")) === ownPassword;
  let secretStoreFailureClosed = false;
  try {
    await resolveEnvSecrets({
      ...local,
      USER_PASSWORD: {
        get: async () => {
          throw new Error("unavailable");
        },
      },
    });
  } catch {
    secretStoreFailureClosed = true;
  }
  const getterMarker = `getter-${crypto.randomUUID()}`;
  const getterEnv = { ...local };
  Object.defineProperty(getterEnv, "USER_PASSWORD", {
    enumerable: true,
    get() {
      throw new Error(getterMarker);
    },
  });
  let credentialGetterClosed = false;
  try {
    await getRuntimeString(getterEnv, "USER_PASSWORD", "fallback");
  } catch (error) {
    credentialGetterClosed = error instanceof Error &&
      !error.message.includes(getterMarker) &&
      !("cause" in error);
  }
  const probe = new Request("https://pds.example/health");
  const missingContext = {
    request: probe,
    locals: {},
    url: new URL(probe.url),
  };
  const suppliedContext = {
    request: probe,
    locals: { env: local },
    url: new URL(probe.url),
  };
  const missingContextClosed = (await withRequestEnv(
    undefined,
    () => onRequest(missingContext, async () => new Response("unexpected")),
  )).status === 500;
  const explicitLocalsWork = (await withRequestEnv(
    undefined,
    () => onRequest(suppliedContext, async () => new Response("ok")),
  )).status === 200;
  return Response.json({
    hostSecretBefore,
    hostSecretAfter,
    passwordIsolated,
    modernIsolated,
    audienceIsolated,
    identityIsolated,
    loginRejected,
    consentRejected,
    emptyAccount,
    existingRejects,
    existingAccepts,
    secretStoreWorks,
    secretStoreFailureClosed,
    credentialGetterClosed,
    missingContextClosed,
    explicitLocalsWork,
  });
}
