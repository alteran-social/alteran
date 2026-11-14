import { expect } from "@std/expect";
import type { APIContext } from "astro";
import type { Env } from "../src/env";
import { createAccount, getAccountByIdentifier } from "../src/db/account";
import { hashPassword } from "../src/lib/password";
import { authenticateSingleUserPassword } from "../src/lib/oauth/consent";
import { resolveEnvSecrets, SecretResolutionError } from "../src/lib/secrets";
import { POST as createSession } from "../src/pages/xrpc/com.atproto.server.createSession";
import { describe, it } from "./helpers/bdd";
import { makeEnv } from "./helpers/env";

const did = "did:example:test";
const handle = "test.example";

function login(env: Env, password: string): Promise<Response> {
  const request = new Request(
    "https://pds.example/xrpc/com.atproto.server.createSession",
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: handle, password }),
    },
  );
  return createSession({ locals: { env }, request } as unknown as APIContext);
}

describe("account bootstrap environment isolation", () => {
  it("does not bootstrap either login path with another Env's password", async () => {
    const password = crypto.randomUUID();
    const foreign = await makeEnv({
      PDS_DID: did,
      PDS_HANDLE: handle,
      USER_PASSWORD: password,
    });
    const local = await makeEnv({
      PDS_DID: did,
      PDS_HANDLE: handle,
      USER_PASSWORD: undefined,
    });
    await resolveEnvSecrets(foreign);
    expect((await login(local, password)).status).toBe(401);
    expect((await getAccountByIdentifier(local, did)) === null).toBe(true);
    expect((await authenticateSingleUserPassword(local, password)) === null)
      .toBe(true);
    expect((await getAccountByIdentifier(local, did)) === null).toBe(true);
  });

  it("preserves an existing account and accepts only its own password", async () => {
    const foreignPassword = crypto.randomUUID();
    const ownPassword = crypto.randomUUID();
    const foreign = await makeEnv({ USER_PASSWORD: foreignPassword });
    const local = await makeEnv({ USER_PASSWORD: undefined });
    await createAccount(local, {
      did,
      handle,
      passwordScrypt: await hashPassword(ownPassword),
    });
    await resolveEnvSecrets(foreign);
    expect((await login(local, foreignPassword)).status).toBe(401);
    expect(
      (await authenticateSingleUserPassword(local, foreignPassword)) === null,
    ).toBe(true);
    expect((await login(local, ownPassword)).status).toBe(200);
    expect((await authenticateSingleUserPassword(local, ownPassword))?.did)
      .toBe(did);
  });

  it("bootstraps from the request's own string and Secret Store values", async () => {
    const password = ` ${crypto.randomUUID()} `;
    const stringEnv = await makeEnv({
      PDS_DID: did,
      PDS_HANDLE: handle,
      USER_PASSWORD: password,
    });
    expect((await login(stringEnv, password)).status).toBe(200);
    expect((await login(stringEnv, password.trim())).status).toBe(401);
    const storeEnv = await makeEnv({
      PDS_DID: { get: async () => did },
      PDS_HANDLE: { get: async () => handle },
      USER_PASSWORD: { get: async () => password },
    });
    expect((await authenticateSingleUserPassword(storeEnv, password))?.did)
      .toBe(did);
    expect((await login(storeEnv, password)).status).toBe(200);
    expect(
      (await authenticateSingleUserPassword(storeEnv, password.trim())) ===
        null,
    ).toBe(true);
  });

  it("does not bootstrap either account path from scalar credentials", async () => {
    for (const scalar of [false, 0, true]) {
      const env = await makeEnv({
        USER_PASSWORD: scalar,
      } as unknown as Partial<Env>);
      for (
        const run of [
          () => login(env, String(scalar)),
          () => authenticateSingleUserPassword(env, String(scalar)),
        ]
      ) {
        let caught: unknown;
        try {
          await run();
        } catch (error) {
          caught = error;
        }
        expect(caught instanceof SecretResolutionError).toBe(true);
        expect((await getAccountByIdentifier(env, did)) === null).toBe(true);
      }
    }
  });

  it("does not bootstrap either account path from blank credentials", async () => {
    const base = await makeEnv({ USER_PASSWORD: undefined });
    for (const value of [" \t\n", { get: async () => " \t\n" }]) {
      const env = { ...base, USER_PASSWORD: value };
      for (
        const run of [
          () => login(env, "irrelevant"),
          () => authenticateSingleUserPassword(env, "irrelevant"),
        ]
      ) {
        let caught: unknown;
        try {
          await run();
        } catch (error) {
          caught = error;
        }
        expect(caught instanceof SecretResolutionError).toBe(true);
        expect((await getAccountByIdentifier(base, did)) === null).toBe(true);
      }
    }
  });
});
