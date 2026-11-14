import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from "./helpers/env";
import { getSecret, setSecret } from "../src/db/account";
import {
  consumeConsent,
  deleteParSnapshot,
  loadCodeSnapshot,
  loadParSnapshot,
  type ParRecord,
  saveConsent,
  savePar,
} from "../src/lib/oauth/store";
import { saveCode } from "./helpers/oauth-store";
import { issueAuthorizationCode } from "../src/lib/oauth/issue-code";
import {
  GET as consentGet,
  POST as consentPost,
} from "../src/pages/oauth/consent";

const ID = "atomicrequest";
const ORIGIN = "https://pds.example";
const CLIENT = "http://localhost";
const URI = `urn:ietf:params:oauth:request_uri:${ID}`;
type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

async function seed(env: TestEnv, overrides: Partial<ParRecord> = {}) {
  const now = Math.floor(Date.now() / 1000);
  const record: ParRecord = {
    client_id: CLIENT,
    redirect_uri: "http://127.0.0.1:1234/",
    code_challenge: "challenge",
    code_challenge_method: "S256",
    scope: "atproto",
    state: "state",
    dpopJkt: "jkt",
    clientAuthMethod: "none",
    createdAt: now,
    expiresAt: now + 300,
    ...overrides,
  };
  await savePar(env, ID, record);
  return record;
}

async function capture(env: TestEnv) {
  const snapshot = await loadParSnapshot(env, ID);
  if (!snapshot) throw new Error("Missing PAR");
  await saveConsent(
    env,
    ID,
    "csrf",
    Math.floor(Date.now() / 1000) + 300,
    snapshot.value,
  );
  const consent = await consumeConsent(env, ID, "csrf");
  if (!consent) throw new Error("Missing consent");
  return { snapshot, consent };
}

async function codeCount(env: TestEnv): Promise<number> {
  const row = await env.ALTERAN_DB.prepare(
    "SELECT COUNT(*) AS count FROM secret WHERE key LIKE 'oauth:code:%'",
  ).first<{ count: number }>();
  return row?.count ?? -1;
}

function context(env: TestEnv, request: Request) {
  return { locals: { env }, request, url: new URL(request.url) } as any;
}

async function page(env: TestEnv): Promise<string> {
  const response = await consentGet(context(
    env,
    new Request(
      `${ORIGIN}/oauth/consent?request_uri=${encodeURIComponent(URI)}`,
    ),
  ));
  expect(response.status).toBe(200);
  const csrf = (await response.text()).match(/name="csrf" value="([^"]+)"/)
    ?.[1];
  if (!csrf) throw new Error("Missing CSRF");
  return csrf;
}

function submit(env: TestEnv, csrf: string, decision = "allow") {
  return consentPost(context(
    env,
    new Request(`${ORIGIN}/oauth/consent`, {
      method: "POST",
      headers: {
        origin: ORIGIN,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        request_uri: URI,
        client_id: CLIENT,
        csrf,
        decision,
        password: "pwd",
      }).toString(),
    }),
  ));
}

function pauseBatch(env: TestEnv) {
  let started: () => void = () => {};
  let resume: () => void = () => {};
  const entered = new Promise<void>((resolve) => started = resolve);
  const blocked = new Promise<void>((resolve) => resume = resolve);
  const database = env.ALTERAN_DB;
  const delayed = new Proxy(database, {
    get(target, property) {
      if (property === "batch") {
        return async (statements: Parameters<typeof database.batch>[0]) => {
          started();
          await blocked;
          return database.batch(statements);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { env: { ...env, ALTERAN_DB: delayed }, entered, resume };
}

describe("OAuth consent and code atomicity", () => {
  it("issues only one code when a second consent page is approved during the first approval", async () => {
    const env = await makeEnv();
    await seed(env);
    const firstCsrf = await page(env);
    const pause = pauseBatch(env);
    const first = submit(pause.env, firstCsrf);
    await pause.entered;
    try {
      const secondCsrf = await page(env);
      const second = await submit(env, secondCsrf);
      expect(second.status).toBe(302);
      expect(
        new URL(second.headers.get("location") ?? "").searchParams.get("code"),
      ).toBeTruthy();
    } finally {
      pause.resume();
    }
    expect((await first).status).toBe(400);
    expect(await codeCount(env)).toBe(1);
  });

  it("does not issue the pending code when a later page denies the request", async () => {
    const env = await makeEnv();
    await seed(env);
    const firstCsrf = await page(env);
    const pause = pauseBatch(env);
    const first = submit(pause.env, firstCsrf);
    await pause.entered;
    try {
      const denied = await submit(env, await page(env), "deny");
      expect(
        new URL(denied.headers.get("location") ?? "").searchParams.get("error"),
      ).toBe("access_denied");
    } finally {
      pause.resume();
    }
    expect((await first).status).toBe(400);
    expect(await codeCount(env)).toBe(0);
  });

  it("rejects a changed pushed request after the consent page was displayed", async () => {
    const env = await makeEnv();
    await seed(env);
    const csrf = await page(env);
    await seed(env, { scope: "atproto transition:generic" });
    expect((await submit(env, csrf)).status).toBe(400);
    expect(await codeCount(env)).toBe(0);
    expect((await loadParSnapshot(env, ID))?.record.scope).toBe(
      "atproto transition:generic",
    );
  });

  it("does not erase a newer request when discarding an older snapshot", async () => {
    const env = await makeEnv();
    await seed(env);
    const old = await loadParSnapshot(env, ID);
    if (!old) throw new Error("Missing PAR");
    await seed(env, { state: "new-state" });
    await deleteParSnapshot(env, ID, old.value);
    expect((await loadParSnapshot(env, ID))?.record.state).toBe("new-state");
  });

  it("checks consent expiry against database time at code issuance", async () => {
    const env = await makeEnv();
    await seed(env);
    const snapshot = await loadParSnapshot(env, ID);
    if (!snapshot) throw new Error("Missing PAR");
    const clock = Date.now;
    const actual = clock();
    let consent;
    try {
      Date.now = () => actual - 5000;
      await saveConsent(
        env,
        ID,
        "csrf",
        Math.floor(actual / 1000) - 1,
        snapshot.value,
      );
      consent = await consumeConsent(env, ID, "csrf");
    } finally {
      Date.now = clock;
    }
    if (!consent) throw new Error("Expected initially live consent");
    expect(
      await issueAuthorizationCode(
        env,
        ID,
        snapshot,
        consent,
        "did:example:test",
      ),
    ).toBeNull();
    expect(await codeCount(env)).toBe(0);
  });

  it("checks PAR expiry against database time at code issuance", async () => {
    const env = await makeEnv();
    const clock = Date.now;
    const actual = clock();
    const seconds = Math.floor(actual / 1000);
    await seed(env, { createdAt: seconds - 100, expiresAt: seconds - 1 });
    let captured;
    try {
      Date.now = () => actual - 5000;
      captured = await capture(env);
    } finally {
      Date.now = clock;
    }
    expect(
      await issueAuthorizationCode(
        env,
        ID,
        captured.snapshot,
        captured.consent,
        "did:example:test",
      ),
    ).toBeNull();
    expect(await codeCount(env)).toBe(0);
  });

  it("rolls back code creation if a database trigger skips PAR consumption", async () => {
    const env = await makeEnv();
    await seed(env);
    const { snapshot, consent } = await capture(env);
    await env.ALTERAN_DB.exec(`CREATE TRIGGER ignore_par_consumption
      BEFORE UPDATE ON secret WHEN OLD.key = 'oauth:par:${ID}'
      BEGIN SELECT RAISE(IGNORE); END`.replace(/\n/g, " "));
    await expect(
      issueAuthorizationCode(env, ID, snapshot, consent, "did:example:test"),
    ).rejects.toThrow();
    expect(await codeCount(env)).toBe(0);
    expect((await loadParSnapshot(env, ID))?.value).toBe(snapshot.value);
  });

  it("rolls back PAR consumption if a trigger removes the issued code", async () => {
    const env = await makeEnv();
    await seed(env);
    const { snapshot, consent } = await capture(env);
    await env.ALTERAN_DB.exec(`CREATE TRIGGER remove_issued_code
      AFTER UPDATE ON secret WHEN OLD.key = 'oauth:par:${ID}'
      BEGIN DELETE FROM secret WHERE key LIKE 'oauth:code:%'; END`.replace(
      /\n/g,
      " ",
    ));
    await expect(
      issueAuthorizationCode(env, ID, snapshot, consent, "did:example:test"),
    ).rejects.toThrow();
    expect(await codeCount(env)).toBe(0);
    expect((await loadParSnapshot(env, ID))?.value).toBe(snapshot.value);
  });

  it("rolls back an inserted code if a trigger changes its value", async () => {
    const env = await makeEnv();
    await seed(env);
    const { snapshot, consent } = await capture(env);
    await env.ALTERAN_DB.exec(`CREATE TRIGGER change_issued_code
      AFTER INSERT ON secret WHEN NEW.key LIKE 'oauth:code:%'
      BEGIN UPDATE secret SET value = json_set(NEW.value, '$.extra', 1) WHERE key = NEW.key; END`
      .replace(/\n/g, " "));
    await expect(
      issueAuthorizationCode(env, ID, snapshot, consent, "did:example:test"),
    ).rejects.toThrow();
    expect(await codeCount(env)).toBe(0);
    expect((await loadParSnapshot(env, ID))?.value).toBe(snapshot.value);
  });

  it("rolls back if a trigger changes the PAR and removes the code", async () => {
    const env = await makeEnv();
    await seed(env);
    const { snapshot, consent } = await capture(env);
    await env.ALTERAN_DB.exec(`CREATE TRIGGER remove_code_and_change_par
      AFTER UPDATE ON secret WHEN OLD.key = 'oauth:par:${ID}' AND NEW.value LIKE '%consumedBy%'
      BEGIN
        DELETE FROM secret WHERE key LIKE 'oauth:code:%';
        UPDATE secret SET value = '{"blocked":true}' WHERE key = OLD.key;
      END`.replace(/\n/g, " "));
    await expect(
      issueAuthorizationCode(env, ID, snapshot, consent, "did:example:test"),
    ).rejects.toThrow();
    expect(await codeCount(env)).toBe(0);
    expect((await loadParSnapshot(env, ID))?.value).toBe(snapshot.value);
  });

  it("returns the code when an unrelated trigger adds database changes", async () => {
    const env = await makeEnv();
    await seed(env);
    const { snapshot, consent } = await capture(env);
    await env.ALTERAN_DB.exec(`CREATE TRIGGER record_code_issuance
      AFTER INSERT ON secret WHEN NEW.key LIKE 'oauth:code:%'
      BEGIN INSERT INTO secret (key, value, updated_at) VALUES ('test:issued', 'yes', 0); END`
      .replace(/\n/g, " "));
    const code = await issueAuthorizationCode(
      env,
      ID,
      snapshot,
      consent,
      "did:example:test",
    );
    expect(code).toBeTruthy();
    if (!code) throw new Error("Missing issued code");
    expect((await loadCodeSnapshot(env, code))?.record.did).toBe("did:example:test");
    expect(await loadParSnapshot(env, ID)).toBeNull();
  });

  it("recovers a committed code when the database response is lost", async () => {
    const env = await makeEnv();
    await seed(env);
    const { snapshot, consent } = await capture(env);
    const database = env.ALTERAN_DB;
    const delayed = new Proxy(database, {
      get(target, property) {
        if (property === "batch") {
          return async (statements: Parameters<typeof database.batch>[0]) => {
            await database.batch(statements);
            throw new Error("Lost database response");
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const code = await issueAuthorizationCode(
      { ...env, ALTERAN_DB: delayed },
      ID,
      snapshot,
      consent,
      "did:example:test",
    );
    expect(code).toBeTruthy();
    if (!code) throw new Error("Missing recovered code");
    expect((await loadCodeSnapshot(env, code))?.record.did).toBe("did:example:test");
    expect(await loadParSnapshot(env, ID)).toBeNull();
  });

  it("never overwrites an existing authorization code on collision", async () => {
    const env = await makeEnv();
    await seed(env);
    const { snapshot, consent } = await capture(env);
    const id = "11111111111141118111111111111111";
    const existing = {
      code: id,
      client_id: CLIENT,
      redirect_uri: "http://127.0.0.1:1234/",
      code_challenge: "other",
      scope: "atproto",
      dpopJkt: "other",
      clientAuthMethod: "none" as const,
      did: "did:example:test",
      createdAt: Math.floor(Date.now() / 1000),
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    };
    await saveCode(env, id, existing);
    Object.defineProperty(crypto, "randomUUID", {
      value: () => "11111111-1111-4111-8111-111111111111",
      configurable: true,
    });
    try {
      await expect(
        issueAuthorizationCode(env, ID, snapshot, consent, "did:example:test"),
      ).rejects.toThrow();
    } finally {
      delete (crypto as { randomUUID?: unknown }).randomUUID;
    }
    expect((await loadCodeSnapshot(env, id))?.record).toEqual(existing);
    expect((await loadParSnapshot(env, ID))?.value).toBe(snapshot.value);
  });

  it("rejects a pushed request without a valid expiration", async () => {
    const env = await makeEnv();
    const record = await seed(env);
    await setSecret(
      env,
      `oauth:par:${ID}`,
      JSON.stringify({ ...record, expiresAt: null }),
    );
    expect(await loadParSnapshot(env, ID)).toBeNull();
    expect(await getSecret(env, `oauth:par:${ID}`)).toBeTruthy();
  });
});
