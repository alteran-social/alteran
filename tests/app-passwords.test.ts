import { describe, expect, it } from 'bun:test';
import { createOAuthSession, storeRefreshToken } from '../src/db/account';
import { authenticateRequest } from '../src/lib/auth';
import { AuthScope } from '../src/lib/auth-scope';
import { isAppPasswordFormat } from '../src/lib/app-passwords';
import { issueSessionTokens, verifyAccessToken, verifyRefreshToken } from '../src/lib/session-tokens';
import * as CreateAppPassword from '../src/pages/xrpc/com.atproto.server.createAppPassword';
import * as CreateSession from '../src/pages/xrpc/com.atproto.server.createSession';
import * as ListAppPasswords from '../src/pages/xrpc/com.atproto.server.listAppPasswords';
import * as RefreshSession from '../src/pages/xrpc/com.atproto.server.refreshSession';
import * as RevokeAppPassword from '../src/pages/xrpc/com.atproto.server.revokeAppPassword';
import { makeEnv } from './helpers/env';
import { makeDpopKey, signResourceDpop } from './helpers/oauth';

type TestEnv = Awaited<ReturnType<typeof makeEnv>>;

function apiContext(env: TestEnv, request: Request) {
  return { locals: { runtime: { env } }, request } as any;
}

async function json(res: Response) {
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

async function createSession(env: TestEnv, body: Record<string, unknown>) {
  return CreateSession.POST(apiContext(env, new Request(
    'https://pds.example/xrpc/com.atproto.server.createSession',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    },
  )));
}

async function primarySession(env: TestEnv) {
  const res = await createSession(env, {
    identifier: String(env.PDS_HANDLE),
    password: String(env.USER_PASSWORD),
  });
  expect(res.status).toBe(200);
  return json(res) as Promise<{ accessJwt: string; refreshJwt: string; did: string; handle: string }>;
}

async function createAppPassword(
  env: TestEnv,
  accessJwt: string,
  body: Record<string, unknown>,
) {
  return CreateAppPassword.POST(apiContext(env, new Request(
    'https://pds.example/xrpc/com.atproto.server.createAppPassword',
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${accessJwt}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    },
  )));
}

async function listAppPasswords(env: TestEnv, accessJwt: string) {
  return ListAppPasswords.GET(apiContext(env, new Request(
    'https://pds.example/xrpc/com.atproto.server.listAppPasswords',
    { headers: { authorization: `Bearer ${accessJwt}` } },
  )));
}

async function revokeAppPassword(env: TestEnv, accessJwt: string, name: string) {
  return RevokeAppPassword.POST(apiContext(env, new Request(
    'https://pds.example/xrpc/com.atproto.server.revokeAppPassword',
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${accessJwt}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ name }),
    },
  )));
}

async function refreshSession(env: TestEnv, refreshJwt: string) {
  return RefreshSession.POST(apiContext(env, new Request(
    'https://pds.example/xrpc/com.atproto.server.refreshSession',
    {
      method: 'POST',
      headers: { authorization: `Bearer ${refreshJwt}` },
    },
  )));
}

async function issueOAuthAccess(env: TestEnv) {
  const key = await makeDpopKey();
  const sessionId = crypto.randomUUID().replace(/-/g, '');
  const accessJti = crypto.randomUUID().replace(/-/g, '');
  const { accessJwt, accessPayload, refreshPayload, refreshExpiry } = await issueSessionTokens(
    env,
    String(env.PDS_DID),
    {
      scope: 'atproto transition:generic',
      clientId: 'https://client.example/metadata',
      dpopJkt: key.jkt,
      oauthSessionId: sessionId,
      accessJti,
    },
  );
  await createOAuthSession(env, {
    id: sessionId,
    did: String(env.PDS_DID),
    clientId: 'https://client.example/metadata',
    clientAuthMethod: 'none',
    clientAuthKeyId: null,
    dpopJkt: key.jkt,
    scope: 'atproto transition:generic',
    currentRefreshTokenId: refreshPayload.jti,
    accessJti: String(accessPayload.jti),
    expiresAt: refreshExpiry,
  });
  await storeRefreshToken(env, {
    id: refreshPayload.jti,
    did: String(env.PDS_DID),
    expiresAt: refreshExpiry,
    tokenKind: 'oauth',
    oauthSessionId: sessionId,
    clientId: 'https://client.example/metadata',
    clientAuthMethod: 'none',
    dpopJkt: key.jkt,
    oauthScope: 'atproto transition:generic',
    accessJti: String(accessPayload.jti),
  });
  const url = 'https://pds.example/xrpc/com.atproto.server.createAppPassword';
  return {
    authorization: `DPoP ${accessJwt}`,
    dpop: await signResourceDpop(env, key, 'POST', url, accessJwt),
  };
}

describe('app passwords', () => {
  it('creates, lists, and revokes app passwords with full-access credentials', async () => {
    const env = await makeEnv();
    const session = await primarySession(env);

    const created = await createAppPassword(env, session.accessJwt, { name: 'bot' });
    expect(created.status).toBe(200);
    const createdBody = await json(created);
    expect(createdBody.name).toBe('bot');
    expect(isAppPasswordFormat(createdBody.password)).toBe(true);
    expect(createdBody.privileged).toBe(false);
    expect(Date.parse(createdBody.createdAt)).toBeGreaterThan(0);

    const duplicate = await createAppPassword(env, session.accessJwt, { name: 'bot' });
    expect(duplicate.status).toBe(400);
    expect((await json(duplicate)).error).toBe('InvalidRequest');

    const listed = await listAppPasswords(env, session.accessJwt);
    expect(listed.status).toBe(200);
    expect(await json(listed)).toEqual({
      passwords: [{
        name: 'bot',
        createdAt: createdBody.createdAt,
        privileged: false,
      }],
    });

    const revoked = await revokeAppPassword(env, session.accessJwt, 'bot');
    expect(revoked.status).toBe(200);
    expect(await json(revoked)).toEqual({});

    const after = await listAppPasswords(env, session.accessJwt);
    expect(await json(after)).toEqual({ passwords: [] });
  });

  it('logs in with app passwords and issues scoped bearer sessions', async () => {
    const env = await makeEnv();
    const session = await primarySession(env);
    const bot = await json(await createAppPassword(env, session.accessJwt, { name: 'bot' }));
    const admin = await json(await createAppPassword(
      env,
      session.accessJwt,
      { name: 'admin', privileged: true },
    ));

    const botLogin = await createSession(env, {
      identifier: String(env.PDS_HANDLE),
      password: bot.password,
    });
    expect(botLogin.status).toBe(200);
    const botBody = await json(botLogin);
    expect((await verifyAccessToken(env, botBody.accessJwt)).scope).toBe(AuthScope.AppPass);
    const botAuth = await authenticateRequest(new Request(
      'https://pds.example/xrpc/app.bsky.actor.getPreferences',
      { headers: { authorization: `Bearer ${botBody.accessJwt}` } },
    ), env);
    expect(botAuth?.access).toMatchObject({
      kind: 'app-password',
      isAppPassword: true,
      isPrivileged: false,
    });

    const adminLogin = await createSession(env, {
      identifier: String(env.PDS_HANDLE),
      password: admin.password,
    });
    expect(adminLogin.status).toBe(200);
    const adminBody = await json(adminLogin);
    expect((await verifyAccessToken(env, adminBody.accessJwt)).scope)
      .toBe(AuthScope.AppPassPrivileged);
  });

  it('rejects app-password and OAuth credentials for app-password management', async () => {
    const env = await makeEnv();
    const session = await primarySession(env);
    const bot = await json(await createAppPassword(env, session.accessJwt, { name: 'bot' }));
    const botLogin = await json(await createSession(env, {
      identifier: String(env.PDS_HANDLE),
      password: bot.password,
    }));

    const appPassAttempt = await createAppPassword(env, botLogin.accessJwt, { name: 'blocked' });
    expect(appPassAttempt.status).toBe(401);

    const oauthHeaders = await issueOAuthAccess(env);
    const oauthAttempt = await CreateAppPassword.POST(apiContext(env, new Request(
      'https://pds.example/xrpc/com.atproto.server.createAppPassword',
      {
        method: 'POST',
        headers: {
          ...oauthHeaders,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ name: 'blocked-oauth' }),
      },
    )));
    expect(oauthAttempt.status).toBe(401);
  });

  it('preserves app-password scope across refresh and revocation blocks reuse', async () => {
    const env = await makeEnv();
    const session = await primarySession(env);
    const bot = await json(await createAppPassword(env, session.accessJwt, { name: 'bot' }));
    const botLogin = await json(await createSession(env, {
      identifier: String(env.PDS_HANDLE),
      password: bot.password,
    }));

    const refreshed = await refreshSession(env, botLogin.refreshJwt);
    expect(refreshed.status).toBe(200);
    const refreshedBody = await json(refreshed);
    expect((await verifyAccessToken(env, refreshedBody.accessJwt)).scope).toBe(AuthScope.AppPass);

    const stored = await env.ALTERAN_DB.prepare(
      'SELECT app_password_name AS appPasswordName FROM refresh_token WHERE id = ? LIMIT 1',
    ).bind((await verifyRefreshToken(env, refreshedBody.refreshJwt)).decoded.jti)
      .first<{ appPasswordName: string | null }>();
    expect(stored?.appPasswordName).toBe('bot');

    await revokeAppPassword(env, session.accessJwt, 'bot');

    const refreshAfterRevoke = await refreshSession(env, refreshedBody.refreshJwt);
    expect(refreshAfterRevoke.status).toBe(401);
    expect((await json(refreshAfterRevoke)).error).toBe('InvalidToken');

    const loginAfterRevoke = await createSession(env, {
      identifier: String(env.PDS_HANDLE),
      password: bot.password,
    });
    expect(loginAfterRevoke.status).toBe(401);
  });

  it('validates createSession input against required identifier and password fields', async () => {
    const env = await makeEnv();

    const missingIdentifier = await createSession(env, { password: String(env.USER_PASSWORD) });
    expect(missingIdentifier.status).toBe(400);
    expect((await json(missingIdentifier)).error).toBe('InvalidRequest');

    const missingPassword = await createSession(env, { identifier: String(env.PDS_HANDLE) });
    expect(missingPassword.status).toBe(400);
    expect((await json(missingPassword)).error).toBe('InvalidRequest');

    const emptyIdentifier = await createSession(env, {
      identifier: '   ',
      password: String(env.USER_PASSWORD),
    });
    expect(emptyIdentifier.status).toBe(400);
    expect((await json(emptyIdentifier)).error).toBe('InvalidRequest');

    const emptyPassword = await createSession(env, {
      identifier: String(env.PDS_HANDLE),
      password: '',
    });
    expect(emptyPassword.status).toBe(400);
    expect((await json(emptyPassword)).error).toBe('InvalidRequest');
  });
});
