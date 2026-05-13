import { describe, expect, it } from 'bun:test';
import { SignJWT } from 'jose';
import { makeEnv } from './helpers/env';
import { makeDpopKey, signResourceDpop } from './helpers/oauth';
import { createOAuthSession, getSecret, storeRefreshToken } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { authenticateRequest } from '../src/lib/auth';
import { AuthScope, bearerAccessContext, oauthAccessContext } from '../src/lib/auth-scope';
import { proxyAppView } from '../src/lib/appview';
import { verifyResourceRequestHybrid } from '../src/lib/oauth/resource';
import { issueSessionTokens, verifyAccessToken } from '../src/lib/session-tokens';

const did = 'did:example:test';
const clientId = 'https://client.example/metadata';

async function signAccessWithScope(env: any, scope: string): Promise<string> {
  await issueSessionTokens(env, did);
  const secret = await getSecret(env, 'session_jwt_secret');
  if (!secret) throw new Error('missing test session secret');
  const now = Math.floor(Date.now() / 1000);
  const key = new TextEncoder().encode(secret);
  return new SignJWT({
    scope,
    aud: env.PDS_DID,
    sub: did,
    iat: now,
    exp: now + 7200,
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
    .setSubject(did)
    .setAudience(env.PDS_DID)
    .setIssuedAt(now)
    .setExpirationTime(now + 7200)
    .sign(key);
}

async function issueOauthAccess(env: any, key: Awaited<ReturnType<typeof makeDpopKey>>) {
  const sessionId = crypto.randomUUID().replace(/-/g, '');
  const accessJti = crypto.randomUUID().replace(/-/g, '');
  const { accessJwt, accessPayload, refreshPayload, refreshExpiry } = await issueSessionTokens(
    env,
    did,
    {
      scope: 'atproto transition:generic',
      clientId,
      dpopJkt: key.jkt,
      oauthSessionId: sessionId,
      accessJti,
    },
  );
  await createOAuthSession(env, {
    id: sessionId,
    did,
    clientId,
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
    did,
    expiresAt: refreshExpiry,
    tokenKind: 'oauth',
    oauthSessionId: sessionId,
    clientId,
    clientAuthMethod: 'none',
    dpopJkt: key.jkt,
    oauthScope: 'atproto transition:generic',
    accessJti: String(accessPayload.jti),
  });
  return accessJwt;
}

describe('ATProto auth scopes', () => {
  it('issues full-access and refresh tokens with ATProto scope names', async () => {
    const env = await makeEnv();
    const { accessJwt, accessPayload, refreshPayload } = await issueSessionTokens(env, did);

    expect(accessPayload.scope).toBe(AuthScope.Access);
    expect(refreshPayload.scope).toBe(AuthScope.Refresh);

    const auth = await authenticateRequest(
      new Request('https://pds.example/xrpc/com.atproto.server.getSession', {
        headers: { authorization: `Bearer ${accessJwt}` },
      }),
      env,
    );
    expect(auth?.access).toMatchObject({
      credentialType: 'bearer',
      kind: 'full',
      scope: AuthScope.Access,
      accountStatus: 'active',
      isFullAccess: true,
      isPrivileged: true,
      isOAuth: false,
    });
  });

  it('distinguishes non-privileged and privileged app-password bearer scopes', async () => {
    const env = await makeEnv();

    const { accessJwt: appPass } = await issueSessionTokens(env, did, {
      scope: AuthScope.AppPass,
    });
    const appPassAuth = await authenticateRequest(
      new Request('https://pds.example/xrpc/app.bsky.actor.getPreferences', {
        headers: { authorization: `Bearer ${appPass}` },
      }),
      env,
    );
    expect(appPassAuth?.access).toMatchObject({
      kind: 'app-password',
      isAppPassword: true,
      isPrivileged: false,
    });

    const { accessJwt: privileged } = await issueSessionTokens(env, did, {
      scope: AuthScope.AppPassPrivileged,
    });
    const privilegedAuth = await authenticateRequest(
      new Request('https://pds.example/xrpc/app.bsky.actor.getPreferences', {
        headers: { authorization: `Bearer ${privileged}` },
      }),
      env,
    );
    expect(privilegedAuth?.access).toMatchObject({
      kind: 'app-password-privileged',
      isAppPassword: true,
      isPrivileged: true,
    });
  });

  it('preserves OAuth DPoP permission scopes as OAuth auth context', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const access = await issueOauthAccess(env, key);
    const url = 'https://pds.example/xrpc/com.atproto.repo.createRecord';

    const resourceProof = await signResourceDpop(env, key, 'POST', url, access);
    const resource = await verifyResourceRequestHybrid(
      env,
      new Request(url, {
        method: 'POST',
        headers: { authorization: `DPoP ${access}`, dpop: resourceProof },
      }),
    );
    expect(resource?.access).toMatchObject({
      credentialType: 'oauth-dpop',
      kind: 'oauth',
      scope: 'atproto transition:generic',
      isOAuth: true,
    });

    const authProof = await signResourceDpop(env, key, 'POST', url, access);
    const auth = await authenticateRequest(
      new Request(url, {
        method: 'POST',
        headers: { authorization: `DPoP ${access}`, dpop: authProof },
      }),
      env,
    );
    expect(auth?.access).toMatchObject({
      kind: 'oauth',
      accountStatus: 'active',
      isOAuth: true,
    });
  });

  it('rejects unknown bearer access scopes instead of treating them as full access', async () => {
    const env = await makeEnv();
    await expect(issueSessionTokens(env, did, { scope: 'mystery.scope' }))
      .rejects.toThrow('Invalid access token scope');

    const token = await signAccessWithScope(env, 'mystery.scope');
    await expect(verifyAccessToken(env, token)).rejects.toThrow('Invalid access token scope');
    expect(await authenticateRequest(
      new Request('https://pds.example/xrpc/app.bsky.feed.getTimeline', {
        headers: { authorization: `Bearer ${token}` },
      }),
      env,
    )).toBeNull();
  });

  it('surfaces takedown and deactivated account state in auth context', async () => {
    const takendownEnv = await makeEnv();
    await setAccountState(takendownEnv, did, { tag: 'takendown' });
    const { accessJwt: takendownJwt } = await issueSessionTokens(takendownEnv, did);
    const takendownAuth = await authenticateRequest(
      new Request('https://pds.example/xrpc/com.atproto.server.getSession', {
        headers: { authorization: `Bearer ${takendownJwt}` },
      }),
      takendownEnv,
    );
    expect(takendownAuth?.access).toMatchObject({
      kind: 'full',
      accountStatus: 'takendown',
      isTakendown: true,
    });

    const { accessJwt: takendownScopeJwt } = await issueSessionTokens(takendownEnv, did, {
      scope: AuthScope.Takendown,
    });
    const takendownScopeAuth = await authenticateRequest(
      new Request('https://pds.example/xrpc/com.atproto.server.getSession', {
        headers: { authorization: `Bearer ${takendownScopeJwt}` },
      }),
      takendownEnv,
    );
    expect(takendownScopeAuth?.access.kind).toBe('takendown');

    const deactivatedEnv = await makeEnv();
    await setAccountState(deactivatedEnv, did, { tag: 'deactivated' });
    const { accessJwt: deactivatedJwt } = await issueSessionTokens(deactivatedEnv, did);
    const deactivatedAuth = await authenticateRequest(
      new Request('https://pds.example/xrpc/com.atproto.server.getSession', {
        headers: { authorization: `Bearer ${deactivatedJwt}` },
      }),
      deactivatedEnv,
    );
    expect(deactivatedAuth?.access).toMatchObject({
      kind: 'full',
      accountStatus: 'deactivated',
      isTakendown: false,
    });
  });

  it('does not let AppView proxy policy default unknown scopes to full access', async () => {
    const env = await makeEnv();
    const response = await proxyAppView({
      env,
      lxm: 'app.bsky.feed.getTimeline',
      request: new Request('https://pds.example/xrpc/app.bsky.feed.getTimeline'),
      auth: {
        token: 'bad-token',
        claims: { sub: did, scope: 'mystery.scope', t: 'access' },
        access: bearerAccessContext(AuthScope.Access),
      },
    });
    expect(response.status).toBe(401);
    expect((await response.json()) as any).toMatchObject({ error: 'InvalidToken' });
  });

  it('rejects protected proxy methods for OAuth and app-password credentials', async () => {
    const env = await makeEnv();
    const request = new Request('https://pds.example/xrpc/com.atproto.identity.updateHandle');

    const oauth = await proxyAppView({
      env,
      lxm: 'com.atproto.identity.updateHandle',
      request,
      auth: {
        token: 'oauth-token',
        claims: { sub: did, scope: 'atproto', t: 'access' },
        access: oauthAccessContext('atproto'),
      },
    });
    expect(oauth.status).toBe(400);

    const appPass = await proxyAppView({
      env,
      lxm: 'com.atproto.identity.updateHandle',
      request,
      auth: {
        token: 'app-pass-token',
        claims: { sub: did, scope: AuthScope.AppPass, t: 'access' },
        access: bearerAccessContext(AuthScope.AppPass),
      },
    });
    expect(appPass.status).toBe(400);
  });
});
