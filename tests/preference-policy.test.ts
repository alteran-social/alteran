import { describe, expect, it } from 'bun:test';
import { makeEnv } from './helpers/env';
import { makeDpopKey, signResourceDpop } from './helpers/oauth';
import { createOAuthSession, storeRefreshToken } from '../src/db/account';
import { AuthScope } from '../src/lib/auth-scope';
import { getActorPreferences, setActorPreferences } from '../src/lib/preferences';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { GET as getPreferences } from '../src/pages/xrpc/app.bsky.actor.getPreferences';
import { POST as putPreferences } from '../src/pages/xrpc/app.bsky.actor.putPreferences';

const did = 'did:example:test';
const clientId = 'https://client.example/metadata';
const preferencesUrl = 'https://pds.example/xrpc/app.bsky.actor.getPreferences';
const putPreferencesUrl = 'https://pds.example/xrpc/app.bsky.actor.putPreferences';

const savedFeedsPref = {
  $type: 'app.bsky.actor.defs#savedFeedsPref',
  saved: [],
  pinned: [],
};
const personalDetailsPref = {
  $type: 'app.bsky.actor.defs#personalDetailsPref',
  birthDate: '2000-01-01T00:00:00.000Z',
};
const appStatePref = {
  $type: 'app.bsky.actor.defs#bskyAppStatePref',
  nuxs: [],
};

function apiContext(env: any, request: Request) {
  return { locals: { runtime: { env } }, request } as any;
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

describe('Actor preference app-password policy', () => {
  it('lets full bearer credentials see restricted preferences', async () => {
    const env = await makeEnv();
    await setActorPreferences(env, [savedFeedsPref, personalDetailsPref, appStatePref]);
    const { accessJwt } = await issueSessionTokens(env, did);

    const response = await getPreferences(apiContext(
      env,
      new Request(preferencesUrl, {
        headers: { authorization: `Bearer ${accessJwt}` },
      }),
    ));

    expect(response.status).toBe(200);
    expect(((await response.json()) as any).preferences).toEqual([
      savedFeedsPref,
      personalDetailsPref,
      appStatePref,
    ]);
  });

  it('lets OAuth transition:generic credentials see restricted preferences', async () => {
    const env = await makeEnv();
    await setActorPreferences(env, [savedFeedsPref, personalDetailsPref, appStatePref]);
    const key = await makeDpopKey();
    const access = await issueOauthAccess(env, key);
    const proof = await signResourceDpop(env, key, 'GET', preferencesUrl, access);

    const response = await getPreferences(apiContext(
      env,
      new Request(preferencesUrl, {
        headers: { authorization: `DPoP ${access}`, dpop: proof },
      }),
    ));

    expect(response.status).toBe(200);
    expect(((await response.json()) as any).preferences).toEqual([
      savedFeedsPref,
      personalDetailsPref,
      appStatePref,
    ]);
  });

  it('filters restricted preferences for app-password reads', async () => {
    const env = await makeEnv();
    await setActorPreferences(env, [savedFeedsPref, personalDetailsPref, appStatePref]);
    const { accessJwt } = await issueSessionTokens(env, did, { scope: AuthScope.AppPass });

    const response = await getPreferences(apiContext(
      env,
      new Request(preferencesUrl, {
        headers: { authorization: `Bearer ${accessJwt}` },
      }),
    ));

    expect(response.status).toBe(200);
    expect(((await response.json()) as any).preferences).toEqual([savedFeedsPref]);
  });

  it('rejects app-password writes that include restricted preferences without persisting', async () => {
    const env = await makeEnv();
    await setActorPreferences(env, [savedFeedsPref]);
    const { accessJwt } = await issueSessionTokens(env, did, { scope: AuthScope.AppPass });

    const response = await putPreferences(apiContext(
      env,
      new Request(putPreferencesUrl, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${accessJwt}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ preferences: [personalDetailsPref] }),
      }),
    ));

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: 'Forbidden' });
    expect((await getActorPreferences(env)).preferences).toEqual([savedFeedsPref]);
  });

  it('allows app-password writes for ordinary saved-feed preferences', async () => {
    const env = await makeEnv();
    const { accessJwt } = await issueSessionTokens(env, did, { scope: AuthScope.AppPass });

    const response = await putPreferences(apiContext(
      env,
      new Request(putPreferencesUrl, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${accessJwt}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ preferences: [savedFeedsPref] }),
      }),
    ));

    expect(response.status).toBe(200);
    expect((await getActorPreferences(env)).preferences).toEqual([savedFeedsPref]);
  });

  it('preserves existing restricted preferences when app-password writes omit them', async () => {
    const env = await makeEnv();
    await setActorPreferences(env, [savedFeedsPref, personalDetailsPref, appStatePref]);
    const { accessJwt } = await issueSessionTokens(env, did, { scope: AuthScope.AppPass });
    const updatedSavedFeeds = {
      $type: 'app.bsky.actor.defs#savedFeedsPref',
      saved: ['at://did:example:test/app.bsky.feed.generator/abc'],
      pinned: [],
    };

    const response = await putPreferences(apiContext(
      env,
      new Request(putPreferencesUrl, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${accessJwt}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ preferences: [updatedSavedFeeds] }),
      }),
    ));

    expect(response.status).toBe(200);
    expect((await getActorPreferences(env)).preferences).toEqual([
      updatedSavedFeeds,
      personalDetailsPref,
      appStatePref,
    ]);
  });
});
