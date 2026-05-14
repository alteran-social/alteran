import { describe, it, beforeEach } from './helpers/bdd.ts';
import { expect } from '@std/expect';
import { attemptRefresh } from '../src/lib/refresh-session.ts';
import { issueSessionTokens, verifyAccessToken } from '../src/lib/session-tokens.ts';
import { storeRefreshToken } from '../src/db/account.ts';
import { createAppPasswordRow } from '../src/db/app-password.ts';
import { hashPassword } from '../src/lib/password.ts';
import { makeEnv } from './helpers/env.ts';
import { AuthScope } from '../src/lib/auth-scope.ts';
import type { Env } from '../src/env.ts';

const DID = 'did:example:test';

describe('refresh-session preserves app-password scope', () => {
  let env: Env;
  beforeEach(async () => { env = await makeEnv(); });

  it('rotates a non-privileged app-password refresh into a com.atproto.appPass access token', async () => {
    await createAppPasswordRow(env, {
      did: DID, name: 'cli',
      passwordScrypt: await hashPassword('abcd-efgh-2345-67mn'),
      privileged: false,
    });
    const { refreshJwt, refreshPayload, refreshExpiry } = await issueSessionTokens(env, DID, {
      accessScope: AuthScope.AppPass,
    });
    await storeRefreshToken(env, {
      id: refreshPayload.jti, did: DID, expiresAt: refreshExpiry, appPasswordName: 'cli',
    });
    const outcome = await attemptRefresh({ env, token: refreshJwt, nowSec: Math.floor(Date.now() / 1000) });
    expect(outcome.tag).toBe('success');
    if (outcome.tag !== 'success') return;
    expect((await verifyAccessToken(env, outcome.accessJwt)).scope).toBe(AuthScope.AppPass);
  });

  it('rotates a privileged app-password refresh into a com.atproto.appPassPrivileged access token', async () => {
    await createAppPasswordRow(env, {
      did: DID, name: 'tools',
      passwordScrypt: await hashPassword('mnop-qrst-2345-6abc'),
      privileged: true,
    });
    const { refreshJwt, refreshPayload, refreshExpiry } = await issueSessionTokens(env, DID, {
      accessScope: AuthScope.AppPassPrivileged,
    });
    await storeRefreshToken(env, {
      id: refreshPayload.jti, did: DID, expiresAt: refreshExpiry, appPasswordName: 'tools',
    });
    const outcome = await attemptRefresh({ env, token: refreshJwt, nowSec: Math.floor(Date.now() / 1000) });
    expect(outcome.tag).toBe('success');
    if (outcome.tag !== 'success') return;
    expect((await verifyAccessToken(env, outcome.accessJwt)).scope).toBe(AuthScope.AppPassPrivileged);
  });

  it('refuses to refresh when the underlying app password has been revoked', async () => {
    const { refreshJwt, refreshPayload, refreshExpiry } = await issueSessionTokens(env, DID, {
      accessScope: AuthScope.AppPass,
    });
    await storeRefreshToken(env, {
      id: refreshPayload.jti, did: DID, expiresAt: refreshExpiry, appPasswordName: 'cli',
    });
    const outcome = await attemptRefresh({ env, token: refreshJwt, nowSec: Math.floor(Date.now() / 1000) });
    expect(outcome.tag).toBe('failure');
    if (outcome.tag === 'failure') expect(outcome.code).toBe('InvalidToken');
  });
});
