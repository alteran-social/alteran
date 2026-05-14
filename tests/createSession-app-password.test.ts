import { describe, it, beforeEach } from './helpers/bdd.ts';
import { expect } from '@std/expect';
import { POST as createSession } from '../src/pages/xrpc/com.atproto.server.createSession.ts';
import { createAccount } from '../src/db/account.ts';
import { createAppPasswordRow } from '../src/db/app-password.ts';
import { hashPassword } from '../src/lib/password.ts';
import { verifyAccessToken } from '../src/lib/session-tokens.ts';
import { makeEnv } from './helpers/env.ts';
import { buildHandlerContext } from './helpers/handler-context.ts';
import { AuthScope } from '../src/lib/auth-scope.ts';
import type { Env } from '../src/env.ts';

const DID = 'did:example:test';
const HANDLE = 'test.example';
const PRIMARY = 'primary-password-XYZ';
const APP_NON_PRIV = 'abcd-efgh-2345-67mn';
const APP_PRIVILEGED = 'mnop-qrst-2345-6abc';

describe('createSession with app passwords', () => {
  let env: Env;
  beforeEach(async () => {
    env = await makeEnv();
    await createAccount(env, { did: DID, handle: HANDLE, passwordScrypt: await hashPassword(PRIMARY) });
    await createAppPasswordRow(env, { did: DID, name: 'cli',   passwordScrypt: await hashPassword(APP_NON_PRIV),  privileged: false });
    await createAppPasswordRow(env, { did: DID, name: 'tools', passwordScrypt: await hashPassword(APP_PRIVILEGED), privileged: true });
  });

  it('issues com.atproto.access for the primary password', async () => {
    const response = await createSession(buildHandlerContext(env, { body: { identifier: HANDLE, password: PRIMARY } }));
    expect(response.status).toBe(200);
    const claims = await verifyAccessToken(env, (await response.json()).accessJwt);
    expect(claims.scope).toBe(AuthScope.Access);
  });

  it('issues com.atproto.appPass for a non-privileged app password', async () => {
    const response = await createSession(buildHandlerContext(env, { body: { identifier: HANDLE, password: APP_NON_PRIV } }));
    expect(response.status).toBe(200);
    const claims = await verifyAccessToken(env, (await response.json()).accessJwt);
    expect(claims.scope).toBe(AuthScope.AppPass);
  });

  it('issues com.atproto.appPassPrivileged for a privileged app password', async () => {
    const response = await createSession(buildHandlerContext(env, { body: { identifier: HANDLE, password: APP_PRIVILEGED } }));
    expect(response.status).toBe(200);
    const claims = await verifyAccessToken(env, (await response.json()).accessJwt);
    expect(claims.scope).toBe(AuthScope.AppPassPrivileged);
  });

  it('rejects unknown credentials with AuthRequired', async () => {
    const response = await createSession(buildHandlerContext(env, { body: { identifier: HANDLE, password: 'wrong-wrong-wrong-x' } }));
    expect(response.status).toBe(401);
  });
});
