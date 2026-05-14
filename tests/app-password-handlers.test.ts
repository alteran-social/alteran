import { describe, it, beforeEach } from './helpers/bdd.ts';
import { expect } from '@std/expect';
import { POST as createHandler } from '../src/pages/xrpc/com.atproto.server.createAppPassword.ts';
import { GET as listHandler } from '../src/pages/xrpc/com.atproto.server.listAppPasswords.ts';
import { POST as revokeHandler } from '../src/pages/xrpc/com.atproto.server.revokeAppPassword.ts';
import { issueSessionTokens } from '../src/lib/session-tokens.ts';
import { storeRefreshToken, getRefreshToken } from '../src/db/account.ts';
import { listAppPasswordRows, findAppPasswordByName } from '../src/db/app-password.ts';
import { makeEnv } from './helpers/env.ts';
import { buildHandlerContext } from './helpers/handler-context.ts';
import { AuthScope } from '../src/lib/auth-scope.ts';
import type { Env } from '../src/env.ts';

const DID = 'did:example:test';

async function fullAccessToken(env: Env): Promise<string> {
  const { accessJwt } = await issueSessionTokens(env, DID, { accessScope: AuthScope.Access });
  return accessJwt;
}

async function appPassToken(env: Env): Promise<string> {
  const { accessJwt, refreshPayload, refreshExpiry } = await issueSessionTokens(env, DID, {
    accessScope: AuthScope.AppPass,
  });
  await storeRefreshToken(env, {
    id: refreshPayload.jti, did: DID, expiresAt: refreshExpiry, appPasswordName: 'phone',
  });
  return accessJwt;
}

describe('createAppPassword', () => {
  let env: Env;
  beforeEach(async () => { env = await makeEnv(); });

  it('returns the generated password and persists the row', async () => {
    const response = await createHandler(buildHandlerContext(env, {
      bearerToken: await fullAccessToken(env),
      body: { name: 'cli', privileged: false },
    }));
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.name).toBe('cli');
    expect(body.privileged).toBe(false);
    expect(body.password).toMatch(/^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$/);
    expect(typeof body.createdAt).toBe('string');
    expect(new Date(body.createdAt).toString()).not.toBe('Invalid Date');
    expect((await listAppPasswordRows(env, DID)).length).toBe(1);
  });

  it('echoes the stored createdAt rather than computing a fresh one', async () => {
    const token = await fullAccessToken(env);
    const response = await createHandler(buildHandlerContext(env, { bearerToken: token, body: { name: 'cli' } }));
    const body = await response.json();
    const stored = await findAppPasswordByName(env, DID, 'cli');
    expect(stored).not.toBe(null);
    if (!stored) return;
    expect(body.createdAt).toBe(new Date(stored.createdAt * 1000).toISOString());
  });

  it('returns InvalidRequest with status 400 for duplicate names', async () => {
    const token = await fullAccessToken(env);
    await createHandler(buildHandlerContext(env, { bearerToken: token, body: { name: 'cli' } }));
    const dup = await createHandler(buildHandlerContext(env, { bearerToken: token, body: { name: 'cli' } }));
    expect(dup.status).toBe(400);
    expect((await dup.json()).error).toBe('InvalidRequest');
  });

  it('rejects app-password sessions with AuthRequired', async () => {
    const response = await createHandler(buildHandlerContext(env, {
      bearerToken: await appPassToken(env),
      body: { name: 'cli', privileged: false },
    }));
    expect(response.status).toBe(401);
    expect((await response.json()).error).toBe('AuthRequired');
  });
});

describe('listAppPasswords', () => {
  let env: Env;
  beforeEach(async () => { env = await makeEnv(); });

  it('returns names and privileged flag, never the hash', async () => {
    const token = await fullAccessToken(env);
    await createHandler(buildHandlerContext(env, { bearerToken: token, body: { name: 'cli', privileged: true } }));
    const response = await listHandler(buildHandlerContext(env, { method: 'GET', bearerToken: token }));
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.passwords.length).toBe(1);
    expect(body.passwords[0].name).toBe('cli');
    expect(body.passwords[0].privileged).toBe(true);
    expect(typeof body.passwords[0].createdAt).toBe('string');
    expect('passwordScrypt' in body.passwords[0]).toBe(false);
  });

  it('rejects app-password sessions with AuthRequired', async () => {
    const response = await listHandler(buildHandlerContext(env, { method: 'GET', bearerToken: await appPassToken(env) }));
    expect(response.status).toBe(401);
  });
});

describe('revokeAppPassword', () => {
  let env: Env;
  beforeEach(async () => { env = await makeEnv(); });

  it('removes the row and revokes refresh tokens bound to that name', async () => {
    const token = await fullAccessToken(env);
    await createHandler(buildHandlerContext(env, { bearerToken: token, body: { name: 'cli' } }));
    await storeRefreshToken(env, { id: 'rt-cli', did: DID, expiresAt: 9_999_999_999, appPasswordName: 'cli' });
    const response = await revokeHandler(buildHandlerContext(env, { bearerToken: token, body: { name: 'cli' } }));
    expect(response.status).toBe(200);
    expect(await findAppPasswordByName(env, DID, 'cli')).toBe(null);
    expect((await getRefreshToken(env, 'rt-cli'))?.revokedAt).toBeTruthy();
  });

  it('returns InvalidRequest with status 400 for unknown name', async () => {
    const token = await fullAccessToken(env);
    const response = await revokeHandler(buildHandlerContext(env, { bearerToken: token, body: { name: 'absent' } }));
    expect(response.status).toBe(400);
    expect((await response.json()).error).toBe('InvalidRequest');
  });

  it('rejects app-password sessions with AuthRequired', async () => {
    const response = await revokeHandler(buildHandlerContext(env, {
      bearerToken: await appPassToken(env),
      body: { name: 'cli' },
    }));
    expect(response.status).toBe(401);
  });
});
