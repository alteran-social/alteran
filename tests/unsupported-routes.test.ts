import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from './helpers/env';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { GET as catchallGet, POST as catchallPost } from '../src/pages/xrpc/[...nsid]';
import { GET as describeServer } from '../src/pages/xrpc/com.atproto.server.describeServer';

const did = 'did:example:test';

function apiContext(env: any, request: Request, nsid: string) {
  return {
    locals: { runtime: { env } },
    params: { nsid },
    request,
  } as any;
}

async function expectUnsupported(response: Response, nsid: string) {
  expect(response.status).toBe(501);
  expect(response.headers.get('Content-Type')).toBe('application/json');
  const body = await response.json() as { error: string; message: string };
  expect(body).toEqual({
    error: 'NotImplemented',
    message: `${nsid} is intentionally unsupported by Alteran single-user PDS`,
  });
}

describe('intentionally unsupported single-user XRPC routes', () => {
  it('returns stable 501 for unauthenticated public signup routes', async () => {
    const env = await makeEnv();

    for (const [method, nsid] of [
      ['POST', 'com.atproto.server.createAccount'],
      ['POST', 'com.atproto.server.reserveSigningKey'],
      ['GET', 'com.atproto.temp.checkHandleAvailability'],
      ['GET', 'com.atproto.temp.checkSignupQueue'],
      ['POST', 'com.atproto.temp.requestPhoneVerification'],
    ] as const) {
      const request = new Request(`https://pds.example/xrpc/${nsid}`, { method });
      const response = method === 'GET'
        ? await catchallGet(apiContext(env, request, nsid))
        : await catchallPost(apiContext(env, request, nsid));

      await expectUnsupported(response, nsid);
    }
  });

  it('returns stable 501 for authenticated invite and account-management routes', async () => {
    const env = await makeEnv();
    const { accessJwt } = await issueSessionTokens(env, did);

    for (const nsid of [
      'com.atproto.server.createInviteCode',
      'com.atproto.server.createInviteCodes',
      'com.atproto.server.getAccountInviteCodes',
      'com.atproto.temp.addReservedHandle',
      'com.atproto.temp.revokeAccountCredentials',
    ]) {
      const response = await catchallPost(apiContext(
        env,
        new Request(`https://pds.example/xrpc/${nsid}`, {
          method: 'POST',
          headers: { authorization: `Bearer ${accessJwt}` },
        }),
        nsid,
      ));

      await expectUnsupported(response, nsid);
    }
  });

  it('returns stable 501 for unauthenticated admin routes before auth', async () => {
    const env = await makeEnv();
    const nsid = 'com.atproto.admin.getAccountInfo';

    const response = await catchallGet(apiContext(
      env,
      new Request(`https://pds.example/xrpc/${nsid}`),
      nsid,
    ));

    await expectUnsupported(response, nsid);
  });

  it('keeps generic unsupported routes on the existing auth-first path', async () => {
    const env = await makeEnv();
    const nsid = 'com.atproto.temp.dereferenceScope';

    const unauthenticated = await catchallGet(apiContext(
      env,
      new Request(`https://pds.example/xrpc/${nsid}`),
      nsid,
    ));
    expect(unauthenticated.status).toBe(401);

    const { accessJwt } = await issueSessionTokens(env, did);
    const authenticated = await catchallGet(apiContext(
      env,
      new Request(`https://pds.example/xrpc/${nsid}`, {
        headers: { authorization: `Bearer ${accessJwt}` },
      }),
      nsid,
    ));
    expect(authenticated.status).toBe(404);
    const body = await authenticated.json() as { error: string };
    expect(body).toEqual({ error: 'NotImplemented' });
  });

  it('advertises no public signup or invite capability from describeServer', async () => {
    const env = await makeEnv();
    const response = await describeServer({
      locals: { runtime: { env } },
      request: new Request('https://pds.example/xrpc/com.atproto.server.describeServer'),
    } as any);

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      did,
      availableUserDomains: [],
      inviteCodeRequired: false,
      phoneVerificationRequired: false,
    });
  });
});
