import { expect } from '@std/expect';
import { describe, it } from './helpers/bdd';
import { makeEnv } from './helpers/env';
import { makeDpopKey, signAuthzDpop, signResourceDpop } from './helpers/oauth';
import { createAccount, getAccountByIdentifier } from '../src/db/account';
import { setAccountState } from '../src/db/dal';
import { createPersonalSpace } from '../src/db/space-lifecycle-create';
import { applySpaceWrites } from '../src/db/space-store';
import { hashPassword } from '../src/lib/password';
import { sha256b64url } from '../src/lib/oauth/dpop';
import { GET as getSpaceRecord } from '../src/pages/xrpc/com.atproto.space.getRecord';
import { POST as parPost } from '../src/pages/oauth/par';
import { GET as consentGet, POST as consentPost } from '../src/pages/oauth/consent';
import { POST as tokenPost } from '../src/pages/oauth/token';

const origin = 'https://pds.example';
const scope = 'atproto space:com.example.forum?action=read_self';
const client = `http://localhost?${new URLSearchParams({ redirect_uri: 'http://127.0.0.1/callback', scope })}`;
const redirect = 'http://127.0.0.1:51789/callback';
const verifier = 'collection-free-read-code-verifier-0123456789';

describe('collection-free Space OAuth', () => {
  it('carries consent through token rotation and an owned-record HTTP response without declaration fetches', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const context = (request: Request) => ({ locals: { env }, request, url: new URL(request.url) }) as never;
    await createAccount(env, { did: 'did:example:test', handle: 'test.example', passwordScrypt: await hashPassword('pwd') });
    await setAccountState(env, 'did:example:test', { tag: 'active' });
    const owner = (await getAccountByIdentifier(env, 'did:example:test'))?.spaceIncarnation;
    if (!owner) throw new Error('Missing Space owner');
    const space = 'at://did:example:test/space/com.example.forum/general';
    await createPersonalSpace(env, space, { $type: 'com.atproto.personalspace.policy' }, crypto.randomUUID(), owner);
    await applySpaceWrites(env, space, 'did:example:test', [{
      action: 'create', collection: 'com.example.other', rkey: 'one',
      record: { $type: 'com.example.other', text: 'private' },
    }], owner);
    let fetches = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (() => { fetches++; throw new Error('Unexpected declaration fetch'); }) as typeof fetch;
    try {
      const parUrl = `${origin}/oauth/par`;
      const par = await parPost(context(new Request(parUrl, {
        method: 'POST', headers: { dpop: await signAuthzDpop(env, key, 'POST', parUrl), 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: client, response_type: 'code', redirect_uri: redirect, scope, state: 'state',
          code_challenge: await sha256b64url(verifier), code_challenge_method: 'S256' }),
      })));
      expect(par.status).toBe(201);
      const requestUri = (await par.json() as { request_uri: string }).request_uri;
      const page = await consentGet(context(new Request(`${origin}/oauth/consent?request_uri=${encodeURIComponent(requestUri)}`)));
      const html = await page.text();
      expect(html).toContain('Read your own repository, including all collections, in matching spaces');
      const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1];
      if (!csrf) throw new Error('Missing consent token');
      const approved = await consentPost(context(new Request(`${origin}/oauth/consent`, {
        method: 'POST', headers: { origin, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ request_uri: requestUri, client_id: client, csrf, password: 'pwd', decision: 'allow' }),
      })));
      const code = new URL(approved.headers.get('location') ?? '').searchParams.get('code');
      if (!code) throw new Error('Missing authorization code');
      const tokenUrl = `${origin}/oauth/token`;
      async function token(form: Record<string, string>) {
        return tokenPost(context(new Request(tokenUrl, {
          method: 'POST', headers: { dpop: await signAuthzDpop(env, key, 'POST', tokenUrl), 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ client_id: client, ...form }),
        })));
      }
      const issued = await token({ grant_type: 'authorization_code', code, redirect_uri: redirect, code_verifier: verifier });
      expect(issued.status).toBe(200);
      const initial = await issued.json() as { refresh_token: string; scope: string };
      expect(initial.scope).toContain('action=read_self');
      expect(initial.scope).not.toContain('collection=');
      const refreshed = await token({ grant_type: 'refresh_token', refresh_token: initial.refresh_token });
      expect(refreshed.status).toBe(200);
      const rotated = await refreshed.json() as { access_token: string; scope: string };
      expect(rotated.scope).toBe(initial.scope);
      const path = `${origin}/xrpc/com.atproto.space.getRecord`;
      const params = new URLSearchParams({ space, repo: 'did:example:test', collection: 'com.example.other', rkey: 'one' });
      const request = new Request(`${path}?${params}`, { headers: { authorization: `DPoP ${rotated.access_token}`,
        dpop: await signResourceDpop(env, key, 'GET', path, rotated.access_token) } });
      const response = await getSpaceRecord(context(request));
      expect(response.status).toBe(200);
      expect((await response.json() as { value: unknown }).value).toEqual({ $type: 'com.example.other', text: 'private' });
      expect(response.headers.get('cache-control')).toBe('private, no-store');
      expect(fetches).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
