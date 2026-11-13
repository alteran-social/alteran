import type { APIContext } from 'astro';
import { describe, it } from './helpers/bdd';
import { expect } from '@std/expect';
import { GET, HEAD, POST } from '../src/pages/xrpc/[...nsid]';
import { makeEnv } from './helpers/env';
import { issueSessionTokens } from '../src/lib/session-tokens';

function context(env: Awaited<ReturnType<typeof makeEnv>>, request: Request, nsid: string): APIContext {
  return { locals: { env }, request, params: { nsid } } as unknown as APIContext;
}

describe('unsupported Spaces endpoints', () => {
  it('returns 501 without authenticating or forwarding known Spaces namespaces', async () => {
    const env = await makeEnv();
    const { accessJwt } = await issueSessionTokens(env, 'did:example:test');
    const endpoints = [
      'com.atproto.space.getRepo',
      'com.atproto.space.createRecord',
      'com.atproto.personalspace.example',
      'com.atproto.memberspace.putMembers',
      'com.atproto.managedspace.checkAccess',
      'Com.Atproto.Space.getRepo',
    ];
    const originalFetch = globalThis.fetch;
    let forwarded = false;
    globalThis.fetch = (() => {
      forwarded = true;
      throw new Error('unexpected network request');
    }) as typeof fetch;
    try {
      for (const nsid of endpoints) {
        for (const authorization of [undefined, `Bearer ${accessJwt}`]) {
          for (const proxy of [undefined, 'did:example:other#atproto_pds']) {
            for (const [method, handler] of [['GET', GET], ['POST', POST], ['HEAD', HEAD]] as const) {
              const request = new Request(`https://pds.example/xrpc/${nsid}`, {
                method,
                headers: {
                  ...(authorization ? { authorization } : {}),
                  ...(proxy ? { 'atproto-proxy': proxy } : {}),
                },
              });
              const response = await handler(context(env, request, nsid));
              expect(response.status).toBe(501);
              expect(response.headers.get('content-type')).toBe('application/json');
              if (method === 'HEAD') {
                expect(await response.text()).toBe('');
              } else {
                expect(await response.json()).toEqual({
                  error: 'NotImplemented',
                  message: 'AT Protocol Spaces are not supported by this PDS',
                });
              }
            }
          }
        }
      }
      expect(forwarded).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('does not match adjacent namespaces', async () => {
    const env = await makeEnv();
    const nsid = 'com.atproto.spacetime.get';
    const request = new Request(`https://pds.example/xrpc/${nsid}`);
    expect((await GET(context(env, request, nsid))).status).toBe(401);
  });
});
