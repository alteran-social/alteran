import { describe, it } from './helpers/bdd';
import { expect } from '@std/expect';
import type { APIContext } from 'astro';
import type { Env } from '../src/env';
import { issueSessionTokens } from '../src/lib/session-tokens';
import { GET as getRecommendedDidCredentials } from '../src/pages/xrpc/com.atproto.identity.getRecommendedDidCredentials';
import { makeEnv } from './helpers/env';

const plcDid = 'did:plc:ewvi7nxzyoun6zhxrhs64oiz';
const signingKey = '8b5e3d226b44c4c88fbd3d4529f6283fb2b20f6deee8a0b34e7f0a9b12d3e4f1';
const plcUrl = `https://plc.directory/${encodeURIComponent(plcDid)}/data`;

function plcData() {
  return {
    did: plcDid,
    rotationKeys: ['did:key:zRotation'],
    verificationMethods: { atproto: 'did:key:zSigning' },
    alsoKnownAs: ['at://alice.example.com'],
    services: { atproto_pds: { type: 'AtprotoPersonalDataServer', endpoint: 'https://old.example.com' } },
  };
}

async function makeRequest(did = plcDid): Promise<{ env: Env; request: Request }> {
  const env = await makeEnv({
    PDS_DID: did,
    PDS_HANDLE: 'alice.example.com',
    PDS_HOSTNAME: 'pds.example.com',
    REPO_SIGNING_KEY: signingKey,
  });
  const { accessJwt } = await issueSessionTokens(env, did);
  return {
    env,
    request: new Request('https://pds.example.com/xrpc/com.atproto.identity.getRecommendedDidCredentials', {
      headers: { authorization: `Bearer ${accessJwt}` },
    }),
  };
}

function callEndpoint(env: Env, request: Request): Promise<Response> {
  return getRecommendedDidCredentials({ locals: { env }, request } as unknown as APIContext);
}

async function withPlcResponse(
  response: () => Response | Promise<Response>,
  run: () => Promise<void>,
): Promise<void> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input) === plcUrl) {
      expect(init?.redirect).toBe('manual');
      expect(init?.signal).toBeDefined();
      return Promise.resolve().then(response);
    }
    return originalFetch(input, init);
  }) as typeof fetch;
  try {
    await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

describe('recommended DID credentials', () => {
  it('preserves rotation keys from valid PLC data without a KEM key', async () => {
    const { env, request } = await makeRequest();
    await withPlcResponse(() => Response.json(plcData()), async () => {
      const response = await callEndpoint(env, request);
      expect(response.status).toBe(200);
      const body = await response.json() as {
        rotationKeys: string[];
        verificationMethods: { atproto: string };
        services: { atproto_pds: { endpoint: string } };
      };
      expect(body.rotationKeys).toEqual(['did:key:zRotation']);
      expect(body.verificationMethods.atproto).toMatch(/^did:key:/);
      expect(body.services.atproto_pds.endpoint).toBe('https://pds.example.com');
    });
  });

  it('does not recommend replacement credentials for an account with a KEM key', async () => {
    const { env, request } = await makeRequest();
    const data = plcData();
    const withKem = {
      ...data,
      verificationMethods: { ...data.verificationMethods, atproto_kem: 'did:key:zKem' },
    };
    await withPlcResponse(() => Response.json(withKem), async () => {
      const response = await callEndpoint(env, request);
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({
        error: 'SpacesMigrationUnsupported',
        message: 'This account has a Spaces KEM key. Alteran cannot migrate Spaces data or recommend replacement credentials yet.',
      });
    });
  });

  it('fails closed when PLC data cannot be obtained or validated', async () => {
    const { env, request } = await makeRequest();
    const data = plcData();
    const failures = [
      () => new Response('unavailable', { status: 503 }),
      () => new Response(null, { status: 302, headers: { location: 'https://other.example/data' } }),
      () => { throw new Error('network failure'); },
      () => new Response('{', { headers: { 'Content-Type': 'application/json' } }),
      () => Response.json({ ...data, did: 'did:plc:another' }),
      () => Response.json({ ...data, verificationMethods: undefined }),
      () => Response.json({ ...data, verificationMethods: [] }),
      () => Response.json({ ...data, rotationKeys: [] }),
      () => Response.json({ ...data, rotationKeys: ['did:key:zRotation', null] }),
    ];
    for (const failure of failures) {
      await withPlcResponse(failure, async () => {
        const response = await callEndpoint(env, request);
        expect(response.status).toBe(502);
        expect(await response.json()).toEqual({
          error: 'PlcDataUnavailable',
          message: 'Unable to verify current PLC credentials',
        });
      });
    }
  });

  it('rejects non-PLC DIDs without making a PLC request', async () => {
    for (const did of ['did:web:alice.example.com', 'did:example:alice']) {
      const { env, request } = await makeRequest(did);
      const originalFetch = globalThis.fetch;
      let plcRequests = 0;
      globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input).startsWith('https://plc.directory/')) {
          plcRequests++;
          throw new Error('unexpected PLC request');
        }
        return originalFetch(input, init);
      }) as typeof fetch;
      try {
        const response = await callEndpoint(env, request);
        expect(response.status).toBe(400);
        expect(await response.json()).toEqual({
          error: 'UnsupportedDidMethod',
          message: 'DID credential recommendations require a did:plc account',
        });
        expect(plcRequests).toBe(0);
      } finally {
        globalThis.fetch = originalFetch;
      }
    }
  });
});
