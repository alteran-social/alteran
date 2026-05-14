import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { makeEnv } from './helpers/env';
import { GET as atprotoDid } from '../src/entrypoints/well-known/atproto-did';
import { GET as didJson } from '../src/entrypoints/well-known/did.json.ts';
import { GET as describeRepo } from '../src/pages/xrpc/com.atproto.repo.describeRepo';
import { POST as createSession } from '../src/pages/xrpc/com.atproto.server.createSession';
import { GET as getSession } from '../src/pages/xrpc/com.atproto.server.getSession';
import { POST as updateHandle } from '../src/pages/xrpc/com.atproto.identity.updateHandle';
import { GET as resolveHandle } from '../src/pages/xrpc/com.atproto.identity.resolveHandle';
import { GET as getRecommendedDidCredentials } from '../src/pages/xrpc/com.atproto.identity.getRecommendedDidCredentials';
import { resolvePdsHostname } from '../src/lib/relay';
import { handleResolvesToDid } from '../src/lib/public-host';

const did = 'did:example:test';
const handle = 'alice.example.com';
const pdsHost = 'pds.example.com:8443';
const pdsOrigin = `https://${pdsHost}`;

function apiContext(env: any, request: Request, extra: Record<string, unknown> = {}) {
  return {
    locals: { env },
    request,
    ...extra,
  } as any;
}

function didDocServiceEndpoint(doc: any): string | undefined {
  return doc.service?.find((service: any) => service.type === 'AtprotoPersonalDataServer')
    ?.serviceEndpoint;
}

async function canonicalEnv(overrides: Record<string, unknown> = {}) {
  return makeEnv({
    PDS_DID: did,
    PDS_HANDLE: handle,
    PDS_HOSTNAME: pdsHost,
    REPO_SIGNING_KEY: '8b5e3d226b44c4c88fbd3d4529f6283fb2b20f6deee8a0b34e7f0a9b12d3e4f1',
    ...overrides,
  });
}

describe('canonical public host identity surfaces', () => {
  it('serves atproto-did only from the configured handle host', async () => {
    const env = await canonicalEnv();

    const canonical = await atprotoDid(apiContext(
      env,
      new Request(`https://${handle}/.well-known/atproto-did`),
    ));
    expect(canonical.status).toBe(200);
    expect(canonical.headers.get('Content-Type')).toBe('text/plain');
    expect(await canonical.text()).toBe(did);

    const alternate = await atprotoDid(apiContext(
      env,
      new Request('https://worker-preview.example/.well-known/atproto-did'),
    ));
    expect(alternate.status).toBe(404);
    expect(await alternate.text()).toBe('NotFound');
  });

  it('normalizes the configured handle before host checks and DID claims', async () => {
    const env = await canonicalEnv({ PDS_HANDLE: 'Alice.Example.Com' });

    const canonical = await atprotoDid(apiContext(
      env,
      new Request('https://alice.example.com/.well-known/atproto-did'),
    ));
    expect(canonical.status).toBe(200);

    const response = await didJson(apiContext(
      env,
      new Request('https://worker-preview.example/.well-known/did.json'),
    ));
    const body = await response.json() as any;
    expect(body.alsoKnownAs).toEqual(['at://alice.example.com']);
  });

  it('uses spec-compatible handle resolution rules for canonical identity', async () => {
    for (const specHandle of ['name.t--t', 'example.t', 'xn--notarealidn.com']) {
      const env = await canonicalEnv({ PDS_HANDLE: specHandle });

      const canonical = await atprotoDid(apiContext(
        env,
        new Request(`https://${specHandle}/.well-known/atproto-did`),
      ));
      expect(canonical.status).toBe(200);

      const didResponse = await didJson(apiContext(
        env,
        new Request('https://worker-preview.example/.well-known/did.json'),
      ));
      const didBody = await didResponse.json() as any;
      expect(didBody.alsoKnownAs).toEqual([`at://${specHandle}`]);

      const repoResponse = await describeRepo(apiContext(
        env,
        new Request(`https://worker-preview.example/xrpc/com.atproto.repo.describeRepo?repo=${did}`),
        { url: new URL(`https://worker-preview.example/xrpc/com.atproto.repo.describeRepo?repo=${did}`) },
      ));
      const repoBody = await repoResponse.json() as any;
      expect(repoBody.handleIsCorrect).toBe(true);
    }
  });

  it('does not resolve reserved or invalid TLD handles as correct', async () => {
    for (const invalidHandle of ['alice.example', 'john.0', 'cn.8']) {
      const env = await canonicalEnv({ PDS_HANDLE: invalidHandle });

      if (invalidHandle === 'alice.example') {
        const canonical = await atprotoDid(apiContext(
          env,
          new Request(`https://${invalidHandle}/.well-known/atproto-did`),
        ));
        expect(canonical.status).toBe(404);
      }

      const repoResponse = await describeRepo(apiContext(
        env,
        new Request(`https://worker-preview.example/xrpc/com.atproto.repo.describeRepo?repo=${did}`),
        { url: new URL(`https://worker-preview.example/xrpc/com.atproto.repo.describeRepo?repo=${did}`) },
      ));
      const repoBody = await repoResponse.json() as any;
      expect(repoBody.didDoc.alsoKnownAs).toEqual([]);
      expect(repoBody.handleIsCorrect).toBe(false);
    }
  });

  it('resolves only normalized spec-valid local handles through resolveHandle', async () => {
    const env = await canonicalEnv({ PDS_HANDLE: 'Alice.Example.Com' });

    const response = await resolveHandle(apiContext(
      env,
      new Request('https://worker-preview.example/xrpc/com.atproto.identity.resolveHandle?handle=ALICE.EXAMPLE.COM'),
      { url: new URL('https://worker-preview.example/xrpc/com.atproto.identity.resolveHandle?handle=ALICE.EXAMPLE.COM') },
    ));
    expect(response.status).toBe(200);
    expect(await response.json() as any).toEqual({ did });
  });

  it('rejects reserved and invalid resolveHandle requests before proxying', async () => {
    for (const requestedHandle of ['alice.example', 'john.0']) {
      const env = await canonicalEnv({ PDS_HANDLE: requestedHandle });
      const response = await resolveHandle(apiContext(
        env,
        new Request(`https://worker-preview.example/xrpc/com.atproto.identity.resolveHandle?handle=${requestedHandle}`),
        { url: new URL(`https://worker-preview.example/xrpc/com.atproto.identity.resolveHandle?handle=${requestedHandle}`) },
      ));
      expect(response.status).toBe(400);
      expect(await response.json() as any).toEqual({
        error: 'InvalidRequest',
        message: 'Unable to resolve handle',
      });
    }
  });

  it('uses the configured PDS origin in did.json and preserves ports', async () => {
    const env = await canonicalEnv();
    const response = await didJson(apiContext(
      env,
      new Request('https://worker-preview.example/.well-known/did.json'),
    ));

    expect(response.status).toBe(200);
    const body = await response.json() as any;
    expect(body.id).toBe(did);
    expect(body.alsoKnownAs).toEqual([`at://${handle}`]);
    expect(didDocServiceEndpoint(body)).toBe(pdsOrigin);
  });

  it('uses the configured PDS origin in createSession and getSession didDocs', async () => {
    const env = await canonicalEnv();

    const created = await createSession(apiContext(
      env,
      new Request('https://worker-preview.example/xrpc/com.atproto.server.createSession', {
        method: 'POST',
        body: JSON.stringify({ identifier: handle, password: 'pwd' }),
      }),
    ));
    expect(created.status).toBe(200);
    const session = await created.json() as any;
    expect(didDocServiceEndpoint(session.didDoc)).toBe(pdsOrigin);

    const fetched = await getSession(apiContext(
      env,
      new Request('https://worker-preview.example/xrpc/com.atproto.server.getSession', {
        headers: { authorization: `Bearer ${session.accessJwt}` },
      }),
    ));
    expect(fetched.status).toBe(200);
    const fetchedBody = await fetched.json() as any;
    expect(didDocServiceEndpoint(fetchedBody.didDoc)).toBe(pdsOrigin);
  });

  it('describes only the local repo with computed handle correctness', async () => {
    const env = await canonicalEnv();

    const response = await describeRepo(apiContext(
      env,
      new Request(`https://worker-preview.example/xrpc/com.atproto.repo.describeRepo?repo=${handle}`),
      { url: new URL(`https://worker-preview.example/xrpc/com.atproto.repo.describeRepo?repo=${handle}`) },
    ));
    expect(response.status).toBe(200);
    const body = await response.json() as any;
    expect(body.did).toBe(did);
    expect(body.handle).toBe(handle);
    expect(body.handleIsCorrect).toBe(true);
    expect(didDocServiceEndpoint(body.didDoc)).toBe(pdsOrigin);

    const nonLocal = await describeRepo(apiContext(
      env,
      new Request('https://worker-preview.example/xrpc/com.atproto.repo.describeRepo?repo=did:example:other'),
      { url: new URL('https://worker-preview.example/xrpc/com.atproto.repo.describeRepo?repo=did:example:other') },
    ));
    expect(nonLocal.status).toBe(404);
    const nonLocalBody = await nonLocal.json() as any;
    expect(nonLocalBody).toEqual({ error: 'NotFound', message: 'Repo not found' });
  });

  it('reports handleIsCorrect false for local repos with invalid configured handles', async () => {
    const env = await canonicalEnv({ PDS_HANDLE: 'alice.example.com:8443' });

    const response = await describeRepo(apiContext(
      env,
      new Request(`https://worker-preview.example/xrpc/com.atproto.repo.describeRepo?repo=${did}`),
      { url: new URL(`https://worker-preview.example/xrpc/com.atproto.repo.describeRepo?repo=${did}`) },
    ));
    expect(response.status).toBe(200);
    const body = await response.json() as any;
    expect(body.handle).toBe('alice.example.com:8443');
    expect(body.didDoc.alsoKnownAs).toEqual([]);
    expect(body.handleIsCorrect).toBe(false);
  });

  it('rejects handle and DID mismatches during bidirectional validation', async () => {
    const env = await canonicalEnv();

    await expect(handleResolvesToDid(env, 'bob.example', did)).resolves.toBe(false);
    await expect(handleResolvesToDid(env, handle, 'did:example:other')).resolves.toBe(false);
  });

  it('does not reflect request hosts when resolving relay notification hostname', async () => {
    const env = await canonicalEnv();
    await expect(resolvePdsHostname(env, 'https://worker-preview.example')).resolves.toBe('pds.example.com');

    const fallbackEnv = await makeEnv({ PDS_HOSTNAME: undefined, PDS_HANDLE: 'user.example' });
    await expect(resolvePdsHostname(fallbackEnv, 'https://worker-preview.example')).resolves.toBe('user.example');

    const localEnv = await makeEnv({ PDS_HOSTNAME: 'localhost:4321', PDS_HANDLE: 'user.example' });
    await expect(resolvePdsHostname(localEnv, 'https://worker-preview.example')).resolves.toBeNull();

    const ipv6LocalEnv = await makeEnv({ PDS_HOSTNAME: 'https://[::1]:4321', PDS_HANDLE: 'user.example' });
    await expect(resolvePdsHostname(ipv6LocalEnv, 'https://worker-preview.example')).resolves.toBeNull();
  });

  it('uses the canonical PDS origin in recommended DID credentials', async () => {
    const env = await canonicalEnv();

    const created = await createSession(apiContext(
      env,
      new Request('https://worker-preview.example/xrpc/com.atproto.server.createSession', {
        method: 'POST',
        body: JSON.stringify({ identifier: handle, password: 'pwd' }),
      }),
    ));
    const session = await created.json() as any;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      expect(String(input)).toBe(`https://plc.directory/${did}/data`);
      return new Response(JSON.stringify({ rotationKeys: ['did:key:zRotation'] }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    try {
      const response = await getRecommendedDidCredentials(apiContext(
        env,
        new Request('https://worker-preview.example/xrpc/com.atproto.identity.getRecommendedDidCredentials', {
          headers: { authorization: `Bearer ${session.accessJwt}` },
        }),
      ));
      expect(response.status).toBe(200);
      const body = await response.json() as any;
      expect(body.alsoKnownAs).toEqual([`at://${handle}`]);
      expect(body.services.atproto_pds.endpoint).toBe(pdsOrigin);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('documents updateHandle as stable unsupported behavior before body parsing', async () => {
    const env = await canonicalEnv();
    const expected = {
      error: 'NotImplemented',
      message: 'Handle updates require PDS reconfiguration for single-user mode',
    };

    for (const request of [
      new Request('https://pds.example/xrpc/com.atproto.identity.updateHandle', { method: 'POST' }),
      new Request('https://pds.example/xrpc/com.atproto.identity.updateHandle', {
        method: 'POST',
        body: '{not-json',
      }),
      new Request('https://pds.example/xrpc/com.atproto.identity.updateHandle', {
        method: 'POST',
        body: JSON.stringify({ handle: 'new.example' }),
      }),
    ]) {
      const response = await updateHandle(apiContext(env, request));
      expect(response.status).toBe(501);
      const body = await response.json() as any;
      expect(body).toEqual(expected);
    }
  });
});
