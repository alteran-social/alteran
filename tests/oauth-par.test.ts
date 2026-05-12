import { describe, expect, it } from 'bun:test';
import { makeEnv } from './helpers/env';
import { makeDpopKey, mockClientMetadata, signAuthzDpop, signDpopProof } from './helpers/oauth';
import { getSecret } from '../src/db/account';
import { getAuthzNonce } from '../src/lib/oauth/dpop';
import { POST as parPost } from '../src/pages/oauth/par';
import { loadPar } from '../src/lib/oauth/store';

const clientId = 'https://client.example/metadata';

describe('OAuth PAR endpoint', () => {
  it('stores a DPoP-bound PAR and returns expires_in', async () => {
    const restore = mockClientMetadata(clientId);
    try {
      const env = await makeEnv();
      const key = await makeDpopKey();
      const url = 'https://pds.example/oauth/par';
      const proof = await signAuthzDpop(env, key, 'POST', url);
      const res = await parPost({ locals: { runtime: { env } }, request: new Request(url, {
        method: 'POST',
        headers: { dpop: proof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: clientId,
          response_type: 'code',
          redirect_uri: 'https://client.example/callback',
          scope: 'atproto',
          state: 'state123',
          code_challenge: 'challenge',
          code_challenge_method: 'S256',
        }).toString(),
      }) } as any);
      expect(res.status).toBe(201);
      const body = await res.json() as any;
      expect(body.expires_in).toBe(300);
      const id = String(body.request_uri).replace('urn:ietf:params:oauth:request_uri:', '');
      const stored = await loadPar(env, id);
      expect(stored?.dpopJkt).toBe(key.jkt);
      expect(stored?.clientAuthMethod).toBe('none');
    } finally {
      restore();
    }
  });

  it('accepts a first PAR DPoP proof without a nonce challenge', async () => {
    const restore = mockClientMetadata(clientId);
    try {
      const env = await makeEnv();
      const key = await makeDpopKey();
      const url = 'https://pds.example/oauth/par';
      const proof = await signDpopProof({ key, method: 'POST', url });
      const res = await parPost({ locals: { runtime: { env } }, request: new Request(url, {
        method: 'POST',
        headers: { dpop: proof, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: clientId,
          response_type: 'code',
          redirect_uri: 'https://client.example/callback',
          scope: 'atproto',
          state: 'state123',
          code_challenge: 'challenge',
          code_challenge_method: 'S256',
        }).toString(),
      }) } as any);
      expect(res.status).toBe(201);
      expect(res.headers.get('DPoP-Nonce')).toBeTruthy();
      const body = await res.json() as any;
      const id = String(body.request_uri).replace('urn:ietf:params:oauth:request_uri:', '');
      const stored = await loadPar(env, id);
      expect(stored?.dpopJkt).toBe(key.jkt);
    } finally {
      restore();
    }
  });

  it('rejects unsafe client metadata URLs before fetching', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const url = 'https://pds.example/oauth/par';
    const proof = await signAuthzDpop(env, key, 'POST', url);
    const res = await parPost({ locals: { runtime: { env } }, request: new Request(url, {
      method: 'POST',
      headers: { dpop: proof, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: 'https://127.0.0.1/metadata',
        response_type: 'code',
        redirect_uri: 'https://client.example/callback',
        scope: 'atproto',
        state: 'state123',
        code_challenge: 'challenge',
        code_challenge_method: 'S256',
      }).toString(),
    }) } as any);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe('invalid_client');
  });

  it('does not persist DPoP replay entries for invalid clients', async () => {
    const env = await makeEnv();
    const key = await makeDpopKey();
    const url = 'https://pds.example/oauth/par';
    const jti = 'invalid-client-jti';
    const proof = await signDpopProof({
      key,
      method: 'POST',
      url,
      nonce: await getAuthzNonce(env),
      jti,
    });
    const res = await parPost({ locals: { runtime: { env } }, request: new Request(url, {
      method: 'POST',
      headers: { dpop: proof, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: 'https://127.0.0.1/metadata',
        response_type: 'code',
        redirect_uri: 'https://client.example/callback',
        scope: 'atproto',
        state: 'state123',
        code_challenge: 'challenge',
        code_challenge_method: 'S256',
      }).toString(),
    }) } as any);

    expect(res.status).toBe(400);
    expect(await getSecret(env, `oauth:dpop:jti:authz:${jti}`)).toBeNull();
  });
});
