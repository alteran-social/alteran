import { describe, expect, it } from 'bun:test';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { makeEnv } from './helpers/env';
import {
  isAllowedRedirectUri,
  isSafeFetchUrl,
  redirectUriMatches,
  safeFetchJson,
  validateClientMetadataShape,
  validateParRequest,
  verifyClientAuthentication,
} from '../src/lib/oauth/clients';

describe('OAuth client metadata validation', () => {
  const clientId = 'https://client.example/metadata';
  const metadata = {
    client_id: clientId,
    redirect_uris: ['https://client.example/callback', 'http://127.0.0.1/callback'],
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    scope: 'atproto transition:generic',
    dpop_bound_access_tokens: true,
  };

  it('rejects unsafe metadata and JWKS fetch URLs', () => {
    expect(isSafeFetchUrl('https://client.example/metadata')).toBe(true);
    expect(isSafeFetchUrl('http://client.example/metadata')).toBe(false);
    expect(isSafeFetchUrl('https://localhost/metadata')).toBe(false);
    expect(isSafeFetchUrl('https://127.0.0.1/metadata')).toBe(false);
    expect(isSafeFetchUrl('https://[::ffff:169.254.169.254]/metadata')).toBe(false);
    expect(isSafeFetchUrl('https://client.example:444/metadata')).toBe(false);
    expect(isSafeFetchUrl('https://user:pass@client.example/metadata')).toBe(false);
  });

  it('rejects hostnames that resolve to private addresses and oversized JSON responses', async () => {
    const env = await makeEnv();
    const original = globalThis.fetch;
    try {
      globalThis.fetch = (async (url: RequestInfo | URL) => {
        const href = url instanceof Request ? url.url : String(url);
        if (href.startsWith('https://cloudflare-dns.com/dns-query')) {
          return new Response(JSON.stringify({ Answer: [{ type: 1, data: '10.0.0.7' }] }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        throw new Error('client URL should not be fetched after private DNS resolution');
      }) as typeof fetch;
      await expect(safeFetchJson(env, 'https://client.example/metadata', 'client metadata')).rejects.toThrow('blocked address');

      globalThis.fetch = (async (url: RequestInfo | URL) => {
        const href = url instanceof Request ? url.url : String(url);
        if (href.startsWith('https://cloudflare-dns.com/dns-query')) {
          return new Response(JSON.stringify({ Answer: [{ type: 28, data: '::ffff:169.254.169.254' }] }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        throw new Error('client URL should not be fetched after IPv4-mapped private DNS resolution');
      }) as typeof fetch;
      await expect(safeFetchJson(env, 'https://client.example/metadata', 'client metadata')).rejects.toThrow('blocked address');

      globalThis.fetch = (async (url: RequestInfo | URL) => {
        const href = url instanceof Request ? url.url : String(url);
        if (href.startsWith('https://cloudflare-dns.com/dns-query')) {
          return new Response(JSON.stringify({ Answer: [{ type: 1, data: '93.184.216.34' }] }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return new Response(JSON.stringify({ data: 'x'.repeat(130 * 1024) }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;
      await expect(safeFetchJson(env, 'https://client.example/metadata', 'client metadata')).rejects.toThrow('too large');
    } finally {
      globalThis.fetch = original;
    }
  });

  it('requires client metadata and JWKS hosts to be explicitly trusted', async () => {
    const env = await makeEnv({ PDS_OAUTH_CLIENT_HOSTS: 'trusted.example' } as any);
    await expect(safeFetchJson(env, 'https://client.example/metadata', 'client metadata')).rejects.toThrow('not allowlisted');
  });

  it('supports loopback redirect ports while rejecting private-use schemes', () => {
    expect(isAllowedRedirectUri('https://client.example/callback')).toBe(true);
    expect(isAllowedRedirectUri('http://127.0.0.1:43210/callback')).toBe(true);
    expect(isAllowedRedirectUri('com.example.app:/callback')).toBe(false);
    expect(redirectUriMatches('http://127.0.0.1/callback', 'http://127.0.0.1:43210/callback')).toBe(true);
  });

  it('rejects unsupported auth methods and malformed PAR requests', () => {
    expect(() => validateClientMetadataShape({ ...metadata, token_endpoint_auth_method: 'client_secret_basic' }, clientId)).toThrow();
    expect(() => validateClientMetadataShape({ ...metadata, token_endpoint_auth_method: 'private_key_jwt', jwks_uri: 'https://127.0.0.1/jwks' }, clientId)).toThrow();
    expect(() => validateClientMetadataShape({ ...metadata, token_endpoint_auth_method: 'private_key_jwt' }, clientId)).toThrow();
    const valid = validateClientMetadataShape(metadata, clientId);
    expect(() => validateParRequest(valid, {
      response_type: 'code',
      grant_type: 'authorization_code',
      redirect_uri: 'https://client.example/callback',
      scope: 'atproto',
      code_challenge: 'challenge',
      code_challenge_method: 'S256',
    })).not.toThrow();
    expect(() => validateParRequest(valid, {
      response_type: 'token',
      redirect_uri: 'https://client.example/callback',
      scope: 'atproto',
      code_challenge: 'challenge',
      code_challenge_method: 'S256',
    })).toThrow();
    expect(() => validateParRequest(valid, {
      response_type: 'code',
      grant_type: 'client_credentials',
      redirect_uri: 'https://client.example/callback',
      scope: 'atproto',
      code_challenge: 'challenge',
      code_challenge_method: 'S256',
    })).toThrow();
    expect(() => validateParRequest(valid, {
      response_type: 'code',
      redirect_uri: 'https://evil.example/callback',
      scope: 'atproto',
      code_challenge: 'challenge',
      code_challenge_method: 'S256',
    })).toThrow();
  });

  it('verifies private_key_jwt clients and rejects assertion replay', async () => {
    const env = await makeEnv();
    const { publicKey, privateKey } = await generateKeyPair('ES256');
    const publicJwk = await exportJWK(publicKey);
    const meta = validateClientMetadataShape({
      ...metadata,
      token_endpoint_auth_method: 'private_key_jwt',
      jwks: { keys: [{ ...publicJwk, kid: 'test-key' }] },
    }, clientId);
    const assertion = await new SignJWT({
      iss: clientId,
      sub: clientId,
      aud: 'https://pds.example',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60,
      jti: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: 'ES256', kid: 'test-key' })
      .sign(privateKey);
    const form = new URLSearchParams({
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion,
    });
    const result = await verifyClientAuthentication(env, clientId, 'https://pds.example', meta, form);
    expect(result).toEqual({ method: 'private_key_jwt', keyId: 'test-key' });
    await expect(verifyClientAuthentication(env, clientId, 'https://pds.example', meta, form)).rejects.toThrow('invalid client assertion');

    const replayJti = crypto.randomUUID();
    const concurrentAssertion = await new SignJWT({
      iss: clientId,
      sub: clientId,
      aud: 'https://pds.example',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60,
      jti: replayJti,
    })
      .setProtectedHeader({ alg: 'ES256', kid: 'test-key' })
      .sign(privateKey);
    const concurrentForm = new URLSearchParams({
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: concurrentAssertion,
    });
    const attempts = await Promise.allSettled(
      Array.from({ length: 20 }, () => verifyClientAuthentication(env, clientId, 'https://pds.example', meta, concurrentForm)),
    );
    expect(attempts.filter((attempt) => attempt.status === 'fulfilled')).toHaveLength(1);
    expect(attempts.filter((attempt) => attempt.status === 'rejected')).toHaveLength(19);
  });
});
