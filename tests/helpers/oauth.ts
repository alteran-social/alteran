import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import type { Env } from '../../src/env';
import { getAuthzNonce, jwkThumbprint, sha256b64url } from '../../src/lib/oauth/dpop';
import { dpopResourceUnauthorized } from '../../src/lib/oauth/resource';

export async function makeDpopKey() {
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const jwk = await exportJWK(publicKey);
  const jkt = await jwkThumbprint(jwk as JsonWebKey);
  return { publicKey, privateKey, jwk: jwk as JsonWebKey, jkt };
}

export async function signDpopProof(input: {
  key: Awaited<ReturnType<typeof makeDpopKey>>;
  method: string;
  url: string;
  nonce: string;
  accessToken?: string;
  jti?: string;
}) {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    htm: input.method.toUpperCase(),
    htu: input.url,
    iat: now,
    jti: input.jti ?? crypto.randomUUID(),
    nonce: input.nonce,
  };
  if (input.accessToken) payload.ath = await sha256b64url(input.accessToken);
  return new SignJWT(payload)
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: input.key.jwk as any })
    .sign(input.key.privateKey);
}

export async function signAuthzDpop(env: Env, key: Awaited<ReturnType<typeof makeDpopKey>>, method: string, url: string) {
  return signDpopProof({ key, method, url, nonce: await getAuthzNonce(env) });
}

export async function signResourceDpop(env: Env, key: Awaited<ReturnType<typeof makeDpopKey>>, method: string, url: string, accessToken: string) {
  const nonceResponse = await dpopResourceUnauthorized(env);
  const nonce = nonceResponse.headers.get('DPoP-Nonce') ?? '';
  return signDpopProof({ key, method, url, nonce, accessToken });
}

export function mockClientMetadata(clientId = 'https://client.example/metadata') {
  const metadata = {
    client_id: clientId,
    client_name: 'Test Client',
    redirect_uris: ['https://client.example/callback', 'http://127.0.0.1/callback'],
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    scope: 'atproto transition:generic',
    dpop_bound_access_tokens: true,
  };
  const original = globalThis.fetch;
  globalThis.fetch = (async (url: RequestInfo | URL) => {
    const href = url instanceof Request ? url.url : String(url);
    if (href.startsWith('https://cloudflare-dns.com/dns-query')) {
      return new Response(JSON.stringify({ Answer: [{ type: 1, data: '93.184.216.34' }] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    if (href !== clientId) {
      return new Response(JSON.stringify({ keys: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response(JSON.stringify(metadata), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}
