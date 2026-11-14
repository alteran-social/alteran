import type { Env } from '../../env';
import { jwkThumbprint } from './dpop';
import { DpopNonceError } from './dpop-errors';
import { consumeOAuthReplay } from '../../db/oauth-replay';
import { decodeProtectedHeader, importJWK, compactVerify, type JWK as JoseJWK } from 'jose';
import { resolveLoopbackClient } from './loopback-client';
import { isAllowedRedirectUri, redirectUriMatches } from './redirect-uri';
import { isSafeFetchUrl, safeFetchJson } from './safe-fetch';

const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export type ClientAuthMethod = 'none' | 'private_key_jwt';
export type OAuthApplicationType = 'web' | 'native';

export type OAuthClientMetadata = {
  client_id: string;
  client_name?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: ClientAuthMethod;
  grant_types: string[];
  response_types: string[];
  scope: string;
  dpop_bound_access_tokens: true;
  jwks?: { keys: JsonWebKey[] };
  jwks_uri?: string;
  application_type: OAuthApplicationType;
};

export type VerifiedClientAuth = {
  method: ClientAuthMethod;
  keyId: string | null;
  keyBinding?: 'jwk-thumbprint-v1';
  replay?: { key: string; issuedAt: number; expiresAt: number };
};

export async function resolveClientMetadata(env: Env, clientId: string): Promise<OAuthClientMetadata> {
  const loopback = resolveLoopbackClient(clientId);
  switch (loopback.tag) {
    case 'loopback':
      return loopback.metadata;
    case 'invalid':
      throw new Error(loopback.message);
    case 'not-loopback': {
      const metadata = await safeFetchJson(env, clientId, 'client metadata');
      return validateClientMetadataShape(metadata, clientId);
    }
  }
}

export function validateClientMetadataShape(metadata: any, clientId: string): OAuthClientMetadata {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    throw new Error('client metadata must be an object');
  }
  if (metadata.client_id !== clientId) {
    throw new Error('client_id mismatch');
  }
  if (!Array.isArray(metadata.redirect_uris) || metadata.redirect_uris.length === 0) {
    throw new Error('redirect_uris required');
  }
  const redirect_uris = metadata.redirect_uris;
  const application_type = metadata.application_type ?? 'web';
  if (application_type !== 'web' && application_type !== 'native') {
    throw new Error('unsupported application_type');
  }
  if (!redirect_uris.every((uri: unknown) => (
    typeof uri === 'string' &&
    isAllowedRedirectUri(uri, { applicationType: application_type, clientId })
  ))) {
    throw new Error('redirect_uris contains unsupported URI');
  }
  if (metadata.dpop_bound_access_tokens !== true) {
    throw new Error('client must require DPoP');
  }

  const method = metadata.token_endpoint_auth_method ?? 'none';
  if (method !== 'none' && method !== 'private_key_jwt') {
    throw new Error('unsupported token_endpoint_auth_method');
  }

  if (!Array.isArray(metadata.response_types) || !metadata.response_types.includes('code')) {
    throw new Error('response_types must include code');
  }
  if (!Array.isArray(metadata.grant_types) || !metadata.grant_types.includes('authorization_code')) {
    throw new Error('grant_types must include authorization_code');
  }
  if (!metadata.grant_types.includes('refresh_token')) {
    throw new Error('grant_types must include refresh_token');
  }
  if (typeof metadata.scope !== 'string' || !metadata.scope.split(' ').includes('atproto')) {
    throw new Error('metadata scope must include atproto');
  }
  if (metadata.scope.split(' ').includes('openid')) {
    throw new Error('openid scope is not supported');
  }
  if (metadata.jwks && metadata.jwks_uri) {
    throw new Error('client metadata must not include both jwks and jwks_uri');
  }
  if (method === 'private_key_jwt' && !metadata.jwks && typeof metadata.jwks_uri !== 'string') {
    throw new Error('private_key_jwt clients must provide jwks or jwks_uri');
  }
  if (metadata.jwks_uri && !isSafeFetchUrl(metadata.jwks_uri)) {
    throw new Error('jwks_uri is not safe to fetch');
  }

  return {
    client_id: metadata.client_id,
    client_name: typeof metadata.client_name === 'string' ? metadata.client_name : undefined,
    redirect_uris,
    token_endpoint_auth_method: method,
    grant_types: metadata.grant_types,
    response_types: metadata.response_types,
    scope: metadata.scope,
    dpop_bound_access_tokens: true,
    jwks: metadata.jwks,
    jwks_uri: metadata.jwks_uri,
    application_type,
  };
}

export function validateParRequest(metadata: OAuthClientMetadata, request: {
  response_type: string;
  grant_type?: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
}): void {
  if (request.grant_type && request.grant_type !== 'authorization_code') {
    throw new Error('unsupported grant_type');
  }
  if (request.response_type !== 'code') {
    throw new Error('unsupported response_type');
  }
  if (!request.redirect_uri || !isAllowedRedirectUri(request.redirect_uri, {
    applicationType: metadata.application_type,
    clientId: metadata.client_id,
  })) {
    throw new Error('unsupported redirect_uri');
  }
  if (!metadata.redirect_uris.some((uri) => redirectUriMatches(uri, request.redirect_uri))) {
    throw new Error('redirect_uri not registered');
  }
  if (!request.code_challenge || request.code_challenge_method !== 'S256') {
    throw new Error('PKCE S256 required');
  }
}

export async function resolveClientJwks(env: Env, metadata: OAuthClientMetadata): Promise<{ keys: JsonWebKey[] }> {
  let jwks = metadata.jwks;
  if (!jwks && metadata.jwks_uri) {
    jwks = await safeFetchJson(env, metadata.jwks_uri, 'client jwks');
  }
  if (!jwks || typeof jwks !== 'object' || !Array.isArray((jwks as any).keys)) {
    throw new Error('invalid JWKS');
  }
  const keys = (jwks as any).keys;
  if (!keys.every((key: unknown) => key && typeof key === 'object')) {
    throw new Error('invalid JWKS key');
  }
  return { keys };
}

export async function verifyClientAuthentication(
  env: Env,
  client_id: string,
  issuerOrigin: string,
  metadata: OAuthClientMetadata,
  form: URLSearchParams,
  opts: { deferReplay?: boolean } = {},
): Promise<VerifiedClientAuth> {
  if (metadata.token_endpoint_auth_method === 'none') {
    return verifyPublicClientAuthentication(form);
  }

  const client_assertion_type = form.get('client_assertion_type') || '';
  const client_assertion = form.get('client_assertion') || '';
  if (client_assertion_type !== CLIENT_ASSERTION_TYPE || !client_assertion) {
    throw new Error('missing client assertion');
  }
  const jwks = await resolveClientJwks(env, metadata);
  if (opts.deferReplay) {
    const result = await verifySignedClientAssertion(client_id, issuerOrigin, client_assertion, jwks);
    if (!result) throw new Error('invalid client assertion');
    return { method: 'private_key_jwt', keyId: result.keyId, keyBinding: 'jwk-thumbprint-v1', replay: result.replay };
  }
  const result = await verifyClientAssertion(env, client_id, issuerOrigin, client_assertion, jwks);
  if (!result) throw new Error('invalid client assertion');
  return { method: 'private_key_jwt', keyId: result.keyId, keyBinding: 'jwk-thumbprint-v1' };
}

export function verifyPublicClientAuthentication(form: URLSearchParams): VerifiedClientAuth {
  if (form.get('client_assertion') || form.get('client_assertion_type')) {
    throw new Error('public client must not send client_assertion');
  }
  return { method: 'none', keyId: null };
}

export async function requireStoredClientAuthentication(
  env: Env,
  clientId: string,
  issuerOrigin: string,
  form: URLSearchParams,
  expected: { method: string | null; keyId?: string | null; keyBinding?: string | null },
  opts: { deferReplay?: boolean } = {},
): Promise<VerifiedClientAuth> {
  if (expected.method === 'none') {
    return verifyPublicClientAuthentication(form);
  }
  if (expected.method !== 'private_key_jwt' || expected.keyBinding !== 'jwk-thumbprint-v1' || !expected.keyId) {
    throw new Error('client authentication requires renewed authorization');
  }
  const metadata = await resolveClientMetadata(env, clientId);
  return requireSameClientAuth(env, clientId, issuerOrigin, metadata, form, expected, opts);
}

function clientAssertionTimesValid(iat: unknown, exp: unknown, now: number): boolean {
  return typeof iat === 'number' && Number.isFinite(iat) &&
    now - iat <= 300 && iat - now <= 30 &&
    typeof exp === 'number' && Number.isFinite(exp) && exp > now && exp - now <= 300;
}

export async function verifyClientAssertion(
  env: Env,
  client_id: string,
  issuerOrigin: string,
  assertionJwt: string,
  jwks: { keys: JsonWebKey[] },
): Promise<{ keyId: string } | null> {
  const result = await verifySignedClientAssertion(client_id, issuerOrigin, assertionJwt, jwks);
  if (!result) return null;
  try {
    const replay = await consumeOAuthReplay(env, result.replay.key, {
      tag: 'assertion', issuedAt: result.replay.issuedAt, expiresAt: result.replay.expiresAt,
    });
    if (replay.tag !== 'accepted') return null;
    if (!clientAssertionTimesValid(result.replay.issuedAt, result.replay.expiresAt, Math.floor(Date.now() / 1000))) return null;
    return { keyId: result.keyId };
  } catch (error) {
    if (error instanceof DpopNonceError) throw error;
    return null;
  }
}

async function verifySignedClientAssertion(
  client_id: string,
  issuerOrigin: string,
  assertionJwt: string,
  jwks: { keys: JsonWebKey[] },
): Promise<{ keyId: string; replay: { key: string; issuedAt: number; expiresAt: number } } | null> {
  try {
    const [h, p] = assertionJwt.split('.');
    if (!h || !p) return null;
    const header = decodeProtectedHeader(assertionJwt) as any;
    if (header.alg !== 'ES256') return null;
    if ('kid' in header && (typeof header.kid !== 'string' || !header.kid)) return null;
    const keys: any[] = Array.isArray(jwks?.keys) ? jwks.keys : [];
    if (!keys.length) return null;
    const candidates = typeof header.kid === 'string' ? keys.filter((k) => k.kid === header.kid) : keys;
    if (!candidates.length) return null;

    let payload: any | null = null;
    let matchedKey: JsonWebKey | null = null;
    for (const jwk of candidates) {
      try {
        const key = await importJWK(jwk as JoseJWK, 'ES256');
        const verified = await compactVerify(assertionJwt, key);
        payload = JSON.parse(new TextDecoder().decode(verified.payload));
        matchedKey = jwk as JsonWebKey;
        break;
      } catch {
        // Try the next JWK candidate; only the final no-payload check matters.
      }
    }
    if (!payload || !matchedKey) return null;

    const now = Math.floor(Date.now() / 1000);
    if (payload.iss !== client_id) return null;
    if (payload.sub !== client_id) return null;
    if (payload.aud !== issuerOrigin) return null;
    if (!clientAssertionTimesValid(payload.iat, payload.exp, now)) return null;
    if (typeof payload.jti !== 'string' || payload.jti.length < 8) return null;
    const keyId = await jwkThumbprint(matchedKey);
    const key = `oauth:client-assertion:jti:${client_id}:${payload.jti}`;
    if (key.length > 8192 || new TextEncoder().encode(key).byteLength > 8192) return null;
    return { keyId, replay: { key, issuedAt: payload.iat, expiresAt: payload.exp } };
  } catch (error) {
    if (error instanceof DpopNonceError) throw error;
    return null;
  }
}

export async function requireSameClientAuth(
  env: Env,
  clientId: string,
  issuerOrigin: string,
  metadata: OAuthClientMetadata,
  form: URLSearchParams,
  expected: { method: string | null; keyId?: string | null; keyBinding?: string | null },
  opts: { deferReplay?: boolean } = {},
): Promise<VerifiedClientAuth> {
  const actual = await verifyClientAuthentication(env, clientId, issuerOrigin, metadata, form, opts);
  if (actual.method !== expected.method) {
    throw new Error('client authentication method changed');
  }
  if (actual.method === 'private_key_jwt' &&
      (expected.keyBinding !== 'jwk-thumbprint-v1' || !expected.keyId || actual.keyId !== expected.keyId)) {
    throw new Error('client authentication key changed');
  }
  return actual;
}
