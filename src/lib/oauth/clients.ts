import type { Env } from '../../env';
import { jwkThumbprint } from './dpop';
import { DpopNonceError } from './dpop-errors';
import { cleanupExpiredOAuthReplaySecrets, createSecretOnce } from '../../db/account';
import { decodeProtectedHeader, importJWK, compactVerify, type JWK as JoseJWK } from 'jose';

const MAX_CLIENT_JSON_BYTES = 128 * 1024;
const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export type ClientAuthMethod = 'none' | 'private_key_jwt';

export type OAuthClientMetadata = {
  client_id: string;
  redirect_uris: string[];
  token_endpoint_auth_method: ClientAuthMethod;
  grant_types: string[];
  response_types: string[];
  scope: string;
  dpop_bound_access_tokens: true;
  jwks?: { keys: JsonWebKey[] };
  jwks_uri?: string;
  application_type?: string;
};

export type VerifiedClientAuth = {
  method: ClientAuthMethod;
  keyId: string | null;
};

function configuredClientHosts(env: Env): Set<string> {
  return new Set(
    String(env.PDS_OAUTH_CLIENT_HOSTS || '')
      .split(',')
      .map((host) => host.trim().toLowerCase())
      .filter(Boolean),
  );
}

function assertClientHostAllowed(env: Env, url: URL, label: string): void {
  const allowed = configuredClientHosts(env);
  if (allowed.size === 0) {
    throw new Error(`${label} host is not allowlisted`);
  }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!allowed.has(host)) {
    throw new Error(`${label} host is not allowlisted`);
  }
}

function isIpLiteral(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return true;
  return host.includes(':');
}

function isBlockedHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  if (host.endsWith('.internal') || host.endsWith('.home.arpa')) return true;
  if (isIpLiteral(host)) return true;
  return false;
}

function ipv4ToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const v = Number(part);
    if (v < 0 || v > 255) return null;
    n = (n << 8) + v;
  }
  return n >>> 0;
}

function ipv4InRange(ip: number, base: string, bits: number): boolean {
  const baseNumber = ipv4ToNumber(base);
  if (baseNumber === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ip & mask) === (baseNumber & mask);
}

function isBlockedIpv4Number(ip: number): boolean {
  return [
    ['0.0.0.0', 8],
    ['10.0.0.0', 8],
    ['100.64.0.0', 10],
    ['127.0.0.0', 8],
    ['169.254.0.0', 16],
    ['172.16.0.0', 12],
    ['192.0.0.0', 24],
    ['192.0.2.0', 24],
    ['192.168.0.0', 16],
    ['198.18.0.0', 15],
    ['198.51.100.0', 24],
    ['203.0.113.0', 24],
    ['224.0.0.0', 4],
    ['240.0.0.0', 4],
  ].some(([base, bits]) => ipv4InRange(ip, base as string, bits as number));
}

function isBlockedIpAddress(value: string): boolean {
  const host = value.toLowerCase().replace(/^\[|\]$/g, '');
  const ipv4 = ipv4ToNumber(host);
  if (ipv4 !== null) {
    return isBlockedIpv4Number(ipv4);
  }

  if (!host.includes(':')) return false;
  const dottedIpv4Suffix = host.match(/(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/)?.[1];
  if (dottedIpv4Suffix) {
    const embedded = ipv4ToNumber(dottedIpv4Suffix);
    if (embedded !== null) return true;
  }
  if (host.startsWith('::ffff:') || host.startsWith('0:0:0:0:0:ffff:')) return true;
  return (
    host === '::' ||
    host === '::1' ||
    host.startsWith('fc') ||
    host.startsWith('fd') ||
    host.startsWith('fe8') ||
    host.startsWith('fe9') ||
    host.startsWith('fea') ||
    host.startsWith('feb') ||
    host.startsWith('2001:db8') ||
    host.startsWith('::ffff:10.') ||
    host.startsWith('::ffff:127.') ||
    host.startsWith('::ffff:192.168.')
  );
}

export function isSafeFetchUrl(u: string): boolean {
  try {
    const url = new URL(u);
    if (url.protocol !== 'https:') return false;
    if (url.username || url.password || url.hash) return false;
    if (url.port && url.port !== '443') return false;
    if (isBlockedHost(url.hostname)) return false;
    if (isBlockedIpAddress(url.hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

export function isHttpsUrl(u: string): boolean {
  return isSafeFetchUrl(u);
}

function isLoopbackHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '127.0.0.1' || host === '::1';
}

export function isAllowedRedirectUri(uri: string): boolean {
  try {
    const url = new URL(uri);
    if (url.username || url.password || url.hash) return false;
    if (url.protocol === 'https:') {
      return !isBlockedHost(url.hostname);
    }
    if (url.protocol === 'http:') {
      return isLoopbackHostname(url.hostname);
    }
    return false;
  } catch {
    return false;
  }
}

export function redirectUriMatches(registered: string, requested: string): boolean {
  if (registered === requested) return true;
  try {
    const reg = new URL(registered);
    const req = new URL(requested);
    if (reg.protocol !== 'http:' || req.protocol !== 'http:') return false;
    if (!isLoopbackHostname(reg.hostname) || !isLoopbackHostname(req.hostname)) return false;
    if (reg.hostname.toLowerCase() !== req.hostname.toLowerCase()) return false;
    if (reg.pathname !== req.pathname || reg.search !== req.search) return false;
    return !reg.port && !!req.port;
  } catch {
    return false;
  }
}

export async function safeFetchJson(env: Env, url: string, label: string): Promise<any> {
  if (!isSafeFetchUrl(url)) {
    throw new Error(`${label} URL is not safe to fetch`);
  }

  const parsed = new URL(url);
  assertClientHostAllowed(env, parsed, label);
  await assertHostnameResolvesPublic(parsed, label);

  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 3000);
  try {
    const response = await fetch(url, {
      signal: ctl.signal,
      redirect: 'error',
      headers: { accept: 'application/json' },
    });
    if (!response.ok) throw new Error(`${label} fetch failed: ${response.status}`);
    const ctype = response.headers.get('content-type') || '';
    if (!ctype.includes('application/json') && !ctype.includes('json')) {
      throw new Error(`${label} must be JSON`);
    }
    const text = await readResponseTextBounded(response, label);
    return JSON.parse(text || '{}');
  } finally {
    clearTimeout(t);
  }
}

async function readResponseTextBounded(response: Response, label: string): Promise<string> {
  if (!response.body) {
    const text = await response.text();
    if (text.length > MAX_CLIENT_JSON_BYTES) throw new Error(`${label} response too large`);
    return text;
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let text = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_CLIENT_JSON_BYTES) {
      await reader.cancel().catch(() => {});
      throw new Error(`${label} response too large`);
    }
    text += decoder.decode(value, { stream: true });
  }
  text += decoder.decode();
  return text;
}

async function assertHostnameResolvesPublic(url: URL, label: string): Promise<void> {
  if (isIpLiteral(url.hostname)) {
    if (isBlockedIpAddress(url.hostname)) throw new Error(`${label} resolves to blocked address`);
    return;
  }

  const records = await resolveHostAddresses(url.hostname);
  if (records.length === 0) {
    throw new Error(`${label} hostname has no public address records`);
  }
  if (records.some(isBlockedIpAddress)) {
    throw new Error(`${label} resolves to blocked address`);
  }
}

async function resolveHostAddresses(hostname: string): Promise<string[]> {
  const records: string[] = [];
  for (const type of ['A', 'AAAA']) {
    const url = new URL('https://cloudflare-dns.com/dns-query');
    url.searchParams.set('name', hostname);
    url.searchParams.set('type', type);
    const response = await fetch(url.toString(), {
      headers: { accept: 'application/dns-json' },
      redirect: 'error',
    });
    if (!response.ok) continue;
    const body = await response.json().catch(() => null) as any;
    const answers = Array.isArray(body?.Answer) ? body.Answer : [];
    for (const answer of answers) {
      if ((answer?.type === 1 || answer?.type === 28) && typeof answer.data === 'string') {
        records.push(answer.data);
      }
    }
  }
  return records;
}

export async function fetchClientMetadata(env: Env, client_id: string): Promise<OAuthClientMetadata> {
  const metadata = await safeFetchJson(env, client_id, 'client metadata');
  return validateClientMetadataShape(metadata, client_id);
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
  if (!redirect_uris.every((uri: unknown) => typeof uri === 'string' && isAllowedRedirectUri(uri))) {
    throw new Error('redirect_uris contains unsupported URI');
  }
  if (metadata.dpop_bound_access_tokens !== true) {
    throw new Error('client must require DPoP');
  }

  const method = metadata.token_endpoint_auth_method;
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
    redirect_uris,
    token_endpoint_auth_method: method,
    grant_types: metadata.grant_types,
    response_types: metadata.response_types,
    scope: metadata.scope,
    dpop_bound_access_tokens: true,
    jwks: metadata.jwks,
    jwks_uri: metadata.jwks_uri,
    application_type: typeof metadata.application_type === 'string' ? metadata.application_type : undefined,
  };
}

export function validateParRequest(metadata: OAuthClientMetadata, request: {
  response_type: string;
  grant_type?: string;
  redirect_uri: string;
  scope: string;
  code_challenge: string;
  code_challenge_method: string;
}): void {
  if (request.grant_type && request.grant_type !== 'authorization_code') {
    throw new Error('unsupported grant_type');
  }
  if (request.response_type !== 'code') {
    throw new Error('unsupported response_type');
  }
  if (!request.redirect_uri || !isAllowedRedirectUri(request.redirect_uri)) {
    throw new Error('unsupported redirect_uri');
  }
  if (!metadata.redirect_uris.some((uri) => redirectUriMatches(uri, request.redirect_uri))) {
    throw new Error('redirect_uri not registered');
  }
  const requestedScopes = request.scope.split(' ').filter(Boolean);
  const allowedScopes = new Set(metadata.scope.split(' ').filter(Boolean));
  if (!requestedScopes.length || !requestedScopes.includes('atproto')) {
    throw new Error('invalid scope');
  }
  if (requestedScopes.includes('openid')) {
    throw new Error('openid scope is not supported');
  }
  for (const scope of requestedScopes) {
    if (!allowedScopes.has(scope)) {
      throw new Error(`scope not allowed: ${scope}`);
    }
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
): Promise<VerifiedClientAuth> {
  if (metadata.token_endpoint_auth_method === 'none') {
    if (form.get('client_assertion') || form.get('client_assertion_type')) {
      throw new Error('public client must not send client_assertion');
    }
    return { method: 'none', keyId: null };
  }

  const client_assertion_type = form.get('client_assertion_type') || '';
  const client_assertion = form.get('client_assertion') || '';
  if (client_assertion_type !== CLIENT_ASSERTION_TYPE || !client_assertion) {
    throw new Error('missing client assertion');
  }
  const jwks = await resolveClientJwks(env, metadata);
  const result = await verifyClientAssertion(env, client_id, issuerOrigin, client_assertion, jwks);
  if (!result) {
    throw new Error('invalid client assertion');
  }
  return { method: 'private_key_jwt', keyId: result.keyId };
}

async function consumeClientAssertionJti(env: Env, clientId: string, jti: string, exp: number): Promise<boolean> {
  const key = `oauth:client-assertion:jti:${clientId}:${jti}`;
  await cleanupExpiredOAuthReplaySecrets(env, Math.floor(Date.now() / 1000));
  return createSecretOnce(env, key, JSON.stringify({ exp }));
}

export async function verifyClientAssertion(
  env: Env,
  client_id: string,
  issuerOrigin: string,
  assertionJwt: string,
  jwks: { keys: JsonWebKey[] },
): Promise<{ keyId: string } | null> {
  try {
    const [h, p] = assertionJwt.split('.');
    if (!h || !p) return null;
    const header = decodeProtectedHeader(assertionJwt) as any;
    if (header.alg !== 'ES256') return null;
    const keys: any[] = Array.isArray(jwks?.keys) ? jwks.keys : [];
    if (!keys.length) return null;
    const byKid = typeof header.kid === 'string' ? keys.find((k) => k.kid === header.kid) : null;
    const candidates = byKid ? [byKid] : keys;

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
    if (typeof payload.iat !== 'number' || now - payload.iat > 300 || payload.iat - now > 30) return null;
    if (typeof payload.exp !== 'number' || payload.exp <= now || payload.exp - now > 300) return null;
    if (typeof payload.jti !== 'string' || payload.jti.length < 8) return null;
    if (!(await consumeClientAssertionJti(env, client_id, payload.jti, payload.exp))) return null;

    return {
      keyId: typeof header.kid === 'string' ? header.kid : await jwkThumbprint(matchedKey),
    };
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
  expected: { method: string | null; keyId?: string | null },
): Promise<VerifiedClientAuth> {
  const actual = await verifyClientAuthentication(env, clientId, issuerOrigin, metadata, form);
  if (actual.method !== expected.method) {
    throw new Error('client authentication method changed');
  }
  if (actual.method === 'private_key_jwt' && expected.keyId && actual.keyId !== expected.keyId) {
    throw new Error('client authentication key changed');
  }
  return actual;
}
