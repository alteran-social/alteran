import type { OAuthClientMetadata } from './clients';

// The atproto OAuth profile lets development clients skip hosting a metadata
// document: the client_id is `http://localhost` and its query string carries
// the only two values a client may choose (`scope` and `redirect_uri`).
// https://atproto.com/specs/oauth#localhost-client-development
const LOOPBACK_CLIENT_ID_ORIGIN = 'http://localhost';
const DEFAULT_LOOPBACK_SCOPE = 'atproto';
const DEFAULT_LOOPBACK_REDIRECT_URIS: readonly string[] = ['http://127.0.0.1/', 'http://[::1]/'];
const LOOPBACK_REDIRECT_HOSTNAMES: ReadonlySet<string> = new Set(['127.0.0.1', '[::1]']);

export type LoopbackClientResolution =
  | { readonly tag: 'not-loopback' }
  | { readonly tag: 'invalid'; readonly message: string }
  | { readonly tag: 'loopback'; readonly metadata: OAuthClientMetadata };

export function isLoopbackClientId(clientId: string): boolean {
  return loopbackClientQuery(clientId).tag !== 'not-loopback';
}

export function resolveLoopbackClient(clientId: string): LoopbackClientResolution {
  const query = loopbackClientQuery(clientId);
  if (query.tag !== 'query') return query;

  let scope: string | null = null;
  const redirectUris: string[] = [];
  for (const [key, value] of new URLSearchParams(query.value)) {
    if (key === 'scope') {
      if (scope !== null) return invalid('duplicate "scope" query parameter');
      scope = value;
    } else if (key === 'redirect_uri') {
      if (!isLoopbackRedirectUri(value)) {
        return invalid('"redirect_uri" must be an http URL on 127.0.0.1 or [::1]');
      }
      redirectUris.push(value);
    } else {
      return invalid(`unexpected query parameter "${key}"`);
    }
  }

  const grantedScope = scope ?? DEFAULT_LOOPBACK_SCOPE;
  if (!/^[\x21-\x7e]+(?: [\x21-\x7e]+)*$/.test(grantedScope)) {
    return invalid('"scope" must be a space-separated list of scope values');
  }
  if (!grantedScope.split(' ').includes('atproto')) {
    return invalid('"scope" must include atproto');
  }

  return {
    tag: 'loopback',
    metadata: {
      client_id: clientId,
      redirect_uris: redirectUris.length > 0 ? redirectUris : [...DEFAULT_LOOPBACK_REDIRECT_URIS],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: grantedScope,
      dpop_bound_access_tokens: true,
      application_type: 'native',
    },
  };
}

type LoopbackClientQuery =
  | { readonly tag: 'not-loopback' }
  | { readonly tag: 'invalid'; readonly message: string }
  | { readonly tag: 'query'; readonly value: string };

// Parsed by hand rather than with `new URL`: URL parsing normalises the input,
// and a client_id is an opaque identifier that must match byte for byte.
function loopbackClientQuery(clientId: string): LoopbackClientQuery {
  if (!clientId.startsWith(LOOPBACK_CLIENT_ID_ORIGIN)) return { tag: 'not-loopback' };
  const rest = clientId.slice(LOOPBACK_CLIENT_ID_ORIGIN.length);
  if (rest !== '' && !/^[/?#]/.test(rest)) {
    // `http://localhost:8080`, `http://localhost.example`, ...
    return { tag: 'not-loopback' };
  }
  if (rest.includes('#')) return invalid('client_id must not contain a fragment');
  const afterSlash = rest.startsWith('/') ? rest.slice(1) : rest;
  if (afterSlash === '') return { tag: 'query', value: '' };
  if (!afterSlash.startsWith('?')) return invalid('client_id must not contain a path');
  return { tag: 'query', value: afterSlash.slice(1) };
}

function isLoopbackRedirectUri(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return url.protocol === 'http:' &&
    LOOPBACK_REDIRECT_HOSTNAMES.has(url.hostname) &&
    !url.username &&
    !url.password &&
    !url.hash;
}

function invalid(message: string): { readonly tag: 'invalid'; readonly message: string } {
  return { tag: 'invalid', message: `invalid loopback client_id: ${message}` };
}
