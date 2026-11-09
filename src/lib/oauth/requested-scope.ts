import { isSupportedOAuthScopeValue } from '../auth-scope';

export type RequestedScopeResolution =
  | { readonly tag: 'granted'; readonly scope: string }
  | { readonly tag: 'invalid'; readonly message: string };

/**
 * Decides which scope a pushed authorization request is granted.
 *
 * The result is what the consent screen shows and what the tokens carry, so a
 * value this server cannot enforce is left out of the grant rather than stored
 * (RFC 6749 §3.3 lets the server narrow a request; the token response then
 * reports the granted scope).
 */
export function resolveRequestedScope(requested: string, declared: string): RequestedScopeResolution {
  // Enforcement tokenises on any whitespace, so a tab or newline smuggled into
  // one "value" here would become two scopes there.
  if (!/^[\x21-\x7e]+(?: [\x21-\x7e]+)*$/.test(requested)) {
    return { tag: 'invalid', message: 'scope must be printable ASCII values separated by single spaces' };
  }
  const requestedValues = [...new Set(requested.split(' '))];
  const declaredValues = new Set(declared.split(' ').filter(Boolean));

  if (!requestedValues.includes('atproto')) {
    return { tag: 'invalid', message: 'the "atproto" scope is required' };
  }
  if (requestedValues.includes('openid')) {
    return { tag: 'invalid', message: 'the "openid" scope is not supported' };
  }
  for (const value of requestedValues) {
    if (!declaredValues.has(value)) {
      return { tag: 'invalid', message: `scope "${value}" is not declared in the client metadata` };
    }
  }
  return { tag: 'granted', scope: requestedValues.filter(isSupportedOAuthScopeValue).join(' ') };
}
