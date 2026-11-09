import { isBlockedHost } from './safe-fetch';
import type { OAuthApplicationType } from './clients';

// RFC 8252 §8.3: loopback redirects must name the IP literal, because
// `localhost` can resolve to a non-loopback interface.
function isLoopbackIpHostname(hostname: string): boolean {
  return hostname === '127.0.0.1' || hostname === '[::1]';
}

function reverseDomain(hostname: string): string {
  return hostname
    .toLowerCase()
    .split('.')
    .filter(Boolean)
    .reverse()
    .join('.');
}

function isNativePrivateUseRedirect(url: URL, uri: string, clientId: string | undefined): boolean {
  if (!clientId) return false;
  let clientUrl: URL;
  try {
    clientUrl = new URL(clientId);
  } catch {
    return false;
  }
  if (clientUrl.protocol !== 'https:') return false;

  const scheme = url.protocol.slice(0, -1);
  if (!scheme || scheme !== reverseDomain(clientUrl.hostname)) return false;
  if (!uri.startsWith(`${scheme}:/`) || uri.startsWith(`${scheme}://`)) return false;
  if (url.username || url.password || url.hash || url.host) return false;
  return url.pathname.startsWith('/');
}

export function isAllowedRedirectUri(
  uri: string,
  opts: { applicationType?: OAuthApplicationType; clientId?: string } = {},
): boolean {
  try {
    const url = new URL(uri);
    if (url.username || url.password || url.hash) return false;
    if (url.protocol === 'https:') {
      if (opts.applicationType === 'native' && opts.clientId) {
        const clientUrl = new URL(opts.clientId);
        if (url.origin !== clientUrl.origin) return false;
      }
      return !isBlockedHost(url.hostname);
    }
    if (url.protocol === 'http:') {
      return opts.applicationType === 'native' && isLoopbackIpHostname(url.hostname);
    }
    if (opts.applicationType === 'native') {
      return isNativePrivateUseRedirect(url, uri, opts.clientId);
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
    if (!isLoopbackIpHostname(reg.hostname) || reg.hostname !== req.hostname) return false;
    if (reg.pathname !== req.pathname || reg.search !== req.search) return false;
    // RFC 8252 §7.3: a native client listens on an ephemeral port, so a
    // registration without a port accepts any port. A registered port is a
    // deliberate pin and still has to match exactly (handled above).
    return !reg.port;
  } catch {
    return false;
  }
}
