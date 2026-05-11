import type { Env } from '../env';

/**
 * Resolve the public hostname for this PDS.
 * Priority: env.PDS_HOSTNAME -> request URL host.
 * Ensures the value is a bare hostname (no scheme/port/path).
 */
export function resolvePdsHostname(env: Env, requestUrl?: string): string | null {
  let host = (env.PDS_HOSTNAME as string | undefined)?.trim() || '';

  if (!host && requestUrl) {
    try {
      const url = new URL(requestUrl);
      host = url.hostname;
    } catch {}
  }

  if (!host) return null;

  // Normalize: strip protocol/port if somehow present
  host = host.replace(/^https?:\/\//i, '').replace(/:\d+$/, '').trim();

  // Skip obvious local hosts to avoid spamming relays from dev
  const lower = host.toLowerCase();
  if (
    lower === 'localhost' ||
    lower.endsWith('.localhost') ||
    lower === '127.0.0.1' ||
    lower === '0.0.0.0' ||
    lower === '::1'
  ) {
    return null;
  }

  return host;
}

/**
 * Parse relay hosts from env or return default list.
 * CSV of bare hostnames (e.g. "bsky.network,relay.example.org").
 */
export function getRelayHosts(env: Env): string[] {
  const csv = (env.PDS_RELAY_HOSTS as string | undefined)?.trim();
  const hosts = csv && csv.length > 0 ? csv.split(',') : ['bsky.network'];
  return hosts
    .map((h) => h.trim())
    .filter((h) => h && !/^https?:\/\//i.test(h))
    .filter((h, i, arr) => arr.indexOf(h) === i);
}

/**
 * Notify a single relay host using com.atproto.sync.requestCrawl
 */
export async function requestCrawl(relayHost: string, pdsHostname: string): Promise<Response> {
  const url = `https://${relayHost}/xrpc/com.atproto.sync.requestCrawl`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ hostname: pdsHostname }),
  });
  return response;
}

// In-memory isolation-scoped throttle to avoid spamming relays on every request.
let lastNotifyTs = 0;

/**
 * Best-effort: notify relays that our PDS is available.
 * - No throw on failure; logs to console only.
 * - Throttled per isolate to at most once every 12h.
 */
export async function notifyRelaysIfNeeded(env: Env, requestUrl?: string): Promise<void> {
  // Allow disabling via flag
  const disabled = String(env.PDS_RELAY_NOTIFY || '').toLowerCase() === 'false';
  if (disabled) return;

  const now = Date.now();
  if (now - lastNotifyTs < 12 * 60 * 60 * 1000) {
    return;
  }

  const hostname = resolvePdsHostname(env, requestUrl);
  if (!hostname) return;

  const relays = getRelayHosts(env);
  lastNotifyTs = now; // set early to avoid stampedes

  await Promise.allSettled(
    relays.map(async (relay) => {
      try {
        const response = await requestCrawl(relay, hostname);
        if (!response.ok) {
          console.warn('requestCrawl failed', { relay, status: response.status });
        }
      } catch (error) {
        console.warn('requestCrawl error', { relay, error: String(error) });
      }
    }),
  );
}

