import type { Env } from '../../env';

const MAX_CLIENT_JSON_BYTES = 128 * 1024;

function isIpLiteral(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return true;
  return host.includes(':');
}

export function isBlockedHost(hostname: string): boolean {
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

export async function safeFetchJson(env: Env, url: string, label: string): Promise<any> {
  if (!isSafeFetchUrl(url)) {
    throw new Error(`${label} URL is not safe to fetch`);
  }

  const parsed = new URL(url);
  await assertHostnameResolvesPublic(parsed, label);

  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 3000);
  try {
    let response: Response;
    try {
      response = await fetch(url, {
        signal: ctl.signal,
        // Cloudflare Workers' fetch rejects redirect: 'error' at the edge.
        // Use 'manual' and treat any 3xx as a refused redirect.
        redirect: 'manual',
        headers: { accept: 'application/json' },
      });
    } catch (e) {
      const err = new Error(`${label} fetch error: ${e instanceof Error ? e.message : String(e)}`);
      throw err;
    }
    if ((response.status >= 300 && response.status < 400) || response.type === 'opaqueredirect') {
      const err = new Error(`${label} fetch failed: redirected (status ${response.status})`);
      Object.assign(err, {
        metadataStatus: response.status,
        metadataContentType: response.headers.get('content-type'),
        metadataRedirected: true,
      });
      throw err;
    }
    if (!response.ok) {
      const err = new Error(`${label} fetch failed: ${response.status}`);
      Object.assign(err, {
        metadataStatus: response.status,
        metadataContentType: response.headers.get('content-type'),
        metadataRedirected: response.redirected,
      });
      throw err;
    }
    const ctype = response.headers.get('content-type') || '';
    if (!ctype.includes('application/json') && !ctype.includes('json')) {
      const err = new Error(`${label} must be JSON`);
      Object.assign(err, {
        metadataStatus: response.status,
        metadataContentType: ctype,
        metadataRedirected: response.redirected,
      });
      throw err;
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
      redirect: 'manual',
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
