import type { Env } from '../env';
import { getRuntimeString } from './secrets';

export type PublicOrigin = {
  origin: string;
  hostname: string;
  host: string;
};

const HANDLE_SYNTAX = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/i;
const DISALLOWED_RESOLUTION_TLDS = new Set([
  'alt',
  'arpa',
  'example',
  'internal',
  'invalid',
  'local',
  'localhost',
  'onion',
]);

export async function configuredDid(env: Env): Promise<string> {
  return (await getRuntimeString(env, 'PDS_DID', 'did:example:single-user')) ?? 'did:example:single-user';
}

async function configuredHandleValue(env: Env): Promise<string> {
  return (await getRuntimeString(env, 'PDS_HANDLE', 'user.example.com')) ?? 'user.example.com';
}

export async function configuredHandle(env: Env): Promise<string> {
  const value = await configuredHandleValue(env);
  return validAtprotoHandle(value) ?? value.trim().toLowerCase();
}

export function validAtprotoHandle(handle: string | undefined | null): string | null {
  if (typeof handle !== 'string') return null;
  if (handle === '' || handle.length > 253) return null;
  const normalized = handle.toLowerCase();
  if (!HANDLE_SYNTAX.test(normalized)) return null;

  const tld = normalized.slice(normalized.lastIndexOf('.') + 1);
  if (DISALLOWED_RESOLUTION_TLDS.has(tld)) return null;

  return normalized;
}

export async function configuredAtprotoHandle(env: Env): Promise<string | null> {
  return validAtprotoHandle(await configuredHandleValue(env));
}

export async function canonicalPdsOrigin(env: Env): Promise<string> {
  const configuredHost = await getRuntimeString(env, 'PDS_HOSTNAME', '');
  const handle = await configuredHandle(env);
  const parsed = parsePublicOrigin(configuredHost || handle);
  return parsed?.origin ?? `https://${handle}`;
}

export async function canonicalPdsHost(env: Env): Promise<string | null> {
  const configuredHost = await getRuntimeString(env, 'PDS_HOSTNAME', '');
  const handle = await configuredHandle(env);
  return parsePublicOrigin(configuredHost || handle)?.hostname ?? null;
}

export async function configuredHandleHost(env: Env): Promise<string | null> {
  return configuredAtprotoHandle(env);
}

export function requestHostname(request: Request): string | null {
  try {
    return normalizeHostname(new URL(request.url).hostname);
  } catch {
    return null;
  }
}

export async function requestMatchesConfiguredHandle(request: Request, env: Env): Promise<boolean> {
  const actual = requestHostname(request);
  const expected = await configuredHandleHost(env);
  return !!actual && !!expected && actual === expected;
}

export async function handleResolvesToDid(env: Env, handle: string, did: string): Promise<boolean> {
  const normalizedHandle = validAtprotoHandle(handle);
  const expectedHandle = await configuredHandle(env);
  const expectedDid = await configuredDid(env);
  return !!normalizedHandle &&
    normalizedHandle === expectedHandle &&
    did === expectedDid &&
    !!(await configuredAtprotoHandle(env));
}

export function didDocClaimsHandle(didDoc: { alsoKnownAs?: unknown }, handle: string): boolean {
  const normalizedHandle = validAtprotoHandle(handle);
  if (!normalizedHandle) return false;
  return Array.isArray(didDoc.alsoKnownAs) &&
    didDoc.alsoKnownAs.includes(`at://${normalizedHandle}`);
}

export function isLocalHostname(hostname: string): boolean {
  const lower = normalizeHostname(hostname);
  return lower === 'localhost' ||
    lower.endsWith('.localhost') ||
    lower === '127.0.0.1' ||
    lower === '0.0.0.0' ||
    lower === '::1';
}

function normalizeHostname(hostname: string): string {
  return hostname.trim().toLowerCase().replace(/^\[(.*)\]$/, '$1');
}

export function parsePublicOrigin(raw: string | undefined | null): PublicOrigin | null {
  const value = raw?.trim();
  if (!value) return null;

  try {
    const url = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
    if (!url.hostname) return null;
    return {
      origin: `https://${url.host}`,
      hostname: normalizeHostname(url.hostname),
      host: url.host.toLowerCase(),
    };
  } catch {
    return null;
  }
}
