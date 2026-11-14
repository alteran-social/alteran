import type { Env } from '../../env';
import { isValidHandle } from '@atproto/syntax-spaces';
import { resolveSecret } from '../secrets';
import { spaceIdentityDocumentUrl } from './identity-url';
import { parseUniqueIdentityJson } from './identity-json';
import { checkSpaceKemIdentity } from './kem-identity';
import { loadSpaceKemKey, type SpaceKemKey } from './kem-key';
import { fetchPublicHttps } from './public-fetch';

export type LocalSpaceKemIdentity =
  | { readonly tag: 'ready'; readonly did: string; readonly key: SpaceKemKey }
  | { readonly tag: 'missing' | 'invalid' | 'mismatch' | 'unsupported' | 'unavailable' | 'aborted' | 'timeout' };

/** Resolve only the configured account; callers must establish a safe egress boundary. */
export async function resolveLocalSpaceKemIdentity(
  env: Env,
  expectedDid: string,
  signal: AbortSignal,
  timeoutMs = 3000,
): Promise<LocalSpaceKemIdentity> {
  if (!(signal instanceof AbortSignal) || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 3000) {
    return { tag: 'invalid' };
  }
  if (signal.aborted) return { tag: 'aborted' };
  const controller = new AbortController();
  const deadline = performance.now() + timeoutMs;
  let stopped: 'aborted' | 'timeout' | null = null;
  let finishStop: (result: LocalSpaceKemIdentity) => void = () => {};
  const stopResult = new Promise<LocalSpaceKemIdentity>((resolve) => { finishStop = resolve; });
  const stop = (reason: 'aborted' | 'timeout') => {
    if (stopped) return;
    stopped = reason;
    controller.abort();
    finishStop({ tag: reason });
  };
  const onAbort = () => stop('aborted');
  signal.addEventListener('abort', onAbort, { once: true });
  const timer = setTimeout(() => stop('timeout'), timeoutMs);
  const isStopped = () => {
    if (!stopped && performance.now() >= deadline) stop('timeout');
    return controller.signal.aborted;
  };
  if (signal.aborted) stop('aborted');
  const resolveIdentity = async (): Promise<LocalSpaceKemIdentity> => {
    if (isStopped()) return { tag: stopped ?? 'unavailable' };
    const [did, loaded, configuredHost] = await Promise.all([
      resolveSecret(env.PDS_DID), loadSpaceKemKey(env), resolveSecret(env.PDS_HOSTNAME),
    ]);
    if (isStopped()) return { tag: stopped ?? 'unavailable' };
    if (typeof did !== 'string' || did !== expectedDid) return { tag: 'invalid' };
    const origin = strictPdsOrigin(configuredHost, true);
    if (!origin) return { tag: 'invalid' };
    const url = spaceIdentityDocumentUrl(did);
    if (!url) return { tag: 'unsupported' };
    if (loaded.tag !== 'ready') return { tag: loaded.tag === 'missing' ? 'missing' : loaded.tag === 'invalid' ? 'invalid' : 'unavailable' };
    const response = await fetchPublicHttps(url, { maxBytes: 65_536, timeoutMs, signal: controller.signal });
    if (isStopped()) return { tag: stopped ?? 'unavailable' };
    if (response.tag !== 'ok' || !isJsonContentType(response.contentType)) return { tag: 'unavailable' };
    let document: unknown;
    try {
      document = parseUniqueIdentityJson(new TextDecoder('utf-8', { fatal: true }).decode(response.bytes));
    } catch {
      return { tag: 'invalid' };
    }
    const status = checkSpaceKemIdentity(did, loaded.key.publicDidKey, document);
    if (status !== 'ready') return { tag: status };
    if (!claimsPdsOrigin(document, did, origin)) return { tag: 'mismatch' };
    const [currentDid, currentKey, currentHost] = await Promise.all([
      resolveSecret(env.PDS_DID), loadSpaceKemKey(env), resolveSecret(env.PDS_HOSTNAME),
    ]);
    if (isStopped()) return { tag: stopped ?? 'unavailable' };
    if (currentDid !== did || currentKey.tag !== 'ready' || currentKey.key.publicDidKey !== loaded.key.publicDidKey ||
      currentHost !== configuredHost || strictPdsOrigin(currentHost, true) !== origin) return { tag: 'unavailable' };
    return { tag: 'ready', did, key: currentKey.key };
  };
  try {
    const result = await Promise.race([resolveIdentity().catch((): LocalSpaceKemIdentity => ({ tag: 'unavailable' })), stopResult]);
    if (isStopped()) return { tag: stopped ?? 'unavailable' };
    return result;
  } finally {
    clearTimeout(timer);
    signal.removeEventListener('abort', onAbort);
  }
}

function isJsonContentType(value: string | null): boolean {
  const type = value?.split(';', 1)[0].trim().toLowerCase();
  return type === 'application/json' || type === 'application/did+json' || type === 'application/did+ld+json';
}

// A bare configured host denotes HTTPS; an explicit URL must be an HTTPS origin.
function strictPdsOrigin(value: unknown, allowBareHost: boolean): string | null {
  if (typeof value !== 'string' || value.length > 260) return null;
  const match = /^(https:\/\/)?([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::([0-9]{1,5}))?\/?$/i.exec(value);
  if (!match || (!allowBareHost && !match[1]) || !isValidHandle(match[2])) return null;
  try {
    const parsed = new URL(`https://${match[2]}${match[3] ? `:${match[3]}` : ''}`);
    return parsed.hostname === match[2].toLowerCase() ? parsed.origin : null;
  } catch {
    return null;
  }
}

function claimsPdsOrigin(document: unknown, did: string, expectedOrigin: string): boolean {
  if (!document || typeof document !== 'object' || Array.isArray(document)) return false;
  const services = (document as Record<string, unknown>).service;
  if (!Array.isArray(services) || services.length > 128) return false;
  const matches = services.filter((service: unknown) => {
    if (!service || typeof service !== 'object' || Array.isArray(service)) return false;
    const id = (service as Record<string, unknown>).id;
    return id === '#atproto_pds' || id === `${did}#atproto_pds`;
  });
  if (matches.length !== 1) return false;
  const service = matches[0] as Record<string, unknown>;
  if (service.type !== 'AtprotoPersonalDataServer' || typeof service.serviceEndpoint !== 'string') return false;
  return strictPdsOrigin(service.serviceEndpoint, false) === expectedOrigin;
}
