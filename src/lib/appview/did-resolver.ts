import type { Env } from '../../env';
import { InvalidProxyHeader, UpstreamProxyFailure } from '../errors';
import type { ProxyTarget, ServiceConfig, ServiceId } from './types';

type DidService = {
  readonly id?: unknown;
  readonly serviceEndpoint?: unknown;
};

type DidDocument = {
  readonly id?: unknown;
  readonly service?: unknown;
};

// The cache key is derived from a user-supplied `atproto-proxy` header. Without
// bounds, a noisy or hostile client can grow this map without limit. Cap the
// entry count and expire entries after a fixed TTL so memory stays predictable
// across long-lived isolates.
const CACHE_MAX = 1024;
const CACHE_TTL_MS = 10 * 60 * 1000;

type CacheEntry = {
  readonly doc: Promise<DidDocument>;
  readonly expiresAt: number;
};
const didDocumentCache = new Map<string, CacheEntry>();

let clock: () => number = () => Date.now();
let fetchOverride: ((did: string) => Promise<DidDocument>) | null = null;

function getCached(did: string): Promise<DidDocument> | null {
  const entry = didDocumentCache.get(did);
  if (!entry) return null;
  if (entry.expiresAt <= clock()) {
    didDocumentCache.delete(did);
    return null;
  }
  // Re-insert to mark as most recently used. Map preserves insertion order, so
  // the oldest entry is whatever keys().next() returns when we evict.
  didDocumentCache.delete(did);
  didDocumentCache.set(did, entry);
  return entry.doc;
}

function setCached(did: string, doc: Promise<DidDocument>): void {
  if (didDocumentCache.size >= CACHE_MAX) {
    const oldest = didDocumentCache.keys().next().value;
    if (oldest !== undefined) didDocumentCache.delete(oldest);
  }
  didDocumentCache.set(did, { doc, expiresAt: clock() + CACHE_TTL_MS });
}

export function parseProxyHeader(header: string): { did: string; serviceId: string } {
  const value = header.trim();
  const hashIndex = value.indexOf('#');

  if (hashIndex <= 0 || hashIndex === value.length - 1) {
    throw new InvalidProxyHeader('invalid format');
  }

  if (value.indexOf('#', hashIndex + 1) !== -1) {
    throw new InvalidProxyHeader('invalid format');
  }

  const did = value.slice(0, hashIndex);
  const serviceId = value.slice(hashIndex);

  if (!did.startsWith('did:')) {
    throw new InvalidProxyHeader('invalid DID');
  }

  if (!serviceId.startsWith('#')) {
    throw new InvalidProxyHeader('invalid service id');
  }

  if (value.includes(' ')) {
    throw new InvalidProxyHeader('invalid format');
  }

  return { did, serviceId };
}

export async function resolveProxyTargetWithRegistry(
  env: Env,
  proxyHeader: string,
  registry: Record<ServiceId, ServiceConfig>,
): Promise<ProxyTarget> {
  const { did, serviceId } = parseProxyHeader(proxyHeader);

  const trimmedServiceId = serviceId.startsWith('#') ? serviceId.slice(1) : serviceId;
  const known = registry[trimmedServiceId as ServiceId];
  if (known && did === known.did) {
    return { did, url: known.url };
  }

  const didDoc = await resolveDidDocument(env, did);
  const endpoint = getServiceEndpointFromDidDoc(didDoc, serviceId);
  if (!endpoint) {
    throw new InvalidProxyHeader('service id not found in DID document');
  }
  return { did, url: endpoint };
}

async function resolveDidDocument(env: Env, did: string): Promise<DidDocument> {
  const existing = getCached(did);
  if (existing) return existing;

  const loader = fetchDidDocument(env, did).catch((error) => {
    didDocumentCache.delete(did);
    throw error;
  });

  setCached(did, loader);
  return loader;
}

async function fetchDidDocument(_env: Env, did: string): Promise<DidDocument> {
  if (fetchOverride) return fetchOverride(did);

  let url: string;
  if (did.startsWith('did:web:')) {
    url = buildDidWebUrl(did);
  } else if (did.startsWith('did:plc:')) {
    url = `https://plc.directory/${did}`;
  } else {
    throw new InvalidProxyHeader('unsupported DID method');
  }

  const response = await fetch(url, {
    headers: {
      accept: 'application/did+json, application/json;q=0.9',
    },
  });

  if (!response.ok) {
    throw new UpstreamProxyFailure('failed to resolve DID document');
  }

  return parseDidDocument(await response.json());
}

function parseDidDocument(value: unknown): DidDocument {
  if (!value || typeof value !== 'object') {
    throw new UpstreamProxyFailure('DID document is not an object');
  }
  const record = value as Record<string, unknown>;
  if (typeof record.id !== 'string') {
    throw new UpstreamProxyFailure('DID document missing id');
  }
  if (record.service !== undefined && !Array.isArray(record.service)) {
    throw new UpstreamProxyFailure('DID document service field is not an array');
  }
  return record as DidDocument;
}

function buildDidWebUrl(did: string): string {
  const suffix = did.slice('did:web:'.length);
  const parts = suffix.split(':').map((segment) => {
    try {
      return decodeURIComponent(segment);
    } catch {
      throw new InvalidProxyHeader('invalid did:web encoding');
    }
  });

  const host = parts.shift();
  if (!host) throw new InvalidProxyHeader('invalid did:web value');

  if (parts.length === 0) {
    return `https://${host}/.well-known/did.json`;
  }

  return `https://${host}/${parts.join('/')}/did.json`;
}

function getServiceEndpointFromDidDoc(didDoc: DidDocument, serviceId: string): string | null {
  if (!didDoc || typeof didDoc !== 'object') return null;
  const services = Array.isArray(didDoc.service) ? (didDoc.service as DidService[]) : [];
  if (!services.length) return null;

  const targets = new Set<string>([serviceId]);
  const docId = typeof didDoc.id === 'string' ? didDoc.id : undefined;
  if (docId && !serviceId.startsWith(docId)) {
    targets.add(`${docId}${serviceId}`);
  }

  for (const service of services) {
    if (!service || typeof service !== 'object') continue;
    const id = typeof service.id === 'string' ? service.id : undefined;
    if (!id || !targets.has(id)) continue;

    const endpoint = extractServiceEndpoint(service);
    if (endpoint) return endpoint;
  }

  return null;
}

function extractServiceEndpoint(service: DidService): string | null {
  const endpoint = service.serviceEndpoint;
  if (typeof endpoint === 'string') return endpoint;
  if (endpoint && typeof endpoint === 'object') {
    const obj = endpoint as { uri?: unknown; urls?: unknown };
    if (typeof obj.uri === 'string') return obj.uri;
    if (Array.isArray(obj.urls)) {
      const first = obj.urls.find((value: unknown) => typeof value === 'string');
      if (typeof first === 'string') return first;
    }
  }
  return null;
}

// Test seam — exercised only by tests/did-resolver-cache.test.ts. Production
// code does not import this object.
export const __testHooks = {
  reset(): void {
    didDocumentCache.clear();
    clock = () => Date.now();
    fetchOverride = null;
  },
  setClock(fn: () => number): void {
    clock = fn;
  },
  setFetcher(fn: (did: string) => Promise<DidDocument>): void {
    fetchOverride = fn;
  },
  cacheSize(): number {
    return didDocumentCache.size;
  },
  async resolve(did: string): Promise<DidDocument> {
    return resolveDidDocument({} as Env, did);
  },
};
