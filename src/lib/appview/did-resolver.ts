import type { Env } from '../../env';
import { InvalidProxyHeader, UpstreamProxyFailure } from '../errors';
import type { ProxyTarget, ServiceConfig, ServiceId } from './types';

interface DidService {
  readonly id?: unknown;
  readonly serviceEndpoint?: unknown;
}

interface DidDocument {
  readonly id?: unknown;
  readonly service?: unknown;
}

const didDocumentCache = new Map<string, Promise<DidDocument>>();

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
  const existing = didDocumentCache.get(did);
  if (existing) {
    return existing;
  }

  const loader = fetchDidDocument(env, did).catch((error) => {
    didDocumentCache.delete(did);
    throw error;
  });

  didDocumentCache.set(did, loader);
  return loader;
}

async function fetchDidDocument(_env: Env, did: string): Promise<DidDocument> {
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

  return response.json() as Promise<DidDocument>;
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
