import type { Env } from '../env';
import { getRuntimeString } from './secrets';
import { AuthTokenExpiredError, authenticateRequest, expiredToken, unauthorized } from './auth';

const DEFAULT_APPVIEW_URL = 'https://api.bsky.app';
const DEFAULT_APPVIEW_DID = 'did:web:api.bsky.app';
const DEFAULT_CHAT_URL = 'https://api.bsky.chat';
const DEFAULT_CHAT_DID = 'did:web:api.bsky.chat';
const DEFAULT_OZONE_URL = 'https://mod.bsky.app';
const DEFAULT_OZONE_DID = 'did:plc:ar7c4by46qjdydhdevvrndac';

export interface AppViewConfig {
  url: string;
  did: string;
  cdnUrlPattern?: string;
}

type ServiceId = 'bsky_appview' | 'bsky_chat' | 'atproto_labeler';

interface ServiceConfig { id: ServiceId; url: string; did: string }


const didDocumentCache = new Map<string, Promise<unknown>>();

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function encodeJson(obj: Record<string, unknown>): string {
  const encoder = new TextEncoder();
  return encodeBase64Url(encoder.encode(JSON.stringify(obj)));
}

function randomHex(bytes = 16): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}

interface ProxyTarget { did: string; url: string }

type AuthScope =
  | 'com.atproto.access'
  | 'com.atproto.appPass'
  | 'com.atproto.appPassPrivileged'
  | 'com.atproto.signupQueued'
  | 'com.atproto.takendown';

const DEFAULT_ACCESS_SCOPE: AuthScope = 'com.atproto.access';
const TAKENDOWN_SCOPE: AuthScope = 'com.atproto.takendown';
const PRIVILEGED_SCOPES = new Set<AuthScope>([
  'com.atproto.access',
  'com.atproto.appPassPrivileged',
]);

const PRIVILEGED_METHODS = new Set<string>([
  'chat.bsky.actor.deleteAccount',
  'chat.bsky.actor.exportAccountData',
  'chat.bsky.convo.deleteMessageForSelf',
  'chat.bsky.convo.getConvo',
  'chat.bsky.convo.getConvoForMembers',
  'chat.bsky.convo.getLog',
  'chat.bsky.convo.getMessages',
  'chat.bsky.convo.leaveConvo',
  'chat.bsky.convo.listConvos',
  'chat.bsky.convo.muteConvo',
  'chat.bsky.convo.sendMessage',
  'chat.bsky.convo.sendMessageBatch',
  'chat.bsky.convo.unmuteConvo',
  'chat.bsky.convo.updateRead',
  'com.atproto.server.createAccount',
]);

const PROTECTED_METHODS = new Set<string>([
  'com.atproto.admin.sendEmail',
  'com.atproto.identity.requestPlcOperationSignature',
  'com.atproto.identity.signPlcOperation',
  'com.atproto.identity.updateHandle',
  'com.atproto.server.activateAccount',
  'com.atproto.server.confirmEmail',
  'com.atproto.server.createAppPassword',
  'com.atproto.server.deactivateAccount',
  'com.atproto.server.getAccountInviteCodes',
  'com.atproto.server.getSession',
  'com.atproto.server.listAppPasswords',
  'com.atproto.server.requestAccountDelete',
  'com.atproto.server.requestEmailConfirmation',
  'com.atproto.server.requestEmailUpdate',
  'com.atproto.server.revokeAppPassword',
  'com.atproto.server.updateEmail',
]);

// (no-op placeholder; do not short-circuit to fallback)

class ProxyHeaderError extends Error {}

function resolveAuthScope(scope: unknown): AuthScope {
  if (typeof scope !== 'string') {
    return DEFAULT_ACCESS_SCOPE;
  }

  switch (scope) {
    case 'access':
      // Map internal session token scope to official value
      return 'com.atproto.access';
    case 'com.atproto.access':
    case 'com.atproto.appPass':
    case 'com.atproto.appPassPrivileged':
    case 'com.atproto.signupQueued':
    case 'com.atproto.takendown':
      return scope;
    default:
      console.warn('Unknown auth scope, treating as access scope', scope);
      return DEFAULT_ACCESS_SCOPE;
  }
}

function parseProxyHeader(header: string): { did: string; serviceId: string } {
  const value = header.trim();
  const hashIndex = value.indexOf('#');

  if (hashIndex <= 0 || hashIndex === value.length - 1) {
    throw new ProxyHeaderError('invalid format');
  }

  if (value.indexOf('#', hashIndex + 1) !== -1) {
    throw new ProxyHeaderError('invalid format');
  }

  const did = value.slice(0, hashIndex);
  const serviceId = value.slice(hashIndex); // includes leading '#'

  if (!did.startsWith('did:')) {
    throw new ProxyHeaderError('invalid DID');
  }

  if (!serviceId.startsWith('#')) {
    throw new ProxyHeaderError('invalid service id');
  }

  if (value.includes(' ')) {
    throw new ProxyHeaderError('invalid format');
  }

  return { did, serviceId };
}

async function resolveProxyTargetWithRegistry(
  env: Env,
  proxyHeader: string,
  registry: Record<ServiceId, ServiceConfig>,
): Promise<ProxyTarget> {
  const { did, serviceId } = parseProxyHeader(proxyHeader);

  const sid = serviceId.startsWith('#') ? (serviceId.slice(1) as ServiceId) : (serviceId as ServiceId);
  const known = registry[sid];
  if (known && did === known.did) {
    return { did, url: known.url };
  }

  const didDoc = await resolveDidDocument(env, did);
  const endpoint = getServiceEndpointFromDidDoc(didDoc, did, serviceId);
  if (!endpoint) {
    throw new ProxyHeaderError('service id not found in DID document');
  }
  return { did, url: endpoint };
}

async function resolveDidDocument(env: Env, did: string): Promise<any> {
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

async function fetchDidDocument(_env: Env, did: string): Promise<any> {
  let url: string;
  if (did.startsWith('did:web:')) {
    url = buildDidWebUrl(did);
  } else if (did.startsWith('did:plc:')) {
    url = `https://plc.directory/${did}`;
  } else {
    throw new ProxyHeaderError('unsupported DID method');
  }

  const res = await fetch(url, {
    headers: {
      accept: 'application/did+json, application/json;q=0.9',
    },
  });

  if (!res.ok) {
    throw new ProxyHeaderError('failed to resolve DID document');
  }

  return res.json();
}

function buildDidWebUrl(did: string): string {
  const suffix = did.slice('did:web:'.length);
  const parts = suffix.split(':').map((segment) => {
    try {
      return decodeURIComponent(segment);
    } catch {
      throw new ProxyHeaderError('invalid did:web encoding');
    }
  });

  const host = parts.shift();
  if (!host) throw new ProxyHeaderError('invalid did:web value');

  if (parts.length === 0) {
    return `https://${host}/.well-known/did.json`;
  }

  const path = parts.join('/');
  return `https://${host}/${path}/did.json`;
}

function getServiceEndpointFromDidDoc(didDoc: any, did: string, serviceId: string): string | null {
  if (!didDoc || typeof didDoc !== 'object') return null;
  const services = Array.isArray((didDoc as any).service) ? (didDoc as any).service : [];
  if (!services.length) return null;

  const targets = new Set<string>([serviceId]);
  const docId = typeof (didDoc as any).id === 'string' ? (didDoc as any).id : undefined;
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

function extractServiceEndpoint(service: any): string | null {
  const endpoint = service?.serviceEndpoint;
  if (typeof endpoint === 'string') return endpoint;
  if (endpoint && typeof endpoint === 'object') {
    if (typeof endpoint.uri === 'string') return endpoint.uri;
    if (Array.isArray(endpoint.urls)) {
      const first = endpoint.urls.find((value: unknown) => typeof value === 'string');
      if (typeof first === 'string') return first;
    }
  }
  return null;
}

// For service auth, AppView verifies against the issuer DID's "atproto" key.
// We sign service JWTs with the same key used for repo commits (REPO_SIGNING_KEY).

export function getAppViewConfig(env: Env): AppViewConfig | null {
  const url = (typeof env.PDS_BSKY_APP_VIEW_URL === 'string' && env.PDS_BSKY_APP_VIEW_URL.trim() !== '')
    ? env.PDS_BSKY_APP_VIEW_URL.trim()
    : DEFAULT_APPVIEW_URL;
  const did = (typeof env.PDS_BSKY_APP_VIEW_DID === 'string' && env.PDS_BSKY_APP_VIEW_DID.trim() !== '')
    ? env.PDS_BSKY_APP_VIEW_DID.trim()
    : DEFAULT_APPVIEW_DID;

  if (!url || !did) return null;

  const cdn = typeof env.PDS_BSKY_APP_VIEW_CDN_URL_PATTERN === 'string'
    ? env.PDS_BSKY_APP_VIEW_CDN_URL_PATTERN.trim()
    : undefined;

  return { url, did, cdnUrlPattern: cdn || undefined };
}

function getChatConfig(env: Env): ServiceConfig {
  const url = (typeof env.PDS_BSKY_CHAT_URL === 'string' && env.PDS_BSKY_CHAT_URL.trim() !== '')
    ? env.PDS_BSKY_CHAT_URL.trim()
    : DEFAULT_CHAT_URL;
  const did = (typeof env.PDS_BSKY_CHAT_DID === 'string' && env.PDS_BSKY_CHAT_DID.trim() !== '')
    ? env.PDS_BSKY_CHAT_DID.trim()
    : DEFAULT_CHAT_DID;
  return { id: 'bsky_chat', url, did };
}

function getOzoneConfig(env: Env): ServiceConfig {
  const url = (typeof env.PDS_OZONE_URL === 'string' && env.PDS_OZONE_URL.trim() !== '')
    ? env.PDS_OZONE_URL.trim()
    : DEFAULT_OZONE_URL;
  const did = (typeof env.PDS_OZONE_DID === 'string' && env.PDS_OZONE_DID.trim() !== '')
    ? env.PDS_OZONE_DID.trim()
    : DEFAULT_OZONE_DID;
  return { id: 'atproto_labeler', url, did };
}

function getServiceRegistry(env: Env): Record<ServiceId, ServiceConfig> {
  const app = getAppViewConfig(env);
  const chat = getChatConfig(env);
  const ozone = getOzoneConfig(env);
  if (!app) {
    throw new Error('AppView not configured');
  }
  return {
    bsky_appview: { id: 'bsky_appview', url: app.url, did: app.did },
    bsky_chat: chat,
    atproto_labeler: ozone,
  };
}

function defaultServiceForNsid(env: Env, nsid: string): ServiceConfig {
  const reg = getServiceRegistry(env);
  if (nsid.startsWith('chat.bsky.')) return reg.bsky_chat;
  if (nsid.startsWith('tools.ozone.') || nsid.startsWith('com.atproto.moderation.')) return reg.atproto_labeler;
  // default to AppView for app.bsky.* and everything else that's proxied
  return reg.bsky_appview;
}

async function createServiceJwt(
  env: Env,
  issuerDid: string,
  audienceDid: string,
  lexiconMethod: string | null,
  expiresInSeconds = 60,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + Math.max(1, expiresInSeconds);
  const payload: Record<string, unknown> = {
    iss: issuerDid,
    aud: audienceDid,
    iat: now,
    exp,
    jti: randomHex(),
  };
  if (lexiconMethod) payload.lxm = lexiconMethod;

  // Always ES256K: sign with secp256k1 using REPO_SIGNING_KEY
  const priv = ((await getRuntimeString(env, 'REPO_SIGNING_KEY', '')) ?? '').trim();
  if (!priv) throw new Error('REPO_SIGNING_KEY not configured for ES256K service-auth');

  // Service-auth uses a standard JWT header with ES256K
  const header = { typ: 'JWT', alg: 'ES256K' } as const;
  const encodedHeader = encodeJson(header as any);
  const encodedPayload = encodeJson(payload);
  const toSign = `${encodedHeader}.${encodedPayload}`;

  const signature = await es256kSign(priv, toSign);
  const encodedSignature = encodeBase64Url(signature);
  return `${toSign}.${encodedSignature}`;
}

async function es256kSign(privateKey: string, data: string): Promise<Uint8Array> {
  // Accept 32-byte hex (preferred) or base64 for secp256k1 private key
  const cleaned = privateKey.trim();
  const { Secp256k1Keypair } = await import('@atproto/crypto');
  let keypair: any;
  if (/^[0-9a-fA-F]{64}$/.test(cleaned)) {
    keypair = await Secp256k1Keypair.import(cleaned);
  } else {
    // try base64
    const bin = atob(cleaned.replace(/\s+/g, ''));
    const priv = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) priv[i] = bin.charCodeAt(i);
    keypair = await Secp256k1Keypair.import(priv);
  }
  const sig = await keypair.sign(new TextEncoder().encode(data));
  // Secp256k1Keypair.sign returns 64-byte compact (r||s), which matches JWS ECDSA encoding
  return sig as Uint8Array;
}

const FORWARDED_HEADERS = [
  'accept',
  'accept-encoding',
  'accept-language',
  'atproto-accept-labelers',
  'atproto-accept-personalized-feed',
  'cache-control',
  'if-none-match',
  'if-modified-since',
  'pragma',
  'x-bsky-topics',
  'x-bsky-feeds',
  'x-bsky-latest',
  'x-bsky-appview-features',
  'user-agent',
];

// Endpoints where we benefit from read-after-write behavior.
// When the viewer just posted, conditional headers can cause 304s that hide
// the fresh content. Upstream PDS handles RAW merging; we "nudge" freshness by
// dropping conditionals for the viewer's own requests.
const RAW_SENSITIVE_METHODS = new Set<string>([
  'app.bsky.unspecced.getPostThreadV2',
  'app.bsky.feed.getFeed',
  'app.bsky.feed.getPosts',
  'app.bsky.feed.getTimeline',
  'app.bsky.feed.getAuthorFeed',
]);

export interface ProxyAppViewOptions {
  request: Request;
  env: Env;
  lxm: string;
  fallback?: () => Promise<Response>;
}

export async function proxyAppView({ request, env, lxm, fallback }: ProxyAppViewOptions): Promise<Response> {
  console.log('proxyAppView called:', { lxm, url: request.url });
  // Build service registry and pick default for this NSID
  let registry: Record<ServiceId, ServiceConfig>;
  try {
    registry = getServiceRegistry(env);
  } catch (e) {
    console.log('proxyAppView: No service config, using fallback');
    return fallback ? await fallback() : new Response('Services not configured', { status: 501 });
  }
  const defaultService = defaultServiceForNsid(env, lxm);

  // Emergency kill-switch: allow deployments to bypass AppView entirely
  // while service-auth/DID alignment is being verified.
  if ((env as any).PDS_APPVIEW_FORCE_FALLBACK === '1') {
    console.log('proxyAppView: PDS_APPVIEW_FORCE_FALLBACK=1, using fallback');
    if (fallback) return fallback();
  }

  console.log('proxyAppView: Selected service for method:', { lxm, serviceId: defaultService.id, url: defaultService.url, did: defaultService.did });

  let auth;
  try {
    auth = await authenticateRequest(request, env);
  } catch (err) {
    if (err instanceof AuthTokenExpiredError) {
      return expiredToken();
    }
    throw err;
  }
  if (!auth) {
    console.log('proxyAppView: Authentication failed');
    return unauthorized();
  }

  if (!auth.claims.sub) {
    console.log('proxyAppView: No subject in auth claims');
    return new Response(JSON.stringify({ error: 'InvalidToken' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  console.log('proxyAppView: Authenticated as', auth.claims.sub);

  if (PROTECTED_METHODS.has(lxm)) {
    console.log('proxyAppView: Method is protected, cannot proxy');
    return new Response(
      JSON.stringify({ error: 'InvalidToken', message: 'method cannot be proxied' }),
      {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      },
    );
  }

  const scope = resolveAuthScope(auth.claims.scope);
  if (scope === TAKENDOWN_SCOPE) {
    console.log('proxyAppView: Account is takendown');
    return new Response(JSON.stringify({ error: 'AccountTakendown' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (!PRIVILEGED_SCOPES.has(scope) && PRIVILEGED_METHODS.has(lxm)) {
    console.log('proxyAppView: Insufficient privileges for method');
    return new Response(JSON.stringify({ error: 'InvalidToken' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Do not short-circuit to fallback; exercise upstream so we can surface real errors

  let target: ProxyTarget = { did: defaultService.did, url: defaultService.url };
  const proxyHeader = request.headers.get('atproto-proxy');
  if (proxyHeader) {
    console.log('proxyAppView: Resolving proxy header:', proxyHeader);
    try {
      target = await resolveProxyTargetWithRegistry(env, proxyHeader, registry);
    } catch (error) {
      console.error('AppView proxy header error:', error);
      const isHeaderError = error instanceof ProxyHeaderError;
      return new Response(
        JSON.stringify({ error: isHeaderError ? 'InvalidProxyHeader' : 'ProxyResolutionFailed' }),
        {
          status: isHeaderError ? 400 : 502,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }
  }

  const originalUrl = new URL(request.url);
  const upstreamUrl = new URL(target.url);
  upstreamUrl.pathname = originalUrl.pathname;
  upstreamUrl.search = originalUrl.search;
  upstreamUrl.hash = '';

  console.log('proxyAppView: Proxying to', upstreamUrl.toString());

  const headers = new Headers();
  for (const header of FORWARDED_HEADERS) {
    const value = request.headers.get(header);
    if (value) headers.set(header, value);
  }

  // Strip conditional headers for RAW-sensitive methods when the viewer is the issuer
  // This avoids immediate 304s right after a successful write.
  if (RAW_SENSITIVE_METHODS.has(lxm)) {
    try {
      const viewerDid = auth.claims.sub || '';
      if (viewerDid && viewerDid.startsWith('did:')) {
        headers.delete('if-none-match');
        headers.delete('if-modified-since');
      }
    } catch {}
  }

  let serviceJwt: string | null = null;
  try {
    // Issuer is the authenticated DID (like upstream PDS). In single-user mode,
    // this should equal the DID whose signing key we hold.
    const issuerDid = auth.claims.sub;
    if (!issuerDid || !issuerDid.startsWith('did:')) {
      throw new Error(`Invalid issuer DID: ${issuerDid || '(empty)'}`);
    }
    console.log('proxyAppView: Creating service JWT for', { iss: issuerDid, aud: target.did, lxm });
    serviceJwt = await createServiceJwt(env, issuerDid, target.did, lxm);
    console.log('proxyAppView: Service JWT created successfully');
  } catch (error) {
    console.error('AppView service token error:', error);
    // For public endpoints, we can proceed without Authorization; for private ones,
    // upstream will return 401. This surfaces real upstream behavior for debugging.
    serviceJwt = null;
  }

  if (serviceJwt) headers.set('authorization', `Bearer ${serviceJwt}`);

  const method = request.method.toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && method !== 'POST') {
    console.log('proxyAppView: Method not allowed:', method);
    return new Response(JSON.stringify({ error: 'MethodNotAllowed' }), {
      status: 405,
      headers: {
        'Content-Type': 'application/json',
        Allow: 'GET, HEAD, POST',
      },
    });
  }

  if (!headers.has('accept-encoding')) {
    headers.set('accept-encoding', 'identity');
  }

  if (method === 'POST') {
    const contentType = request.headers.get('content-type');
    if (contentType) headers.set('content-type', contentType);
    const contentEncoding = request.headers.get('content-encoding');
    if (contentEncoding) headers.set('content-encoding', contentEncoding);
  }

  try {
    const init: RequestInit = {
      method,
      headers,
    };

    if (method === 'POST') {
      init.body = request.body as any;
      (init as any).duplex = 'half';
    }

    console.log('proxyAppView: Fetching upstream');
    const upstream = await fetch(upstreamUrl.toString(), init);
    console.log('proxyAppView: Upstream response:', { status: upstream.status, statusText: upstream.statusText });

    const responseHeaders = new Headers(upstream.headers);
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    });
  } catch (error) {
    console.error('AppView proxy error:', error);
    if (fallback) {
      console.log('proxyAppView: Using fallback due to upstream error');
      return fallback();
    }
    return new Response(JSON.stringify({ error: 'UpstreamUnavailable' }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

export async function getAppViewServiceToken(env: Env, did: string, aud?: string, lxm?: string | null, expiresInSeconds = 60) {
  const config = getAppViewConfig(env);
  if (!config) {
    throw new Error('AppView not configured');
  }
  return createServiceJwt(env, did, aud ?? config.did, lxm ?? null, expiresInSeconds);
}

export async function createServiceAuthToken(
  env: Env,
  issuerDid: string,
  audienceDid: string,
  lexiconMethod: string | null,
  expiresInSeconds = 60,
): Promise<string> {
  return createServiceJwt(env, issuerDid, audienceDid, lexiconMethod, expiresInSeconds);
}
