import { CID } from 'multiformats/cid';
import type { Env } from '../env';

export type GuardResult<T> = { ok: true; value: T } | { ok: false; response: Response };

const JSON_HEADERS = { 'Content-Type': 'application/json' };

export function xrpcError(error: string, message: string, status = 400): Response {
  return new Response(JSON.stringify({ error, message }), {
    status,
    headers: JSON_HEADERS,
  });
}

export function invalidRequest(message: string): Response {
  return xrpcError('InvalidRequest', message, 400);
}

export function routeNotFound(message = 'Not Found'): Response {
  return xrpcError('NotFound', message, 404);
}

export function configuredDid(env: Env): string {
  return typeof env.PDS_DID === 'string' ? env.PDS_DID : '';
}

export function configuredHandle(env: Env): string {
  return typeof env.PDS_HANDLE === 'string' ? env.PDS_HANDLE : '';
}

export function isValidDid(value: string): boolean {
  return value.length <= 2048 && /^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$/.test(value);
}

export function isValidNsid(value: string): boolean {
  return value.length <= 317
    && /^[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(\.[a-zA-Z]([a-zA-Z0-9]{0,62})?)$/.test(value);
}

export function isValidAtprotoHandle(value: string): boolean {
  return value.length <= 253
    && /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(value);
}

export function isValidRecordKey(value: string): boolean {
  if (value.length < 1 || value.length > 512) return false;
  if (value === '.' || value === '..' || value.includes('/')) return false;
  return /^[A-Za-z0-9_~.:-]+$/.test(value);
}

export function parseCid(value: string): CID | null {
  try {
    return CID.parse(value);
  } catch {
    return null;
  }
}

export function requireLocalDid(
  env: Env,
  url: URL,
  options: {
    name?: string;
    notFoundError?: string;
    notFoundStatus?: number;
  } = {},
): GuardResult<string> {
  const name = options.name ?? 'did';
  const did = url.searchParams.get(name);
  if (!did) {
    return { ok: false, response: invalidRequest(`${name} parameter is required`) };
  }
  if (!isValidDid(did)) {
    return { ok: false, response: invalidRequest(`${name} must be a valid DID`) };
  }

  const localDid = configuredDid(env);
  if (!localDid || did !== localDid) {
    const error = options.notFoundError ?? 'RepoNotFound';
    return {
      ok: false,
      response: xrpcError(error, `${name} does not identify the local repo`, options.notFoundStatus ?? 400),
    };
  }

  return { ok: true, value: localDid };
}

export function requireLocalRepo(
  env: Env,
  url: URL,
  options: {
    name?: string;
    notFoundError?: string;
  } = {},
): GuardResult<string> {
  const name = options.name ?? 'repo';
  const repo = url.searchParams.get(name);
  if (!repo) {
    return { ok: false, response: invalidRequest(`${name} parameter is required`) };
  }

  const localDid = configuredDid(env);
  const localHandle = configuredHandle(env).toLowerCase();

  if (repo.startsWith('did:')) {
    if (!isValidDid(repo)) {
      return { ok: false, response: invalidRequest(`${name} must be a valid DID or handle`) };
    }
    if (localDid && repo === localDid) return { ok: true, value: localDid };
    return {
      ok: false,
      response: xrpcError(options.notFoundError ?? 'RepoNotFound', `${name} does not identify the local repo`),
    };
  }

  if (!isValidAtprotoHandle(repo)) {
    return { ok: false, response: invalidRequest(`${name} must be a valid DID or handle`) };
  }

  if (localDid && localHandle && repo.toLowerCase() === localHandle) {
    return { ok: true, value: localDid };
  }

  return {
    ok: false,
    response: xrpcError(options.notFoundError ?? 'RepoNotFound', `${name} does not identify the local repo`),
  };
}

export function requireNsid(url: URL, name = 'collection'): GuardResult<string> {
  const value = url.searchParams.get(name);
  if (!value) return { ok: false, response: invalidRequest(`${name} parameter is required`) };
  if (!isValidNsid(value)) return { ok: false, response: invalidRequest(`${name} must be a valid NSID`) };
  return { ok: true, value };
}

export function requireRecordKey(url: URL, name = 'rkey'): GuardResult<string> {
  const value = url.searchParams.get(name);
  if (!value) return { ok: false, response: invalidRequest(`${name} parameter is required`) };
  if (!isValidRecordKey(value)) return { ok: false, response: invalidRequest(`${name} must be a valid record key`) };
  return { ok: true, value };
}

export function optionalCid(url: URL, name = 'cid'): GuardResult<CID | null> {
  if (!url.searchParams.has(name)) return { ok: true, value: null };
  const value = url.searchParams.get(name);
  if (value === null || value === '') {
    return { ok: false, response: invalidRequest(`${name} must be a valid CID`) };
  }
  const cid = parseCid(value);
  if (!cid) return { ok: false, response: invalidRequest(`${name} must be a valid CID`) };
  return { ok: true, value: cid };
}

export function requireCid(url: URL, name = 'cid'): GuardResult<CID> {
  const value = url.searchParams.get(name);
  if (!value) return { ok: false, response: invalidRequest(`${name} parameter is required`) };
  const cid = parseCid(value);
  if (!cid) return { ok: false, response: invalidRequest(`${name} must be a valid CID`) };
  return { ok: true, value: cid };
}

export function requireCidArray(url: URL, name = 'cids'): GuardResult<CID[]> {
  const rawValues = url.searchParams.getAll(name);
  const values = rawValues.length === 1 && rawValues[0].includes(',')
    ? rawValues[0].split(',')
    : rawValues;

  if (values.length === 0 || values.some((value) => value.trim() === '')) {
    return { ok: false, response: invalidRequest(`${name} parameter is required`) };
  }

  const cids: CID[] = [];
  for (const value of values.map((item) => item.trim())) {
    const cid = parseCid(value);
    if (!cid) {
      return { ok: false, response: invalidRequest(`${name} must contain only valid CIDs`) };
    }
    cids.push(cid);
  }

  return { ok: true, value: cids };
}

export function parseLimit(url: URL, options: { defaultValue: number; max: number }): GuardResult<number> {
  const value = url.searchParams.get('limit');
  if (!value) return { ok: true, value: options.defaultValue };

  const limit = Number.parseInt(value, 10);
  if (!Number.isFinite(limit) || String(limit) !== value || limit < 1 || limit > options.max) {
    return { ok: false, response: invalidRequest(`limit must be an integer between 1 and ${options.max}`) };
  }

  return { ok: true, value: limit };
}
