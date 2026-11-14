import type { APIContext } from 'astro';
import { decodeJwt, decodeProtectedHeader, errors as joseErrors } from 'jose';
import { readAuthorizedSpaceRecord } from '../../db/space-authorized-record';
import {
  dpopResourceUnauthorized, handleResourceAuthError, scopeMissingResponse, verifyResourceRequest,
} from '../../lib/oauth/resource';
import { captureRecordIdentity } from '../../lib/spaces/record-response-input';
import { createSpaceRecordResponse } from '../../lib/spaces/record-response';
import { mergeHeaderTokens } from '../../lib/http-headers';

export const prerender = false;

const MAX_URL_LENGTH = 16_384;
const MAX_AUTH_BYTES = 65_536;
const MAX_DPOP_BYTES = 16_384;
const PARAMETERS = ['space', 'repo', 'collection', 'rkey'] as const;

type Target = Record<(typeof PARAMETERS)[number], string>;

export async function GET({ locals, request }: APIContext): Promise<Response> {
  try {
    const target = parseTarget(request);
    if (!target) return secure(error('InvalidRequest', 'Invalid request parameters', 400));
    if (request.signal.aborted) return secure(unauthorized());
    const authorization = request.headers.get('authorization');
    const proof = request.headers.get('dpop');
    if (!boundedHeader(authorization, MAX_AUTH_BYTES) || !boundedHeader(proof, MAX_DPOP_BYTES)) {
      return secure(error('InvalidRequest', 'Request headers are too large', 400));
    }
    if (request.headers.has('accept-signature')) {
      return secure(error('InvalidSpaceMac', 'Space record MAC requests are unavailable', 400));
    }
    if (!authorization || !/^DPoP\s+\S+$/i.test(authorization)) return secure(unauthorized());
    const env = locals.env;
    if (!proof || !validProofStructure(proof)) return secure(await dpopResourceUnauthorized(env));
    let auth;
    try {
      auth = await verifyResourceRequest(env, request);
    } catch (cause) {
      const handled = await handleResourceAuthError(env, cause);
      if (handled) return secure(handled);
      if (cause instanceof joseErrors.JOSEError || cause instanceof SyntaxError ||
        (cause instanceof DOMException && (cause.name === 'DataError' || cause.name === 'OperationError'))) {
        return secure(await dpopResourceUnauthorized(env));
      }
      throw cause;
    }
    if (request.signal.aborted || !auth || auth.authType !== 'oauth-dpop') return secure(unauthorized());
    if (!auth.spacePrincipal) return secure(scopeMissingResponse());
    if (target.repo !== auth.did) return secure(error('RepoNotFound', 'Repository not found', 400));

    const result = await readAuthorizedSpaceRecord(env, auth.spacePrincipal, request,
      target.space, target.repo, target.collection, target.rkey);
    if (result.tag === 'unauthorized') return secure(unauthorized());
    const response = secure(result.tag === 'found'
      ? (() => {
        const serialized = createSpaceRecordResponse(target, result.record,
          { acceptSignature: null, kemKey: null, requireMac: false });
        return new Response(serialized.body, { status: 200, headers: serialized.headers });
      })()
      : error('RecordNotFound', `Could not locate record: ${captureRecordIdentity(target).uri}`, 400));
    if (!await result.complete(request, env.ALTERAN_DB) || request.signal.aborted) return secure(unauthorized());
    return response;
  } catch {
    return secure(error('InternalServerError', 'Internal server error', 500));
  }
}

export function HEAD(): Response {
  return secure(new Response(null, { status: 405, headers: { allow: 'GET' } }));
}

export function ALL(): Response {
  return secure(error('MethodNotAllowed', 'Method not allowed', 405, { allow: 'GET' }));
}

function parseTarget(request: Request): Target | null {
  if (request.method !== 'GET' || request.url.length > MAX_URL_LENGTH) return null;
  const url = new URL(request.url);
  if (url.pathname !== '/xrpc/com.atproto.space.getRecord' ||
    Array.from(url.searchParams.keys()).some((key) => !PARAMETERS.includes(key as (typeof PARAMETERS)[number]))) return null;
  const values = PARAMETERS.map((key) => url.searchParams.getAll(key));
  if (values.some((entries) => entries.length !== 1)) return null;
  const target = { space: values[0][0], repo: values[1][0], collection: values[2][0], rkey: values[3][0] };
  try {
    captureRecordIdentity(target);
    return target;
  } catch {
    return null;
  }
}

function boundedHeader(value: string | null, maximum: number): boolean {
  return value === null || (value.length <= maximum && new TextEncoder().encode(value).byteLength <= maximum);
}

// This only bounds and checks the public proof envelope. The resource verifier
// still verifies the signature, key binding, nonce, time, target and replay.
function validProofStructure(proof: string): boolean {
  try {
    const header = decodeProtectedHeader(proof);
    decodeJwt(proof);
    const jwk = header.jwk;
    return header.typ === 'dpop+jwt' && header.alg === 'ES256' && !!jwk &&
      jwk.kty === 'EC' && jwk.crv === 'P-256' && !('d' in jwk) &&
      typeof jwk.x === 'string' && /^[A-Za-z0-9_-]{43}$/.test(jwk.x) &&
      typeof jwk.y === 'string' && /^[A-Za-z0-9_-]{43}$/.test(jwk.y);
  } catch {
    return false;
  }
}

function error(code: string, message: string, status: number, headers?: HeadersInit): Response {
  const result = new Headers(headers);
  result.set('content-type', 'application/json');
  return new Response(JSON.stringify({ error: code, message }), { status, headers: result });
}

function unauthorized(): Response {
  return error('AuthRequired', 'Authentication required', 401, { 'www-authenticate': 'DPoP' });
}

function secure(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set('cache-control', 'private, no-store');
  mergeHeaderTokens(headers, 'vary', ['Accept-Signature', 'Authorization', 'DPoP']);
  if (headers.has('dpop-nonce')) {
    mergeHeaderTokens(headers, 'access-control-expose-headers', ['DPoP-Nonce']);
  }
  if (headers.has('www-authenticate')) {
    mergeHeaderTokens(headers, 'access-control-expose-headers', ['WWW-Authenticate']);
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
