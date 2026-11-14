import type { APIContext } from 'astro';
import { decodeJwt, decodeProtectedHeader, errors as joseErrors } from 'jose';
import { readAuthorizedSpacePolicy } from '../../db/space-authorized-policy';
import {
  dpopResourceUnauthorized, handleResourceAuthError, scopeMissingResponse, verifyResourceRequest,
} from '../../lib/oauth/resource';
import { mergeHeaderTokens } from '../../lib/http-headers';
import { parseGetSpaceRequest } from '../../lib/spaces/get-space-request';

export const prerender = false;

const MAX_AUTH_BYTES = 65_536;
const MAX_DPOP_BYTES = 16_384;

export async function GET({ locals, request }: APIContext): Promise<Response> {
  try {
    if (request.signal.aborted) return secure(unauthorized());
    const space = parseGetSpaceRequest(request);
    if (!space) return secure(error('InvalidRequest', 'Invalid request parameters', 400));
    const authorization = request.headers.get('authorization');
    const proof = request.headers.get('dpop');
    if (!boundedHeader(authorization, MAX_AUTH_BYTES) || !boundedHeader(proof, MAX_DPOP_BYTES)) {
      return secure(error('InvalidRequest', 'Request headers are too large', 400));
    }
    if (request.headers.has('accept-signature')) {
      return secure(error('InvalidRequest', 'Space policy MAC requests are unavailable', 400));
    }
    if (!authorization || !/^DPoP\s+\S+$/i.test(authorization)) return secure(unauthorized());
    const env = locals.env;
    const database = env.ALTERAN_DB;
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
    if (request.signal.aborted || env.ALTERAN_DB !== database || !auth || auth.authType !== 'oauth-dpop') {
      return secure(unauthorized());
    }
    if (!auth.spacePrincipal) return secure(scopeMissingResponse());
    const result = await readAuthorizedSpacePolicy(env, auth.spacePrincipal, request);
    if (result.tag === 'unauthorized' || env.ALTERAN_DB !== database) return secure(unauthorized());
    let response: Response;
    try {
      if (result.tag === 'notFound') response = error('SpaceNotFound', 'Space not found', 400);
      else response = new Response(JSON.stringify({ space: result.space, policy: { $type: 'com.atproto.personalspace.policy' } }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    } catch {
      response = error('InternalServerError', 'Internal server error', 500);
    }
    let allowed = false;
    try {
      allowed = await result.complete(request, database);
    } catch {
      // A failed completion cannot authorize any data-dependent response.
    }
    if (!allowed || request.signal.aborted || env.ALTERAN_DB !== database) return secure(unauthorized());
    return secure(response);
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

function boundedHeader(value: string | null, maximum: number): boolean {
  return value === null || (value.length <= maximum && new TextEncoder().encode(value).byteLength <= maximum);
}

// The resource verifier checks the signature, key binding, nonce, time and replay.
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
  if (headers.has('dpop-nonce')) mergeHeaderTokens(headers, 'access-control-expose-headers', ['DPoP-Nonce']);
  if (headers.has('www-authenticate')) mergeHeaderTokens(headers, 'access-control-expose-headers', ['WWW-Authenticate']);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
